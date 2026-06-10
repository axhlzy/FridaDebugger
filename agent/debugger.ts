import { infoAddress as printAddressInfo, resolveAddress } from "./address-info.js";
import { BreakpointStore } from "./breakpoints.js";
import { isShown } from "./display.js";
import { logCapturedDisassemblyWindow, logDisassembly, logDisassemblyWindow, type DisassembledInstruction } from "./disassembly.js";
import { log } from "./logger.js";
import { writeMemoryValue, type MemoryWriteType } from "./memory-write.js";
import { toPointer } from "./pointer.js";
import { captureRegisters, logRegisters, type RegisterSnapshot } from "./registers.js";
import { Semaphore } from "./semaphore.js";
import { logStack, type StackSnapshot } from "./stack.js";
import type { FunctionBreakpoint, PointerInput, StalkerIterator } from "./types.js";
import { logIl2CppFields } from "./unity-fields.js";

interface StalkerSession {
    breakpoint: FunctionBreakpoint;
    threadId: ThreadId;
    semaphore: Semaphore;
    paused: boolean;
    stopRequested: boolean;
    stepCount: number;
    pc: NativePointer | null;
    displayPc: NativePointer | null;
    instruction: string | null;
    seenOriginalCode: boolean;
    relocatedDisplayIndex: number;
    filter: TraceFilter | null;
    restoreFilter: TraceFilter | null;
    context: CpuContext | null;
    lastRegisters: RegisterSnapshot | null;
    lastStack: StackSnapshot | null;
    pendingSteps: number;
    runMode: RunMode;
    baseLr: NativePointer | null;
    targetLr: NativePointer | null;
    targetPc: NativePointer | null;
    autoBudget: number;
    autoStopReason: string | null;
}

interface DisplayInstruction {
    address: NativePointer;
    text: string;
    mapped: boolean;
}

interface TraceFilter {
    name: string;
    base: NativePointer;
    end: NativePointer;
}

type RunMode = "none" | "count" | "step-in" | "step-out" | "until";
const MAX_SILENT_AUTO_STEPS = 10000;

export class StalkerBreakpointDebugger {
    readonly breakpoints = new BreakpointStore((breakpoint, _args, context) => {
        this.startStalkerForHit(breakpoint, context);
    });

    private readonly sessions = new Map<ThreadId, StalkerSession>();
    private currentThreadId: ThreadId | null = null;
    private disposed = false;

    step(count = 1): void {
        const session = this.getSession(this.currentThreadId);
        if (session === null) {
            return;
        }

        if (!session.paused) {
            log(`[stalker] thread ${session.threadId} is not paused yet`);
            return;
        }

        const stepCount = this.normalizeCount(count, 1);
        session.runMode = "count";
        session.pendingSteps = stepCount;
        session.baseLr = null;
        session.targetLr = null;
        session.targetPc = null;
        log(`[stalker] step thread ${session.threadId} count=${stepCount}`, "green");
        session.semaphore.post();
    }

    stepIn(): void {
        const session = this.getPausedSession();
        if (session === null || session.context === null) {
            return;
        }

        const lr = this.getLinkRegister(session.context);
        if (lr === null) {
            log("[stalker] step-in requires lr", "yellow");
            return;
        }

        if (!this.isCallInstruction(session.instruction)) {
            log("[stalker] current instruction is not call-like; step-in falls back to s(1)", "yellow");
            this.step(1);
            return;
        }

        session.runMode = "step-in";
        session.baseLr = lr;
        session.targetLr = null;
        session.targetPc = null;
        session.autoBudget = MAX_SILENT_AUTO_STEPS;
        session.autoStopReason = null;
        log(`[stalker] step-in thread ${session.threadId} base-lr=${lr}`, "green");
        session.semaphore.post();
    }

    stepOut(): void {
        const session = this.getPausedSession();
        if (session === null || session.context === null) {
            return;
        }

        const lr = this.getLinkRegister(session.context);
        if (lr === null) {
            log("[stalker] step-out requires lr", "yellow");
            return;
        }

        session.runMode = "step-out";
        session.baseLr = null;
        session.targetLr = lr;
        session.targetPc = null;
        this.relaxFilterIfNeeded(session, lr, "step-out");
        session.autoBudget = MAX_SILENT_AUTO_STEPS;
        session.autoStopReason = null;
        log(`[stalker] step-out thread ${session.threadId} target-lr=${lr}`, "green");
        session.semaphore.post();
    }

    next(): void {
        const session = this.getPausedSession();
        if (session === null || session.displayPc === null) {
            return;
        }

        if (!this.isCallInstruction(session.instruction)) {
            this.step(1);
            return;
        }

        const nextPc = session.displayPc.add(Process.arch === "arm64" || Process.arch === "arm" ? 4 : 1);
        this.runUntilPointer(nextPc, "next-over");
    }

    until(position: PointerInput): void {
        try {
            this.runUntilPointer(toPointer(position), "until");
        } catch (error) {
            log(`[until] invalid address: ${String(error)}`, "red");
        }
    }

    continue(threadId?: ThreadId | null): void {
        const session = this.getSession(threadId ?? this.currentThreadId);
        if (session === null) {
            return;
        }

        log(`[stalker] continue thread ${session.threadId}`, "green");
        session.stopRequested = true;
        Stalker.unfollow(session.threadId);
        Stalker.garbageCollect();
        session.semaphore.post();

        if (!session.paused) {
            this.finishSession(session);
        }
    }

    status(): void {
        if (this.sessions.size === 0) {
            log("[stalker] no active sessions", "gray");
            return;
        }

        for (const session of this.sessions.values()) {
            log(
                `[stalker] thread=${session.threadId} paused=${session.paused} steps=${session.stepCount} pc=${session.pc} filter=${session.filter?.name ?? "none"} ins=${session.instruction}`,
                "gray",
            );
        }
    }

    backtrace(): void {
        if (!isShown("bt")) {
            return;
        }

        const session = this.getPausedSession();
        if (session === null || session.context === null) {
            return;
        }

        try {
            log("[bt] ------------------------------------------------------------", "cyan");
            const frames = this.backtraceByFramePointer(session.context);
            const fuzzyFrames = Thread.backtrace(session.context, Backtracer.FUZZY);
            const merged = this.mergeBacktraceFrames(frames.length > 1 ? frames : [], fuzzyFrames);
            merged.forEach((address, index) => {
                const resolved = resolveAddress(address);
                log(`[bt] #${index} ${address}${resolved.length > 0 ? ` ${resolved}` : ""}`, "gray");
            });
        } catch (error) {
            log(`[bt] failed: ${String(error)}`, "red");
        }
    }

    disassemble(position?: PointerInput, count = 8): void {
        const session = this.getPausedSession();
        if (session === null) {
            return;
        }

        const instructionCount = this.normalizeCount(count, 8);
        if (position === undefined) {
            if (session.displayPc === null) {
                log("[dis] no current pc", "yellow");
                return;
            }

            const capturedWindow = this.getCapturedWindow(session, session.displayPc, instructionCount);
            if (capturedWindow.length > 0) {
                logCapturedDisassemblyWindow(capturedWindow, session.displayPc, session.pc ?? undefined);
                return;
            }

            logDisassembly(session.displayPc, instructionCount);
            return;
        }

        try {
            const address = toPointer(position);
            const capturedWindow = this.getCapturedWindow(session, address, instructionCount);
            if (capturedWindow.length > 0) {
                logCapturedDisassemblyWindow(capturedWindow, address, session.pc ?? undefined);
                return;
            }

            logDisassembly(address, instructionCount);
        } catch (error) {
            log(`[dis] invalid address: ${String(error)}`, "red");
        }
    }

    stack(maxEntries = 32): void {
        const session = this.getPausedSession();
        if (session === null || session.context === null) {
            return;
        }

        session.lastStack = logStack(session.context, this.normalizeCount(maxEntries, 32), session.lastStack);
    }

    registers(): void {
        const session = this.getPausedSession();
        if (session === null || session.context === null) {
            log("[reg] no paused context", "yellow");
            return;
        }

        session.lastRegisters = logRegisters(session.context, null);
    }

    infoAddress(input: PointerInput | string): void {
        if (typeof input === "string") {
            const registerValue = this.getRegisterValue(input);
            if (registerValue !== null) {
                printAddressInfo(registerValue);
                return;
            }
        }

        printAddressInfo(input as PointerInput);
    }

    setRegister(name: string, value: PointerInput): void {
        const session = this.getPausedSession();
        if (session === null || session.context === null) {
            log("[reg] no paused context", "yellow");
            return;
        }

        const key = name.trim().toLowerCase();
        const context = session.context as unknown as Record<string, NativePointer>;
        if (!(key in context)) {
            log(`[reg] unknown register ${name}`, "red");
            return;
        }

        try {
            const nextValue = toPointer(value);
            context[key] = nextValue;
            session.lastRegisters = captureRegisters(session.context);
            log(`[reg] ${key} = ${nextValue}`, "green");
        } catch (error) {
            log(`[reg] failed to set ${key}: ${String(error)}`, "red");
        }
    }

    writeMemory(addressInput: PointerInput | string, value: PointerInput | number | string, type: MemoryWriteType = "pointer"): void {
        const address = this.resolveAddressInput(addressInput);
        if (address === null) {
            log(`[mem] invalid address ${String(addressInput)}`, "red");
            return;
        }

        writeMemoryValue(address, value, type);
    }

    listFields(input?: PointerInput | string): void {
        if (input === undefined) {
            log("[lfs] usage: lfs(\"x0\") or lfs(\"0xADDR\")", "yellow");
            return;
        }

        if (typeof input === "string") {
            const registerValue = this.getRegisterValue(input);
            if (registerValue !== null) {
                logIl2CppFields(registerValue);
                return;
            }
        }

        try {
            logIl2CppFields(toPointer(input as PointerInput));
        } catch (error) {
            log(`[lfs] invalid address: ${String(error)}`, "red");
        }
    }

    dispose(): void {
        if (this.disposed) {
            return;
        }

        this.disposed = true;
        log("[agent] disposing debugger state", "yellow");
        this.breakpoints.detachAll();

        for (const session of Array.from(this.sessions.values())) {
            session.stopRequested = true;
            try {
                Stalker.unfollow(session.threadId);
            } catch (error) {
                log(`[stalker] unfollow failed for thread ${session.threadId}: ${String(error)}`, "red");
            }

            session.semaphore.release();
            if (!session.paused) {
                this.finishSession(session);
            }
        }

        Stalker.garbageCollect();
        this.currentThreadId = null;
    }

    private startStalkerForHit(breakpoint: FunctionBreakpoint, context: CpuContext): void {
        if (this.disposed) {
            log("[stalker] debugger is disposed", "yellow");
            return;
        }

        const threadId = Process.getCurrentThreadId();
        this.currentThreadId = threadId;

        if (this.sessions.has(threadId)) {
            log(`[stalker] thread ${threadId} is already followed`, "yellow");
            return;
        }

        const filter = this.createTraceFilter(breakpoint.address);
        const session: StalkerSession = {
            breakpoint,
            threadId,
            semaphore: new Semaphore(),
            paused: false,
            stopRequested: false,
            stepCount: 0,
            pc: context.pc,
            displayPc: context.pc,
            instruction: null,
            seenOriginalCode: false,
            relocatedDisplayIndex: 0,
            filter,
            restoreFilter: null,
            context,
            lastRegisters: null,
            lastStack: null,
            pendingSteps: 0,
            runMode: "none",
            baseLr: null,
            targetLr: null,
            targetPc: null,
            autoBudget: 0,
            autoStopReason: null,
        };
        this.sessions.set(threadId, session);

        if (filter !== null) {
            log(`[stalker] trace filter ${filter.name} ${filter.base}-${filter.end}`, "cyan");
        } else {
            log("[stalker] trace filter none", "yellow");
        }
        log(`[stalker] follow thread ${threadId} from breakpoint ${breakpoint.address}`, "green");
        Stalker.follow(threadId, {
            events: {
                call: false,
                ret: false,
                exec: false,
                block: false,
                compile: false,
            },
            transform: (iterator: StalkerIterator) => this.transform(iterator, session),
        });
    }

    private transform(iterator: StalkerIterator, session: StalkerSession): void {
        let instruction: Instruction | null;
        while ((instruction = iterator.next()) !== null) {
            if (this.shouldTrace(instruction.address, session.filter)) {
                const address = instruction.address;
                const text = instruction.toString();
                iterator.putCallout((context: CpuContext) => this.onInstruction(context, address, text));
            }
            iterator.keep();
        }
    }

    private onInstruction(context: CpuContext, address: NativePointer, instructionText: string): void {
        const threadId = Process.getCurrentThreadId();
        const session = this.sessions.get(threadId);
        if (session === undefined || session.stopRequested) {
            return;
        }

        if (this.shouldContinueSilently(session, context, address)) {
            return;
        }

        session.paused = true;
        session.pc = address;
        session.stepCount += 1;
        this.currentThreadId = threadId;

        const displayInstruction = this.resolveDisplayInstruction(session, address, instructionText);
        session.displayPc = displayInstruction.address;
        session.instruction = displayInstruction.text;
        session.context = context;
        const reason = session.autoStopReason;
        session.autoStopReason = null;
        log(
            `[stalker] pause thread=${threadId} step=${session.stepCount} pc=${displayInstruction.address} actual=${address}${reason !== null ? ` reason=${reason}` : ""}`,
            "yellow",
        );

        if (isShown("asm")) {
            this.logCurrentDisassembly(session, displayInstruction, address);
        }
        if (isShown("reg")) {
            session.lastRegisters = logRegisters(context, session.lastRegisters);
        }
        if (isShown("stack")) {
            session.lastStack = logStack(context, 32, session.lastStack);
        }

        if (this.shouldAutoContinue(session, context, address)) {
            session.paused = false;
            return;
        }

        session.semaphore.wait();
        session.paused = false;

        if (session.stopRequested) {
            this.finishSession(session);
        }
    }

    private resolveDisplayInstruction(session: StalkerSession, address: NativePointer, instructionText: string): DisplayInstruction {
        if (this.isOriginalCodeAddress(session, address)) {
            session.seenOriginalCode = true;
            const captured = this.getCapturedInstruction(session, address);
            return {
                address,
                text: captured?.text ?? instructionText,
                mapped: false,
            };
        }

        if (!session.seenOriginalCode) {
            const mapped = this.getRelocatedEntryInstruction(session);
            if (mapped !== null) {
                session.relocatedDisplayIndex += 1;
                return {
                    address: mapped.address,
                    text: mapped.text,
                    mapped: true,
                };
            }
        }

        return {
            address,
            text: instructionText,
            mapped: false,
        };
    }

    private logCurrentDisassembly(session: StalkerSession, displayInstruction: DisplayInstruction, actualPc: NativePointer): void {
        const capturedWindow = this.getCapturedWindow(session, displayInstruction.address, 8);
        if (capturedWindow.length > 0) {
            logCapturedDisassemblyWindow(capturedWindow, displayInstruction.address, actualPc);
            return;
        }

        logDisassemblyWindow(displayInstruction.address, displayInstruction.text);
    }

    private isOriginalCodeAddress(session: StalkerSession, address: NativePointer): boolean {
        const filter = session.filter ?? session.restoreFilter;
        if (filter !== null) {
            return address.compare(filter.base) >= 0 && address.compare(filter.end) < 0;
        }

        if (session.breakpoint.moduleName === null) {
            return false;
        }

        try {
            const module = Process.findModuleByAddress(address);
            return module !== null && module.name === session.breakpoint.moduleName;
        } catch (_error) {
            return false;
        }
    }

    private getRelocatedEntryInstruction(session: StalkerSession): DisassembledInstruction | null {
        const instructions = session.breakpoint.originalDisassembly;
        const startIndex = instructions.findIndex((instruction) => instruction.address.equals(session.breakpoint.address));
        if (startIndex === -1) {
            return null;
        }

        return instructions[startIndex + session.relocatedDisplayIndex] ?? null;
    }

    private getCapturedInstruction(session: StalkerSession, address: NativePointer): DisassembledInstruction | null {
        return session.breakpoint.originalDisassembly.find((instruction) => instruction.address.equals(address)) ?? null;
    }

    private getCapturedWindow(session: StalkerSession, current: NativePointer, count: number): DisassembledInstruction[] {
        const instructions = session.breakpoint.originalDisassembly;
        const currentIndex = instructions.findIndex((instruction) => instruction.address.equals(current));
        if (currentIndex === -1) {
            return [];
        }

        const before = 2;
        const start = Math.max(0, currentIndex - before);
        return instructions.slice(start, start + count);
    }

    private getSession(threadId: ThreadId | null): StalkerSession | null {
        if (threadId === null) {
            log("[stalker] no current session", "yellow");
            return null;
        }

        const session = this.sessions.get(threadId);
        if (session === undefined) {
            log(`[stalker] no session for thread ${threadId}`, "yellow");
            return null;
        }

        return session;
    }

    private getPausedSession(): StalkerSession | null {
        const session = this.getSession(this.currentThreadId);
        if (session === null) {
            return null;
        }

        if (!session.paused) {
            log(`[stalker] thread ${session.threadId} is not paused`, "yellow");
            return null;
        }

        return session;
    }

    private finishSession(session: StalkerSession): void {
        session.semaphore.destroy();
        this.sessions.delete(session.threadId);
        if (this.currentThreadId === session.threadId) {
            this.currentThreadId = null;
        }
        log(`[stalker] stopped thread ${session.threadId}`, "green");
    }

    private createTraceFilter(address: NativePointer): TraceFilter | null {
        try {
            const module = Process.findModuleByAddress(address);
            if (module === null) {
                return null;
            }

            return {
                name: module.name,
                base: module.base,
                end: module.base.add(module.size),
            };
        } catch (error) {
            log(`[stalker] module lookup failed: ${String(error)}`, "red");
            return null;
        }
    }

    private shouldTrace(address: NativePointer, filter: TraceFilter | null): boolean {
        if (filter === null) {
            return true;
        }

        return address.compare(filter.base) >= 0 && address.compare(filter.end) < 0;
    }

    private shouldAutoContinue(session: StalkerSession, context: CpuContext, address: NativePointer): boolean {
        if (session.stopRequested) {
            return false;
        }

        if (session.runMode === "count") {
            session.pendingSteps -= 1;
            if (session.pendingSteps > 0) {
                return true;
            }

            session.runMode = "none";
            return false;
        }

        if (session.runMode === "step-in") {
            const currentLr = this.getLinkRegister(context);
            if (session.baseLr !== null && currentLr !== null && !currentLr.equals(session.baseLr)) {
                session.runMode = "none";
                session.baseLr = null;
                return false;
            }

            return true;
        }

        if (session.runMode === "step-out") {
            if (session.targetLr !== null && address.equals(session.targetLr)) {
                session.runMode = "none";
                session.targetLr = null;
                return false;
            }

            return true;
        }

        return false;
    }

    private shouldContinueSilently(session: StalkerSession, context: CpuContext, address: NativePointer): boolean {
        if (session.runMode === "until") {
            return this.shouldContinueUntil(session, address);
        }

        if (session.runMode !== "step-in" && session.runMode !== "step-out") {
            return false;
        }

        session.autoBudget -= 1;
        if (session.autoBudget <= 0) {
            session.autoStopReason = `${session.runMode}-budget-exhausted`;
            session.runMode = "none";
            session.baseLr = null;
            session.targetLr = null;
            session.targetPc = null;
            this.restoreTraceFilter(session);
            return false;
        }

        if (session.runMode === "step-in") {
            const currentLr = this.getLinkRegister(context);
            if (session.baseLr !== null && currentLr !== null && !currentLr.equals(session.baseLr)) {
                session.autoStopReason = `lr-changed ${session.baseLr}->${currentLr}`;
                session.runMode = "none";
                session.baseLr = null;
                session.targetPc = null;
                return false;
            }

            return true;
        }

        if (session.runMode === "step-out") {
            if (session.targetLr !== null && address.equals(session.targetLr)) {
                session.autoStopReason = `pc-reached-lr ${session.targetLr}`;
                session.runMode = "none";
                session.targetLr = null;
                session.targetPc = null;
                this.restoreTraceFilter(session);
                return false;
            }

            return true;
        }

        return false;
    }

    private shouldContinueUntil(session: StalkerSession, address: NativePointer): boolean {
        session.autoBudget -= 1;
        if (session.autoBudget <= 0) {
            session.autoStopReason = "until-budget-exhausted";
            session.runMode = "none";
            session.targetPc = null;
            this.restoreTraceFilter(session);
            return false;
        }

        if (session.targetPc !== null && address.equals(session.targetPc)) {
            session.autoStopReason = `pc-reached ${session.targetPc}`;
            session.runMode = "none";
            session.targetPc = null;
            this.restoreTraceFilter(session);
            return false;
        }

        return true;
    }

    private runUntilPointer(targetPc: NativePointer, reason: string): void {
        const session = this.getPausedSession();
        if (session === null) {
            return;
        }

        session.runMode = "until";
        session.targetPc = targetPc;
        session.targetLr = null;
        session.baseLr = null;
        session.autoBudget = MAX_SILENT_AUTO_STEPS;
        session.autoStopReason = null;

        this.relaxFilterIfNeeded(session, targetPc, reason);

        log(`[stalker] ${reason} target=${targetPc}`, "green");
        session.semaphore.post();
    }

    private relaxFilterIfNeeded(session: StalkerSession, target: NativePointer, reason: string): void {
        if (this.shouldTrace(target, session.filter)) {
            return;
        }

        log(`[stalker] ${reason} target outside filter; temporarily tracing all modules`, "yellow");
        session.restoreFilter = session.filter;
        session.filter = null;
    }

    private restoreTraceFilter(session: StalkerSession): void {
        if (session.restoreFilter === null) {
            return;
        }

        session.filter = session.restoreFilter;
        session.restoreFilter = null;
    }

    private backtraceByFramePointer(context: CpuContext): NativePointer[] {
        const frames: NativePointer[] = [context.pc];
        let fp = this.getFramePointer(context);
        const sp = this.getStackPointer(context);
        if (fp === null || sp === null || fp.compare(sp) < 0) {
            return frames;
        }

        for (let depth = 0; depth < 32; depth++) {
            try {
                const lr = fp.add(Process.pointerSize).readPointer();
                if (!lr.isNull()) {
                    frames.push(lr);
                }

                const nextFp = fp.readPointer();
                if (nextFp.isNull() || nextFp.compare(fp) <= 0) {
                    break;
                }
                fp = nextFp;
            } catch (_error) {
                break;
            }
        }

        return frames;
    }

    private mergeBacktraceFrames(primary: NativePointer[], fallback: NativePointer[]): NativePointer[] {
        const seen = new Set<string>();
        const result: NativePointer[] = [];

        for (const address of [...primary, ...fallback]) {
            const key = address.toString();
            if (seen.has(key)) {
                continue;
            }
            seen.add(key);
            result.push(address);
        }

        return result;
    }

    private getLinkRegister(context: CpuContext): NativePointer | null {
        if (Process.arch === "arm64") {
            return (context as Arm64CpuContext).lr;
        }

        if (Process.arch === "arm") {
            return (context as ArmCpuContext).lr;
        }

        return null;
    }

    private isCallInstruction(instruction: string | null): boolean {
        if (instruction === null) {
            return false;
        }

        const trimmed = instruction.trim();
        return trimmed.startsWith("bl ") || trimmed.startsWith("blr ");
    }

    private getFramePointer(context: CpuContext): NativePointer | null {
        if (Process.arch === "arm64") {
            return (context as Arm64CpuContext).fp;
        }

        if (Process.arch === "arm") {
            return (context as ArmCpuContext).r11;
        }

        return null;
    }

    private getStackPointer(context: CpuContext): NativePointer | null {
        if (Process.arch === "arm64") {
            return (context as Arm64CpuContext).sp;
        }

        if (Process.arch === "arm") {
            return (context as ArmCpuContext).sp;
        }

        return context.sp;
    }

    private normalizeCount(value: number, fallback: number): number {
        if (!Number.isFinite(value)) {
            return fallback;
        }

        const normalized = Math.floor(value);
        return normalized > 0 ? normalized : fallback;
    }

    private getRegisterValue(name: string): NativePointer | null {
        const session = this.getSession(this.currentThreadId);
        if (session === null || session.context === null) {
            return null;
        }

        const normalized = name.trim().toLowerCase();
        const registers = session.lastRegisters ?? captureRegisters(session.context);
        const value = registers[normalized];
        if (value === undefined) {
            return null;
        }

        try {
            return ptr(value);
        } catch (_error) {
            return null;
        }
    }

    private resolveAddressInput(input: PointerInput | string): NativePointer | null {
        if (typeof input !== "string") {
            try {
                return toPointer(input);
            } catch (_error) {
                return null;
            }
        }

        const registerExpression = input.trim().toLowerCase().match(/^([a-z][a-z0-9]*)(?:\s*([+-])\s*(0x[0-9a-f]+|\d+))?$/);
        if (registerExpression !== null) {
            const register = this.getRegisterValue(registerExpression[1]);
            if (register !== null) {
                const sign = registerExpression[2];
                const offsetText = registerExpression[3];
                if (sign === undefined || offsetText === undefined) {
                    return register;
                }

                const offset = Number(offsetText);
                return sign === "+" ? register.add(offset) : register.sub(offset);
            }
        }

        try {
            return toPointer(input);
        } catch (_error) {
            return null;
        }
    }
}
