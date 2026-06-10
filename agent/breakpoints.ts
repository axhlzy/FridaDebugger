import { captureDisassemblyWindow } from "./disassembly.js";
import { log } from "./logger.js";
import { pointerId, toPointer } from "./pointer.js";
import { logRegisters } from "./registers.js";
import type { AddBreakpointResult, BreakpointEnterHandler, BreakpointOptions, FunctionBreakpoint, PointerInput } from "./types.js";

export class BreakpointStore {
    private readonly breakpoints = new Map<string, FunctionBreakpoint>();

    constructor(private readonly onBreakpointEnter?: BreakpointEnterHandler) {}

    add(input: PointerInput, options: BreakpointOptions = {}): AddBreakpointResult {
        let address: NativePointer;
        try {
            address = toPointer(input);
        } catch (error) {
            log(`[bp] invalid address: ${String(error)}`, "red");
            return null;
        }

        log(`[bp] request attach ${address}`, "cyan");

        const id = pointerId(address);
        const existing = this.breakpoints.get(id);
        if (existing !== undefined) {
            existing.enabled = true;
            log(`[bp] already attached ${address}`, "yellow");
            return existing;
        }

        log(`[bp] attach ${address}`, "cyan");
        const originalDisassembly = options.snapshot === false ? [] : captureDisassemblyWindow(address, 2, 32);
        const moduleInfo = this.getModuleInfo(address);
        const store = this;
        const listener = Interceptor.attach(address, {
            onEnter(args) {
                store.onEnter(id, args, this.context);
            },
        });

        const breakpoint: FunctionBreakpoint = {
            address,
            enabled: true,
            hitCount: 0,
            listener,
            originalDisassembly,
            moduleName: moduleInfo.name,
            moduleOffset: moduleInfo.offset,
        };
        this.breakpoints.set(id, breakpoint);
        log(`[bp] attached ${address}`, "green");
        return breakpoint;
    }

    remove(input: PointerInput): boolean {
        const address = toPointer(input);
        const breakpoint = this.breakpoints.get(pointerId(address));
        if (breakpoint === undefined) {
            log(`[bp] not found ${address}`, "yellow");
            return false;
        }

        breakpoint.listener.detach();
        this.breakpoints.delete(pointerId(address));
        log(`[bp] detached ${address}`, "green");
        return true;
    }

    enable(input: PointerInput): boolean {
        return this.setEnabled(input, true);
    }

    disable(input: PointerInput): boolean {
        return this.setEnabled(input, false);
    }

    detachAll(): void {
        for (const breakpoint of this.breakpoints.values()) {
            breakpoint.listener.detach();
            log(`[bp] detached ${breakpoint.address}`, "green");
        }
        this.breakpoints.clear();
    }

    list(): void {
        if (this.breakpoints.size === 0) {
            log("[bp] no breakpoints", "gray");
            return;
        }

        for (const breakpoint of this.breakpoints.values()) {
            const state = breakpoint.enabled ? "enabled" : "disabled";
            const moduleText = breakpoint.moduleName === null ? "" : ` ${breakpoint.moduleName}!${breakpoint.moduleOffset}`;
            log(`[bp] ${state} hits=${breakpoint.hitCount} ${breakpoint.address}${moduleText}`, "gray");
        }
    }

    private setEnabled(input: PointerInput, enabled: boolean): boolean {
        const address = toPointer(input);
        const breakpoint = this.breakpoints.get(pointerId(address));
        if (breakpoint === undefined) {
            log(`[bp] not found ${address}`, "yellow");
            return false;
        }

        breakpoint.enabled = enabled;
        log(`[bp] ${enabled ? "enabled" : "disabled"} ${address}`, enabled ? "green" : "yellow");
        return true;
    }

    private onEnter(id: string, args: InvocationArguments, context: CpuContext): void {
        const breakpoint = this.breakpoints.get(id);
        if (breakpoint === undefined || !breakpoint.enabled) {
            return;
        }

        breakpoint.hitCount += 1;
        log(`[bp] hit ${breakpoint.address} hits=${breakpoint.hitCount}`, "yellow");
        log(`[bp] tid=${Process.getCurrentThreadId()}`, "gray");
        log(`[bp] args=${args[0]}, ${args[1]}, ${args[2]}, ${args[3]}`, "gray");

        if (this.onBreakpointEnter !== undefined) {
            this.onBreakpointEnter(breakpoint, args, context);
            return;
        }

        logRegisters(context);
    }

    private getModuleInfo(address: NativePointer): { name: string | null; offset: NativePointer | null } {
        try {
            const module = Process.findModuleByAddress(address);
            if (module === null) {
                return { name: null, offset: null };
            }

            return { name: module.name, offset: address.sub(module.base) };
        } catch (_error) {
            return { name: null, offset: null };
        }
    }
}
