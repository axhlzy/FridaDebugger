import { setShown, type DisplaySection } from "./display.js";
import { testControlFlowGraph, testFindFunctionRange } from "./cfg-test.js";
import { callFunction, type FunctionCallInput } from "./function-call.js";
import { isUnityIl2CppProcess } from "./il2cpp-symbols.js";
import { log } from "./logger.js";
import type { MemoryWriteType } from "./memory-write.js";
import { printDisassembledFunction } from "./pdf.js";
import { StalkerBreakpointDebugger } from "./debugger.js";
import { NativeSymbolResolver } from "./symbols.js";
import type { BreakpointOptions, PointerInput } from "./types.js";

const debuggerAgent = new StalkerBreakpointDebugger();
const nativeSymbols = new NativeSymbolResolver();
const lifecycle = {};
const isUnity = isUnityIl2CppProcess();

const commands = {
    help: () => printHelp(),
    b: (address: PointerInput, options?: BreakpointOptions) => {
        debuggerAgent.breakpoints.add(address, options);
    },
    bc: (address: PointerInput) => {
        debuggerAgent.breakpoints.remove(address);
    },
    bd: (address: PointerInput) => {
        debuggerAgent.breakpoints.disable(address);
    },
    be: (address: PointerInput) => {
        debuggerAgent.breakpoints.enable(address);
    },
    bl: () => {
        debuggerAgent.breakpoints.list();
    },
    s: (count?: number) => debuggerAgent.step(count),
    si: () => debuggerAgent.stepIn(),
    so: () => debuggerAgent.stepOut(),
    ni: () => debuggerAgent.next(),
    until: (address: PointerInput) => debuggerAgent.until(address),
    c: (threadId?: ThreadId) => debuggerAgent.continue(threadId),
    d: () => {
        debuggerAgent.continue();
        debuggerAgent.breakpoints.detachAll();
    },
    bt: () => debuggerAgent.backtrace(),
    regs: () => debuggerAgent.registers(),
    dis: (position?: PointerInput, count?: number) => debuggerAgent.disassemble(position, count),
    stack: (maxEntries?: number) => debuggerAgent.stack(maxEntries),
    ia: (address: PointerInput | string) => debuggerAgent.infoAddress(address),
    sr: (register: string, value: PointerInput) => debuggerAgent.setRegister(register, value),
    setreg: (register: string, value: PointerInput) => debuggerAgent.setRegister(register, value),
    wm: (address: PointerInput | string, value: PointerInput | number | string, type?: MemoryWriteType) => debuggerAgent.writeMemory(address, value, type),
    wmem: (address: PointerInput | string, value: PointerInput | number | string, type?: MemoryWriteType) => debuggerAgent.writeMemory(address, value, type),
    callFunction: (address: FunctionCallInput, ...args: FunctionCallInput[]) => callFunction(address, ...args),
    ffr: (address: PointerInput) => testFindFunctionRange(address),
    cfg: (address: PointerInput, maxBlocks?: number, maxInstructions?: number) => testControlFlowGraph(address, maxBlocks, maxInstructions),
    show: (section: DisplaySection | "all", enabled?: boolean) => setShown(section, enabled),
    status: () => debuggerAgent.status(),
    dispose: () => debuggerAgent.dispose(),
    sym: nativeSymbols.root,
};

Object.assign(
    globalThis,
    commands,
    isUnity
        ? {
            lfs: (address?: PointerInput | string) => debuggerAgent.listFields(address),
            pdf: (address: PointerInput, maxInstructions?: number) => printDisassembledFunction(address, maxInstructions),
        }
        : {},
);

Script.bindWeak(lifecycle, () => {
    Script.nextTick(() => {
        debuggerAgent.dispose();
    });
});

function printHelp(): void {
    log("============================================================", "cyan");
    log(" Frida Stalker Breakpoint Debugger", "green");
    log("============================================================", "cyan");
    log(" General", "yellow");
    log("   help()              print this help page", "gray");
    log("", "gray");
    log(" Breakpoints", "yellow");
    log("   b(\"0xADDR\")        attach a breakpoint at address", "gray");
    log("   b(\"0xADDR\", { snapshot: false }) skip pre-attach disassembly", "gray");
    log("   bl()                list breakpoints", "gray");
    log("   bc(\"0xADDR\")       detach a breakpoint", "gray");
    log("   bd(\"0xADDR\")       disable a breakpoint", "gray");
    log("   be(\"0xADDR\")       enable a breakpoint", "gray");
    log("   d()                 continue current session and detach all breakpoints", "gray");
    log("", "gray");
    log(" Execution", "yellow");
    log("   s()                 step 1 instruction", "gray");
    log("   s(count)            step count instructions", "gray");
    log("   si()                step in; run until LR changes", "gray");
    log("   so()                step out; run until PC reaches current LR", "gray");
    log("   ni()                next/step-over call-like instruction", "gray");
    log("   until(\"0xADDR\")    run silently until address", "gray");
    log("   c()                 continue and stop current Stalker session", "gray");
    log("", "gray");
    log(" Inspect", "yellow");
    log("   dis()               disassemble from current position, 8 instructions", "gray");
    log("   dis(\"0xADDR\", n)   disassemble n instructions from address", "gray");
    log("   bt()                print backtrace for paused context", "gray");
    log("   regs()              print current registers", "gray");
    log("   stack()             print SP..FP stack window", "gray");
    log("   stack(n)            print stack window with at most n entries", "gray");
    log("   ia(\"0xADDR\")       resolve address with DebugSymbol and lazy IL2CPP names", "gray");
    log("   ia(\"x0\")           resolve register value from paused context", "gray");
    log("   sr(\"x0\", \"0x1\")   set register in paused context", "gray");
    log("   wm(\"sp+0x20\", 0, \"u32\") write memory/register-relative stack slot", "gray");
    log("   callFunction(sym.il2cpp.il2cpp_string_new, Memory.allocUtf8String(\"123\"))", "gray");
    log("   sym.MODULE.NAME     exported symbol pointer, e.g. sym.il2cpp.il2cpp_string_new", "gray");
    log("   sym.reload()        refresh native symbol namespaces", "gray");
    if (isUnity) {
        log("   lfs(\"x0\")          list fields of a Unity Il2Cpp.Object register", "gray");
        log("   lfs(\"0xADDR\")      list fields of a Unity Il2Cpp.Object address", "gray");
        log("   pdf(\"0xADDR\")      disassemble full IL2CPP function by ordered methods", "gray");
    }
    log("   show(\"stack\", false) toggle asm/reg/sym/stack/bt output", "gray");
    log("   status()            show active Stalker sessions", "gray");
    log("", "gray");
    log(" Experimental (requires frida-server >= 17.12.0)", "yellow");
    log("   ffr(\"0xADDR\")      test Process.findFunctionRange(address)", "gray");
    log("   cfg(\"0xADDR\")      test ControlFlowGraph basic blocks", "gray");
    log("   cfg(\"0xADDR\", b, i) limit blocks and instructions per block", "gray");
    log("", "gray");
    log(" Cleanup", "yellow");
    log("   dispose()           detach listeners, unfollow Stalker, release locks", "gray");
    log("============================================================", "cyan");
}

printHelp();
