import type { DisassembledInstruction } from "./disassembly.js";

export type PointerInput = NativePointer | string | number;
export type StalkerIterator =
    | StalkerArmIterator
    | StalkerArm64Iterator
    | StalkerThumbIterator
    | StalkerX86Iterator;

export interface FunctionBreakpoint {
    address: NativePointer;
    enabled: boolean;
    hitCount: number;
    listener: InvocationListener;
    originalDisassembly: DisassembledInstruction[];
    moduleName: string | null;
    moduleOffset: NativePointer | null;
}

export type AddBreakpointResult = FunctionBreakpoint | null;

export interface BreakpointOptions {
    snapshot?: boolean;
}

export type BreakpointEnterHandler = (
    breakpoint: FunctionBreakpoint,
    args: InvocationArguments,
    context: CpuContext,
) => void;
