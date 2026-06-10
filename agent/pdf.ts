import { formatSymbol } from "./address-info.js";
import { findIl2CppFunctionRange, resolveKnownIl2CppAddress } from "./il2cpp-symbols.js";
import { colorize, log } from "./logger.js";
import { toPointer } from "./pointer.js";
import type { PointerInput } from "./types.js";

const DEFAULT_MAX_INSTRUCTIONS = 4096;

export function printDisassembledFunction(input: PointerInput, maxInstructions = DEFAULT_MAX_INSTRUCTIONS): void {
    try {
        const address = toPointer(input);
        log(`[pdf] resolving IL2CPP function range for ${address}`, "cyan");
        // TODO: On frida-server >= 17.12.0, consider using
        // Process.findFunctionRange() and ControlFlowGraph here instead of the
        // IL2CPP method-order heuristic for function bounds.
        const range = findIl2CppFunctionRange(address);
        if (range === null) {
            log(`[pdf] cannot resolve IL2CPP function range for ${address}`, "red");
            return;
        }

        const instructionLimit = normalizeLimit(maxInstructions, DEFAULT_MAX_INSTRUCTIONS);
        log("[pdf] ------------------------------------------------------------", "cyan");
        log(`[pdf] ${range.start}-${range.end} size=${range.end.sub(range.start).toUInt32()} ${range.name}`, "green");

        let pc = range.start;
        let count = 0;
        while (pc.compare(range.end) < 0 && count < instructionLimit) {
            const instruction = Instruction.parse(pc);
            logInstruction(instruction);
            if (instruction.next.compare(pc) <= 0) {
                log(`[pdf] stopped: instruction parser did not advance at ${pc}`, "red");
                break;
            }
            pc = instruction.next;
            count++;
        }

        if (pc.compare(range.end) < 0) {
            log(`[pdf] ... stopped after ${instructionLimit} instructions at ${pc}; pass a larger maxInstructions if needed ...`, "yellow");
        }
    } catch (error) {
        log(`[pdf] failed: ${String(error)}`, "red");
    }
}

function logInstruction(instruction: Instruction): void {
    const target = getDirectCallTarget(instruction);
    const indirect = target === null && isIndirectCall(instruction);
    const address = colorize(instruction.address.toString().padEnd(20), "gray");
    const text = colorize(instruction.toString().padEnd(36), target !== null || indirect ? "yellow" : "gray");

    if (target !== null) {
        const resolved = resolveCallTarget(target);
        const suffix = resolved.length > 0 ? ` ; ${target} ${resolved}` : ` ; ${target}`;
        log(`[pdf] ${address} ${text}${colorize(suffix, "magenta")}`);
        return;
    }

    if (indirect) {
        log(`[pdf] ${address} ${text}${colorize(" ; indirect call", "magenta")}`);
        return;
    }

    log(`[pdf] ${address} ${text}`);
}

function resolveCallTarget(target: NativePointer): string {
    const cachedIl2Cpp = resolveKnownIl2CppAddress(target);
    if (cachedIl2Cpp.length > 0) {
        return cachedIl2Cpp;
    }

    try {
        const symbol = DebugSymbol.fromAddress(target);
        if (symbol.moduleName === null && symbol.name === null) {
            return "";
        }

        return formatSymbol(target, symbol);
    } catch (_error) {
        return "";
    }
}

function getDirectCallTarget(instruction: Instruction): NativePointer | null {
    const mnemonic = instruction.mnemonic.toLowerCase();
    if (!isDirectCallMnemonic(mnemonic)) {
        return null;
    }

    const match = instruction.toString().match(/(?:#)?(0x[0-9a-fA-F]+)/);
    if (match === null) {
        return null;
    }

    try {
        return ptr(match[1]);
    } catch (_error) {
        return null;
    }
}

function isDirectCallMnemonic(mnemonic: string): boolean {
    return mnemonic === "bl" || mnemonic === "call";
}

function isIndirectCall(instruction: Instruction): boolean {
    const mnemonic = instruction.mnemonic.toLowerCase();
    return mnemonic === "blr" || mnemonic === "call";
}

function normalizeLimit(value: number, fallback: number): number {
    if (!Number.isFinite(value) || value <= 0) {
        return fallback;
    }

    return Math.max(1, Math.floor(value));
}
