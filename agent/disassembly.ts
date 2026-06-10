import { padRight } from "./format.js";
import { log } from "./logger.js";

const ARM_INSTRUCTION_SIZE = 4;

export interface DisassembledInstruction {
    address: NativePointer;
    text: string;
}

export function logCurrentInstruction(address: NativePointer, text: string): void {
    log(`[asm] => ${address}  ${text}`, "yellow");
}

export function captureDisassemblyWindow(current: NativePointer, before = 2, after = 5): DisassembledInstruction[] {
    if (Process.arch !== "arm64" && Process.arch !== "arm") {
        return [{ address: current, text: parseInstruction(current) }];
    }

    const start = current.sub(before * ARM_INSTRUCTION_SIZE);
    const count = before + after + 1;
    const result: DisassembledInstruction[] = [];

    for (let index = 0; index < count; index++) {
        const address = start.add(index * ARM_INSTRUCTION_SIZE);
        result.push({ address, text: parseInstruction(address) });
    }

    return result;
}

export function logDisassemblyWindow(current: NativePointer, currentText: string, before = 2, after = 5): void {
    if (Process.arch !== "arm64" && Process.arch !== "arm") {
        logCurrentInstruction(current, currentText);
        return;
    }

    log("[asm] ------------------------------------------------------------", "cyan");
    const start = current.sub(before * ARM_INSTRUCTION_SIZE);
    const count = before + after + 1;

    for (let index = 0; index < count; index++) {
        const address = start.add(index * ARM_INSTRUCTION_SIZE);
        const marker = address.equals(current) ? "=>" : "  ";
        const instructionText = address.equals(current) ? currentText : parseInstruction(address);
        log(`[asm] ${marker} ${padRight(address, 14)} ${instructionText}`, marker === "=>" ? "yellow" : "gray");
    }
}

export function logCapturedDisassemblyWindow(
    instructions: DisassembledInstruction[],
    current: NativePointer,
    actualPc?: NativePointer,
): void {
    if (instructions.length === 0) {
        logDisassembly(current, 8);
        return;
    }

    log("[asm] ------------------------------------------------------------", "cyan");
    if (actualPc !== undefined && !actualPc.equals(current)) {
        log(`[asm] mapped stop ${current} actual ${actualPc}`, "magenta");
    }

    for (const instruction of instructions) {
        const marker = instruction.address.equals(current) ? "=>" : "  ";
        log(
            `[asm] ${marker} ${padRight(instruction.address, 14)} ${instruction.text}`,
            marker === "=>" ? "yellow" : "gray",
        );
    }
}

export function logDisassembly(address: NativePointer, count = 8): void {
    log("[asm] ------------------------------------------------------------", "cyan");
    let current = address;
    for (let index = 0; index < count; index++) {
        const marker = index === 0 ? "=>" : "  ";
        const text = parseInstruction(current);
        log(`[asm] ${marker} ${padRight(current, 14)} ${text}`, marker === "=>" ? "yellow" : "gray");
        current = current.add(Process.arch === "arm64" || Process.arch === "arm" ? ARM_INSTRUCTION_SIZE : 1);
    }
}

function parseInstruction(address: NativePointer): string {
    try {
        return Instruction.parse(address).toString();
    } catch (error) {
        return `<parse failed: ${String(error)}>`;
    }
}
