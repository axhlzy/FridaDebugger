import { resolveAddress } from "./address-info.js";
import { isShown } from "./display.js";
import { formatReg } from "./format.js";
import { colorize, log } from "./logger.js";

export type RegisterSnapshot = Record<string, string>;

export function captureRegisters(context: CpuContext): RegisterSnapshot {
    if (Process.arch === "arm64") {
        const arm64 = context as Arm64CpuContext;
        return {
            pc: arm64.pc.toString(),
            sp: arm64.sp.toString(),
            fp: arm64.fp.toString(),
            lr: arm64.lr.toString(),
            x0: arm64.x0.toString(),
            x1: arm64.x1.toString(),
            x2: arm64.x2.toString(),
            x3: arm64.x3.toString(),
            x4: arm64.x4.toString(),
            x5: arm64.x5.toString(),
            x6: arm64.x6.toString(),
            x7: arm64.x7.toString(),
            x8: arm64.x8.toString(),
            x9: arm64.x9.toString(),
            x10: arm64.x10.toString(),
            x11: arm64.x11.toString(),
            x12: arm64.x12.toString(),
            x13: arm64.x13.toString(),
            x14: arm64.x14.toString(),
            x15: arm64.x15.toString(),
            x16: arm64.x16.toString(),
            x17: arm64.x17.toString(),
            x18: arm64.x18.toString(),
            x19: arm64.x19.toString(),
            x20: arm64.x20.toString(),
            x21: arm64.x21.toString(),
            x22: arm64.x22.toString(),
            x23: arm64.x23.toString(),
            x24: arm64.x24.toString(),
            x25: arm64.x25.toString(),
            x26: arm64.x26.toString(),
            x27: arm64.x27.toString(),
            x28: arm64.x28.toString(),
        };
    }

    if (Process.arch === "arm") {
        const arm = context as ArmCpuContext;
        return {
            pc: arm.pc.toString(),
            sp: arm.sp.toString(),
            lr: arm.lr.toString(),
            r0: arm.r0.toString(),
            r1: arm.r1.toString(),
            r2: arm.r2.toString(),
            r3: arm.r3.toString(),
            r4: arm.r4.toString(),
            r5: arm.r5.toString(),
            r6: arm.r6.toString(),
            r7: arm.r7.toString(),
            r8: arm.r8.toString(),
            r9: arm.r9.toString(),
            r10: arm.r10.toString(),
            r11: arm.r11.toString(),
            r12: arm.r12.toString(),
        };
    }

    return {
        pc: context.pc.toString(),
        sp: context.sp.toString(),
    };
}

export function logRegisters(context: CpuContext, previous?: RegisterSnapshot | null): RegisterSnapshot {
    const current = captureRegisters(context);

    if (Process.arch === "arm64") {
        log("[reg] ------------------------------------------------------------", "cyan");
        logRegLine(["pc", "sp", "fp", "lr"], current, previous);
        logRegLine(["x0", "x1", "x2", "x3"], current, previous);
        logRegLine(["x4", "x5", "x6", "x7"], current, previous);
        logRegLine(["x8", "x9", "x10", "x11"], current, previous);
        logRegLine(["x12", "x13", "x14", "x15"], current, previous);
        logRegLine(["x16", "x17", "x18", "x19"], current, previous);
        logRegLine(["x20", "x21", "x22", "x23"], current, previous);
        logRegLine(["x24", "x25", "x26", "x27"], current, previous);
        logRegLine(["x28"], current, previous);
        logRegisterSymbols(current, previous);
        return current;
    }

    if (Process.arch === "arm") {
        log("[reg] ------------------------------------------------------------", "cyan");
        logRegLine(["pc", "sp", "lr"], current, previous);
        logRegLine(["r0", "r1", "r2", "r3"], current, previous);
        logRegLine(["r4", "r5", "r6", "r7"], current, previous);
        logRegLine(["r8", "r9", "r10", "r11", "r12"], current, previous);
        logRegisterSymbols(current, previous);
        return current;
    }

    log(`[reg] pc=${context.pc} sp=${context.sp}`);
    return current;
}

function logRegLine(names: string[], current: RegisterSnapshot, previous?: RegisterSnapshot | null): void {
    const entries = names.map((name) => formatRegister(name, current, previous));
    log(`[reg] ${entries.join(" ")}`);
}

function formatRegister(name: string, current: RegisterSnapshot, previous?: RegisterSnapshot | null): string {
    const value = current[name] ?? "n/a";
    const entry = formatReg(name, value);
    if (previous !== undefined && previous !== null && previous[name] !== value) {
        return colorize(entry, "red");
    }

    return colorize(entry, "gray");
}

function logRegisterSymbols(current: RegisterSnapshot, previous?: RegisterSnapshot | null): void {
    if (!isShown("sym")) {
        return;
    }

    for (const [name, value] of Object.entries(current)) {
        const symbol = resolveRegisterValue(value);
        if (symbol.length === 0) {
            continue;
        }

        const changed = previous !== undefined && previous !== null && previous[name] !== value;
        log(`[sym] ${name.padEnd(4)} ${value.padEnd(20)} ${symbol}`, changed ? "red" : "magenta");
    }
}

function resolveRegisterValue(value: string): string {
    try {
        return resolveAddress(ptr(value));
    } catch (_error) {
        return "";
    }
}
