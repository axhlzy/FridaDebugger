import { padLeft, padRight } from "./format.js";
import { colorize, log } from "./logger.js";
import { resolveAddress } from "./address-info.js";

const DEFAULT_MAX_ENTRIES = 32;
const DEFAULT_HEAD_ENTRIES = 20;
const DEFAULT_TAIL_ENTRIES = 8;
const MAX_STACK_BYTES = 0x4000;

export type StackSnapshot = Record<string, string>;

export function logStack(
    context: CpuContext,
    maxEntries = DEFAULT_MAX_ENTRIES,
    previous?: StackSnapshot | null,
): StackSnapshot {
    const sp = getStackPointer(context);
    const fp = getFramePointer(context);
    if (sp === null) {
        log("[stk] no stack pointer in current context", "yellow");
        return {};
    }

    const snapshot: StackSnapshot = {};
    const markers = getContextMarkers(context, sp, fp);
    const totalEntries = getEntryCount(sp, fp, maxEntries);
    const headEntries = Math.min(DEFAULT_HEAD_ENTRIES, maxEntries);
    const tailEntries = Math.min(DEFAULT_TAIL_ENTRIES, Math.max(maxEntries - headEntries, 0));
    const omitted = totalEntries > maxEntries;

    log("[stk] ------------------------------------------------------------", "cyan");
    log(`[stk] fp=${fp ?? "n/a"} -> sp=${sp} entries=${totalEntries}${omitted ? " (truncated)" : ""}`, "green");

    let didOmit = false;
    for (const index of getDisplayIndices(totalEntries, omitted, headEntries, tailEntries)) {
        if (index === -1) {
            if (!didOmit) {
                const omittedCount = totalEntries - headEntries - tailEntries;
                log(`[stk] ... ${omittedCount} entries omitted ...`, "yellow");
                didOmit = true;
            }
            continue;
        }

        const slot = sp.add(index * Process.pointerSize);
        logStackSlot(index, slot, snapshot, previous, markers);
    }

    return snapshot;
}

function getDisplayIndices(totalEntries: number, omitted: boolean, headEntries: number, tailEntries: number): number[] {
    if (!omitted) {
        return Array.from({ length: totalEntries }, (_value, index) => totalEntries - 1 - index);
    }

    const highAddressSide = Array.from({ length: tailEntries }, (_value, index) => totalEntries - 1 - index);
    const lowAddressSide = Array.from({ length: headEntries }, (_value, index) => headEntries - 1 - index);
    return [...highAddressSide, -1, ...lowAddressSide];
}

function getEntryCount(sp: NativePointer, fp: NativePointer | null, maxEntries: number): number {
    if (fp === null || fp.compare(sp) <= 0) {
        return maxEntries;
    }

    const byteLength = fp.sub(sp).toUInt32();
    if (byteLength <= 0 || byteLength > MAX_STACK_BYTES) {
        return maxEntries;
    }

    return Math.max(1, Math.floor(byteLength / Process.pointerSize) + 1);
}

function logStackSlot(
    index: number,
    slot: NativePointer,
    snapshot: StackSnapshot,
    previous?: StackSnapshot | null,
    markers?: StackMarkers,
): void {
    const offset = `+0x${(index * Process.pointerSize).toString(16).padStart(4, "0")}`;
    try {
        const value = slot.readPointer();
        const valueText = value.toString();
        snapshot[offset] = valueText;
        const changed = previous !== undefined && previous !== null && previous[offset] !== valueText;
        const symbol = resolveAddress(value);
        const line = [
            colorize("[stk]", "gray"),
            colorize(padLeft(offset, 7), "yellow"),
            colorize(padRight(slot, 14), "cyan"),
            "=>",
            colorize(padRight(value, 20), changed ? "red" : symbol.length > 0 ? "green" : "gray"),
            symbol.length > 0 ? colorize(symbol, changed ? "red" : "magenta") : "",
            markers === undefined ? "" : formatMarkers(slot, value, markers),
        ].filter((part) => part.length > 0).join(" ");
        log(line);
    } catch (error) {
        log(`[stk] ${offset} ${slot} => <read failed: ${String(error)}>`, "red");
    }
}

interface StackMarkers {
    sp: NativePointer;
    fp: NativePointer | null;
    pc: NativePointer;
    lr: NativePointer | null;
}

function getContextMarkers(context: CpuContext, sp: NativePointer, fp: NativePointer | null): StackMarkers {
    return {
        sp,
        fp,
        pc: context.pc,
        lr: getLinkRegister(context),
    };
}

function formatMarkers(slot: NativePointer, value: NativePointer, markers: StackMarkers): string {
    const labels: string[] = [];
    if (slot.equals(markers.sp)) {
        labels.push("slot=sp");
    }
    if (markers.fp !== null && slot.equals(markers.fp)) {
        labels.push("slot=fp");
    }
    if (value.equals(markers.pc)) {
        labels.push("value=pc");
    }
    if (markers.lr !== null && value.equals(markers.lr)) {
        labels.push("value=lr");
    }

    return labels.length === 0 ? "" : colorize(`<${labels.join(",")}>`, "yellow");
}

function getLinkRegister(context: CpuContext): NativePointer | null {
    if (Process.arch === "arm64") {
        return (context as Arm64CpuContext).lr;
    }

    if (Process.arch === "arm") {
        return (context as ArmCpuContext).lr;
    }

    return null;
}

function getStackPointer(context: CpuContext): NativePointer | null {
    if (Process.arch === "arm64") {
        return (context as Arm64CpuContext).sp;
    }

    if (Process.arch === "arm") {
        return (context as ArmCpuContext).sp;
    }

    return context.sp;
}

function getFramePointer(context: CpuContext): NativePointer | null {
    if (Process.arch === "arm64") {
        return (context as Arm64CpuContext).fp;
    }

    if (Process.arch === "arm") {
        return (context as ArmCpuContext).r11;
    }

    return null;
}
