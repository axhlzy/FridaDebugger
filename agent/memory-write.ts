import { log } from "./logger.js";
import { toPointer } from "./pointer.js";
import type { PointerInput } from "./types.js";

export type MemoryWriteType = "pointer" | "ptr" | "u8" | "u16" | "u32" | "u64" | "s8" | "s16" | "s32" | "s64" | "float" | "double" | "utf8";

export function writeMemoryValue(address: NativePointer, value: PointerInput | number | string, type: MemoryWriteType = "pointer"): void {
    try {
        switch (type) {
            case "pointer":
            case "ptr":
                address.writePointer(toPointer(value as PointerInput));
                break;
            case "u8":
                address.writeU8(Number(value));
                break;
            case "u16":
                address.writeU16(Number(value));
                break;
            case "u32":
                address.writeU32(Number(value));
                break;
            case "u64":
                address.writeU64(toUInt64(value));
                break;
            case "s8":
                address.writeS8(Number(value));
                break;
            case "s16":
                address.writeS16(Number(value));
                break;
            case "s32":
                address.writeS32(Number(value));
                break;
            case "s64":
                address.writeS64(toInt64(value));
                break;
            case "float":
                address.writeFloat(Number(value));
                break;
            case "double":
                address.writeDouble(Number(value));
                break;
            case "utf8":
                address.writeUtf8String(String(value));
                break;
            default:
                log(`[mem] unsupported write type ${String(type)}`, "red");
                return;
        }

        log(`[mem] write ${type} ${address} = ${value}`, "green");
    } catch (error) {
        log(`[mem] write failed at ${address}: ${String(error)}`, "red");
    }
}

function toUInt64(value: PointerInput | number | string): number | UInt64 {
    if (typeof value === "number") {
        return value;
    }

    if (value instanceof UInt64) {
        return value;
    }

    return new UInt64(String(value));
}

function toInt64(value: PointerInput | number | string): number | Int64 {
    if (typeof value === "number") {
        return value;
    }

    if (value instanceof Int64) {
        return value;
    }

    return new Int64(String(value));
}
