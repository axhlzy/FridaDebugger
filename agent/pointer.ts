import type { PointerInput } from "./types.js";

export function toPointer(input: PointerInput): NativePointer {
    if (input instanceof NativePointer) {
        return input;
    }

    if (typeof input === "number" && !Number.isSafeInteger(input)) {
        throw new Error(`unsafe numeric address ${input}; use b("0x...") or b(ptr("0x..."))`);
    }

    return ptr(input);
}

export function pointerId(address: NativePointer): string {
    return address.toString();
}

export function describeAddress(address: NativePointer): string {
    return `${address} ${DebugSymbol.fromAddress(address)}`;
}
