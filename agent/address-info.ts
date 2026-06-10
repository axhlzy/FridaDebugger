import { log } from "./logger.js";
import { resolveIl2CppAddress, resolveIl2CppObject } from "./il2cpp-symbols.js";
import { toPointer } from "./pointer.js";
import type { PointerInput } from "./types.js";

export function infoAddress(input: PointerInput): void {
    try {
        const address = toPointer(input);
        const symbol = DebugSymbol.fromAddress(address);
        const resolved = resolveAddress(address);
        log(`[ia] ${address} ${resolved || formatSymbol(address, symbol)}`, resolved !== "" ? "magenta" : "gray");
    } catch (error) {
        log(`[ia] invalid address: ${String(error)}`, "red");
    }
}

export function resolveAddress(value: NativePointer): string {
    if (value.isNull()) {
        return "";
    }

    try {
        const symbol = DebugSymbol.fromAddress(value);
        const symbolText = symbol.moduleName === null && symbol.name === null ? "" : formatSymbol(value, symbol);
        const il2cppText = resolveIl2CppAddress(value);
        const objectText = resolveIl2CppObject(value);
        const parts = [symbolText, il2cppText, objectText].filter(part => part.length > 0);

        return parts.join(" @ ");
    } catch (_error) {
        return "";
    }
}

export function formatSymbol(address: NativePointer, symbol: DebugSymbol): string {
    if (symbol.moduleName === null && symbol.name === null) {
        return symbol.toString();
    }

    const addressText = address.toString();
    const symbolText = symbol.toString();
    if (symbolText.startsWith(addressText)) {
        return `@${symbolText.slice(addressText.length)}`;
    }

    return symbolText;
}
