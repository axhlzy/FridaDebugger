import { resolveAddress } from "./address-info.js";
import { log } from "./logger.js";
import { toPointer } from "./pointer.js";
import type { PointerInput } from "./types.js";

export interface CallableNativeFunction {
    (...args: FunctionCallInput[]): NativePointer | null;
    address: NativePointer;
}

export type FunctionCallInput = PointerInput | CallableNativeFunction;

export function callFunction(addressInput: FunctionCallInput, ...args: FunctionCallInput[]): NativePointer | null {
    try {
        const address = toCallPointer(addressInput);
        const nativeArgs = args.map(arg => toCallPointer(arg));
        const fn = new NativeFunction(address, "pointer", nativeArgs.map(() => "pointer")) as unknown as (...callArgs: NativePointer[]) => NativePointer;
        const result = fn(...nativeArgs);
        const resolved = resolveAddress(result);
        log(`[call] ${address}(${nativeArgs.join(", ")}) => ${result}${resolved.length > 0 ? ` ${resolved}` : ""}`, "green");
        return result;
    } catch (error) {
        log(`[call] failed: ${String(error)}`, "red");
        return null;
    }
}

export function createCallableFunction(address: NativePointer): CallableNativeFunction {
    const callable = ((...args: FunctionCallInput[]) => callFunction(address, ...args)) as CallableNativeFunction;
    Object.defineProperty(callable, "address", {
        value: address,
        enumerable: false,
    });
    Object.defineProperty(callable, "toString", {
        value: () => address.toString(),
        enumerable: false,
    });
    Object.defineProperty(callable, Symbol.toPrimitive, {
        value: () => address.toString(),
        enumerable: false,
    });
    return callable;
}

function toCallPointer(input: FunctionCallInput): NativePointer {
    if (isCallableNativeFunction(input)) {
        return input.address;
    }

    return toPointer(input);
}

function isCallableNativeFunction(value: FunctionCallInput): value is CallableNativeFunction {
    return typeof value === "function" && "address" in value && value.address instanceof NativePointer;
}
