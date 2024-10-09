import { ParserBase } from "./ParserBase.js"

export class SymbolParser extends ParserBase {

    protected constructor() { super() }

    asDebugSymbol(): DebugSymbol {
        return DebugSymbol.fromAddress(this.handle)
    }

    asMapString(map: Map<NativePointer, string>): string {
        return map.get(this.handle) || ''
    }
}

Reflect.set(globalThis, "SymbolParser", SymbolParser)