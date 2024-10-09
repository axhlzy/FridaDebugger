import { ParserBase } from "./ParserBase.js"

export class StructParser extends ParserBase {

    protected constructor() { super() }

    asCStruct(c_code: string): string {
        const cmd = new CModule(c_code)
        //todo

        return ''
    }
}

Reflect.set(globalThis, "StructParser", StructParser)