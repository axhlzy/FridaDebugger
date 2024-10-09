import { ParserBase } from "./ParserBase.js"

export class DynamicParser extends ParserBase {

    protected constructor() { super() }


}

Reflect.set(globalThis, "DynamicParser", DynamicParser)