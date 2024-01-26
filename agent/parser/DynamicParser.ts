import { ParserBase } from "./ParserBase"

export class DynamicParser extends ParserBase {

    protected constructor() { super() }


}

Reflect.set(globalThis, "DynamicParser", DynamicParser)