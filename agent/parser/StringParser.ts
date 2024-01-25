import { ParserBase } from "./ParserBase"

export class StringParser extends ParserBase {

    asU16String(): string | null {
        return this.handle.readUtf16String()
    }

    asU8String(): string | null {
        return this.handle.readUtf8String()
    }

    asStdSting(): string | null {
        return this.handle.readCString()
    }

    asCString(): string | null {
        return this.handle.readCString()
    }

    asUnityString(): string | null {
        // return new Il2Cpp.String(this.handle).content
        return ''
    }
}