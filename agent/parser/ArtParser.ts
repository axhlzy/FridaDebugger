import { ParserBase } from "./ParserBase"

export class ArtParser extends ParserBase {

    from(handle: NativePointer) {
        this.handle = handle
    }

    asArtMethod(): NativePointer {
        return this.handle
    }

    asString(): string {
        //todo
        return ''
    }
}

Reflect.set(globalThis, "ArtParser", ArtParser)