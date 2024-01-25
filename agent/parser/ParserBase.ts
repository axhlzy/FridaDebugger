// import 'frida-il2cpp-bridge'

export abstract class ParserBase implements ParserAction {

    protected handle: NativePointer = NULL

    protected constructor() { }

    from(handle: NativePointer) {
        this.handle = handle
    }

    toString(): string {
        return this.constructor.name
    }

}

interface ParserAction {

    from(handle: NativePointer): void

    toString(): string

}