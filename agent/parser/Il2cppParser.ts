import { ParserBase } from "./ParserBase.js"

export class Il2cppParser extends ParserBase {

    // asObject(): Il2Cpp.Object {
    //     return new Il2Cpp.Object(this.handle)
    // }

    // asMethod(): Il2Cpp.Method {
    //     return new Il2Cpp.Method(this.handle)
    // }

    // asClass(): Il2Cpp.Class {
    //     return new Il2Cpp.Class(this.handle)
    // }

    // asField(): Il2Cpp.Field {
    //     return new Il2Cpp.Field(this.handle)
    // }

    // asString(): Il2Cpp.String {
    //     return new Il2Cpp.String(this.handle)
    // }

    // asArray<T>(): Il2Cpp.Array {
    //     return new Il2Cpp.Array(this.handle)
    // }

    // // -------

    // asGameObject(): GameObject {
    //     return new GameObject(this.handle)
    // }

    // asTransform(): Transform {
    //     return new Transform(this.handle)
    // }

}

// export class GameObject extends Il2Cpp.Object {

// }

// export class Transform extends Il2Cpp.Object {

// }

Reflect.set(globalThis, "Il2cppParser", Il2cppParser)