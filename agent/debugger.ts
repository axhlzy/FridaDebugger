import { BPStatus } from "./breakpoint/BPStatus.js"
import { loge } from "./logger.js"

export class Debugger {

    static moduleFilters = new Set<string>(["libil2cpp.so"])

    static CacheByThreadId = new Map<number, ModuleMap>()

    static getModule = (thread_id: number = BPStatus.currentThreadId): ModuleMap => {
        if (Debugger.CacheByThreadId.has(thread_id)) {
            return Debugger.CacheByThreadId.get(thread_id)!
        } else {
            const ret = new ModuleMap((md: Module) => Debugger.moduleFilters.has(md.name))
            Debugger.CacheByThreadId.set(thread_id, ret)
            return ret
        }
    }

    static getModuleMapByAddress = (mPtr: NativePointer): ModuleMap => {
        const dbgInfo = DebugSymbol.fromAddress(mPtr)
        if (dbgInfo == null || dbgInfo.moduleName == null) {
            loge(`dbgInfo is null`)
            return this.getModule()
        }
        Debugger.addModuleName(dbgInfo.moduleName)
        return Debugger.getModule()
    }

    static addModuleName = (name: string) => {
        Debugger.moduleFilters.add(name)
    }

}

Reflect.set(globalThis, "Debugger", Debugger)