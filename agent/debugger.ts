export namespace Debugger {

    const moduleFilters = new Set<string>(["libil2cpp.so"])

    export const getModule = (): ModuleMap => {
        return new ModuleMap((md: Module) => moduleFilters.has(md.name))
    }

    export const addModuleName = (name: string) => {
        moduleFilters.add(name)
    }

}

declare global {
    var Debugger: any
}

globalThis.Debugger = Debugger