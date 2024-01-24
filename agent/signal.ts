export namespace Signal {

    var semlock = Memory.alloc(0x10)

    const func_sem_init = new NativeFunction(Module.findExportByName("libc.so", "sem_init")!, "int", ["pointer", "int", "uint"])
    const func_sem_destroy = new NativeFunction(Module.findExportByName("libc.so", "sem_destroy")!, "int", ["pointer"])
    const func_sem_wait = new NativeFunction(Module.findExportByName("libc.so", "sem_wait")!, "int", ["pointer"])
    const func_sem_post = new NativeFunction(Module.findExportByName("libc.so", "sem_post")!, "int", ["pointer"])

    export const sem_post = () => {
        func_sem_post(semlock)
        func_sem_destroy(semlock)
    }

    export const sem_wait = () => {
        func_sem_init(semlock, 0, 0)
        func_sem_wait(semlock)
    }

}

declare global {
    var Signal: any
}

globalThis.Signal = Signal