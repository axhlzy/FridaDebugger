import { BPStatus } from "./breakpoint/BPStatus.js"

export namespace Signal {

    var semlock_global = Memory.alloc(0x10)
    var semlock_thread_ids = new Map<number, NativePointer>()

    const func_sem_init = new NativeFunction(Module.findExportByName("libc.so", "sem_init")!, "int", ["pointer", "int", "uint"])
    const func_sem_destroy = new NativeFunction(Module.findExportByName("libc.so", "sem_destroy")!, "int", ["pointer"])
    const func_sem_wait = new NativeFunction(Module.findExportByName("libc.so", "sem_wait")!, "int", ["pointer"])
    const func_sem_post = new NativeFunction(Module.findExportByName("libc.so", "sem_post")!, "int", ["pointer"])

    export const sem_post = () => {
        func_sem_post(semlock_global)
        func_sem_destroy(semlock_global)
    }

    export const sem_wait = () => {
        func_sem_init(semlock_global, 0, 0)
        func_sem_wait(semlock_global)
    }

    export const sem_post_thread_id = (thread_id: number) => {
        if (semlock_thread_ids.has(thread_id)) {
            func_sem_post(semlock_thread_ids.get(thread_id)!)
            func_sem_destroy(semlock_thread_ids.get(thread_id)!)
        }
    }

    export const sem_wait_threadid = (thread_id: number) => {
        if (!semlock_thread_ids.has(thread_id)) {
            var mem = Memory.alloc(0x10)
            semlock_thread_ids.set(thread_id, mem)
            func_sem_init(semlock_thread_ids.get(thread_id)!, 0, 0)
        }
        func_sem_wait(semlock_thread_ids.get(thread_id)!)
    }

    export const continue_instruction = (thread_id: number = BPStatus.currentThreadId) => {
        sem_post_thread_id(thread_id)
        newLine()
    }

}

Reflect.set(globalThis, "Signal", Signal)
Reflect.set(globalThis, "step", Signal.continue_instruction)
Reflect.set(globalThis, "si", Signal.continue_instruction)

// using in local code
export class Semaphore {
    
    private sem: NativePointer
    private sem_init: NativeFunction<number, [NativePointerValue, number, number]>
    private sem_wait: NativeFunction<number, [NativePointerValue]>
    private sem_post: NativeFunction<number, [NativePointerValue]>
    private sem_destroy: NativeFunction<number, [NativePointerValue]>

    constructor(initialValue = 0) {
        this.sem = Memory.alloc(0x8);
        this.sem_init = new NativeFunction(Module.findExportByName("libc.so", "sem_init")!, 'int', ['pointer', 'int', 'uint'])
        this.sem_wait = new NativeFunction(Module.findExportByName("libc.so", "sem_wait")!, 'int', ['pointer'])
        this.sem_post = new NativeFunction(Module.findExportByName("libc.so", "sem_post")!, 'int', ['pointer'])
        this.sem_destroy = new NativeFunction(Module.findExportByName("libc.so", "sem_destroy")!, 'int', ['pointer'])
        this.sem_init(this.sem, 0, initialValue)
    }

    wait() {
        this.sem_wait(this.sem)
    }

    post() {
        this.sem_post(this.sem)
    }

    destroy() {
        this.sem_destroy(this.sem)
    }
}