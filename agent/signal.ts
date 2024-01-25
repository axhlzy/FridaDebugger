import { BPStatus } from "./breakpoint/BPStatus"
import { logd } from "./logger"

export namespace Signal {

    var semlock_global = Memory.alloc(0x10)
    var semlock_threadid = new Map<number, NativePointer>()

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

    export const sem_post_threadid = (thread_id: number) => {
        if (semlock_threadid.has(thread_id)) {
            func_sem_post(semlock_threadid.get(thread_id)!)
            func_sem_destroy(semlock_threadid.get(thread_id)!)
        }
    }

    export const sem_wait_threadid = (thread_id: number) => {
        if (!semlock_threadid.has(thread_id)) {
            var mem = Memory.alloc(0x10)
            semlock_threadid.set(thread_id, mem)
            func_sem_init(semlock_threadid.get(thread_id)!, 0, 0)
        }
        func_sem_wait(semlock_threadid.get(thread_id)!)
    }

    export const continue_instruction = (thread_id: number = BPStatus.currentThreadId) => {
        sem_post_threadid(thread_id)
        newLine()
    }

}

Reflect.set(globalThis, "Signal", Signal)
Reflect.set(globalThis, "step", Signal.continue_instruction)
Reflect.set(globalThis, "si", Signal.continue_instruction)