import { logd, logw } from "../logger.js"

export class BPStatus {

    // is stuck at breakpoint
    static isPaused: Map<number, boolean> = new Map<number, boolean>()

    // current using thread id
    static currentThreadId: number = 0

    // record current pc
    static currentPC: Map<number, NativePointer> = new Map<number, NativePointer>()

    // record breakpoints
    static breakpoints: Set<NativePointer> = new Set<NativePointer>()

    // map bp type
    static bpType: Map<NativePointer, BP_TYPE> = new Map<NativePointer, BP_TYPE>()

    // map action step function to thread
    static actionStep: Map<number, ((ctx: CpuContext) => void)[]> = new Map<number, []>()

    // map thread to contextMap
    static threadContextMap: Map<number, Map<NativePointer, CpuContext>> = new Map<number, Map<NativePointer, CpuContext>>()

    static addBp = (bp: NativePointer, type: BP_TYPE) => {
        BPStatus.breakpoints.add(bp)
        BPStatus.bpType.set(bp, type)
    }

    static removeBp = (bp: NativePointer) => {
        BPStatus.breakpoints.delete(bp)
        BPStatus.bpType.delete(bp)
    }

    static getBpType = (bp: NativePointer): BP_TYPE => {
        const ret = BPStatus.bpType.get(bp)!
        if (ret == null) throw new Error("bp type is null")
        return ret
    }

    static setPaused = (thread_id: number, paused: boolean) => {
        BPStatus.isPaused.set(thread_id, paused)
        BPStatus.currentThreadId = thread_id
    }

    static hasPausedThread = (): boolean => {
        for (const [_key, value] of BPStatus.isPaused) {
            if (value) return true
        }
        return false
    }

    static addStepAction = (action: (ctx: CpuContext) => void, thread_id: number = BPStatus.currentThreadId) => {
        let actions: ((ctx: CpuContext) => void)[] | undefined = BPStatus.actionStep.get(thread_id)
        if (actions == undefined) {
            actions = new Array<(ctx: CpuContext) => void>()
            BPStatus.actionStep.set(thread_id, actions)
        }
        actions.push(action)
    }

    static listStepAction = (thread_id: number = BPStatus.currentThreadId): void => {
        let index: number = -1
        logw(`selectd thread_id: ${thread_id}`)
        BPStatus.actionStep.forEach((value, _key) => {
            logd(`[${++index}]\n\taction: ${value}`)
        })
    }

    static getStepActions = (thread_id: number = BPStatus.currentThreadId): Array<(ctx: CpuContext) => void> => {
        const actions = BPStatus.actionStep.get(thread_id)
        if (actions == undefined) return []
        return actions
    }

    static removeAllStepAction = (thread_id: number = BPStatus.currentThreadId) => {
        const actions = BPStatus.actionStep.get(thread_id)
        if (actions == undefined) throw new Error("actions is null")
        actions.splice(0, actions.length)
    }

    static removeIndexStepAction = (index: number, thread_id: number = BPStatus.currentThreadId) => {
        const actions = BPStatus.actionStep.get(thread_id)
        if (actions == undefined) throw new Error("actions is null")
        actions.splice(index, 1)
    }

    static addThreadContext = (thread_id: number, address: NativePointer, context: CpuContext) => {
        let contextMap: Map<NativePointer, CpuContext> | undefined = BPStatus.threadContextMap.get(thread_id)
        if (contextMap == undefined) {
            contextMap = new Map<NativePointer, CpuContext>()
            BPStatus.threadContextMap.set(thread_id, contextMap)
        }
        contextMap.set(address, context)
    }

    static getCurrentContext = (thread_id: number = BPStatus.currentThreadId): CpuContext => {
        const contextMap: Map<NativePointer, CpuContext> | undefined = BPStatus.threadContextMap.get(thread_id)
        if (contextMap == undefined) throw new Error("contextMap is null")
        const address: NativePointer | undefined = BPStatus.currentPC.get(BPStatus.currentThreadId)
        if (address == undefined) throw new Error("address is null")
        let context: CpuContext | undefined = undefined
        for (const [key, value] of contextMap) {
            if (key.equals(address)) {
                context = value
                break
            }
        }
        // contextMap.forEach((value, key) => logd(`key = ${key} value = ${value}`))
        if (context == undefined) throw new Error("context is null")
        return context
    }

    static toString() {
        let disp: string = '\n'
        disp += `CurrentThreadId : ${BPStatus.currentThreadId}\n`
        disp += `CurrentPC : ${JSON.stringify(Array.from(BPStatus.currentPC))}\n`
        disp += `Breakpoints size : ${BPStatus.breakpoints.size}\n`
        disp += `\t${JSON.stringify(Array.from(BPStatus.breakpoints.entries()))}\n`
        disp += `threadContextMap size : ${BPStatus.threadContextMap.size}\n`
        disp += `\t${JSON.stringify(Array.from(BPStatus.threadContextMap.entries()))}\n`
        return disp
    }

    private static saveBuffer(){
        // mmap maps a section of memory to hold data(BPStatus)
        // todo ...
    }

    toBuffer(): Buffer {
        const data = JSON.stringify({
            isPaused: BPStatus.isPaused,
            currentThreadId: BPStatus.currentThreadId,
            currentPC: Array.from(BPStatus.currentPC.entries())
            // ...
        })
        return Buffer.from(data)
    }

    static fromBuffer(buffer: Buffer): void {
        const json = buffer.toString()
        const data = JSON.parse(json)
        BPStatus.isPaused = data.isPaused
        BPStatus.currentThreadId = data.currentThreadId
        BPStatus.currentPC = new Map(data.currentPC)
        // ...
    }

}

export enum BP_TYPE {
    LR,
    SP,
    RANGE,
    Function,
}

Reflect.set(globalThis, "BPStatus", BPStatus)
Reflect.set(globalThis, "status", ()=>{logd(BPStatus.toString())})
Reflect.set(globalThis, "bps", BPStatus)