import { logd, logz } from "./logger.js"
import { Semaphore } from "./signal.js"

globalThis.clear = () => console.log('\x1Bc')

globalThis.newLine = (lines: number = 1) => {
    for (let i = 0; i < lines; i++) console.log('\n')
}

globalThis.d = () => { Interceptor.detachAll() }

export function getThreadName(tid: number) {
    let threadName: string = "unknown"
    try {
        var file = new File("/proc/self/task/" + tid + "/comm", "r")
        threadName = file.readLine().toString().trimEnd()
        file.close()
    } catch (e) { throw e }

    // var threadNamePtr: NativePointer = Memory.alloc(0x40)
    // var tid_p: NativePointer = Memory.alloc(p_size).writePointer(ptr(tid))
    // var pthread_getname_np = new NativeFunction(Module.findExportByName("libc.so", 'pthread_getname_np')!, 'int', ['pointer', 'pointer', 'int'])
    // pthread_getname_np(ptr(tid), threadNamePtr, 0x40)
    // threadName = threadNamePtr.readCString()!

    return threadName
}

export function demangleName(expName: string) {
    let demangleAddress: NativePointer | null = Module.findExportByName("libc++.so", '__cxa_demangle')
    if (demangleAddress == null) demangleAddress = Module.findExportByName("libunwindstack.so", '__cxa_demangle')
    if (demangleAddress == null) demangleAddress = Module.findExportByName("libbacktrace.so", '__cxa_demangle')
    if (demangleAddress == null) demangleAddress = Module.findExportByName(null, '__cxa_demangle')
    if (demangleAddress == null) throw Error("can not find export function -> __cxa_demangle")
    let demangle: Function = new NativeFunction(demangleAddress, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer'])
    let mangledName: NativePointer = Memory.allocUtf8String(expName)
    let outputBuffer: NativePointer = NULL
    let length: NativePointer = NULL
    let status: NativePointer = Memory.alloc(Process.pageSize)
    let result: NativePointer = demangle(mangledName, outputBuffer, length, status) as NativePointer
    if (status.readInt() === 0) {
        let resultStr: string | null = result.readUtf8String()
        return (resultStr == null || resultStr == expName) ? "" : resultStr
    } else return ""
}

export const padding = (str: string | NativePointer, len: number = 25, pad: string = ' ', end: boolean = true) => {
    if (str instanceof NativePointer) str = str.toString()
    if (str.length >= len) return str
    if (end) return str.padEnd(len, pad)
    else return str.padStart(len, pad)
}

export const packApiResove = (patter: string = "exports:*!*Unwind*") => {
    let index: number = 0
    new ApiResolver("module").enumerateMatches(patter).forEach((exp) => {
        logd(`${padding(`[${++index}]`, 5)}${exp.name} ${exp.address}`)
        logz(`\t${demangleName(exp.name.split("!")[1])}`)
    })
}

export const getMainThreadId = () => {
    let retId = -1
    const semaphore = new Semaphore()
    Java.scheduleOnMainThread(() => {
        retId = Process.getCurrentThreadId()
        semaphore.post()
    })
    semaphore.wait()
    return retId
}

declare global {
    var d: () => void
    var clear: () => void
    var getMainThreadId: () => number
    var newLine: (lines?: number) => void
    var getThreadName: (tid: number) => string
    var demangleName: (expName: string) => string
    var filterDuplicateOBJ: (objstr: string, maxCount?: number) => boolean
    var PD: (str: string | NativePointer, len?: number, pad?: string, end?: boolean) => string
    var padding: (str: string | NativePointer, len?: number, pad?: string, end?: boolean) => string
}

globalThis.d = d
globalThis.PD = padding
globalThis.clear = clear
globalThis.padding = padding
globalThis.newLine = newLine
globalThis.getThreadName = getThreadName
globalThis.getMainThreadId = getMainThreadId
globalThis.demangleName = demangleName