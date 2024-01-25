globalThis.clear = () => console.log('\x1Bc')

globalThis.newLine = (lines: number = 1) => {
    for (let i = 0; i < lines; i++) console.log('\n')
}

var nameCountMap: Map<string, number> = new Map()
export const filterDuplicateOBJ = (objstr: string, maxCount: number = 10) => {
    let count: number | undefined = nameCountMap.get(objstr.toString())
    if (count == undefined) count = 0
    if (count < maxCount) {
        nameCountMap.set(objstr.toString(), count + 1)
        return true
    }
    return false
}

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

export const padding = (str: string | NativePointer, len: number = 18, pad: string = ' ', end: boolean = true) => {
    if (str instanceof NativePointer) str = str.toString()
    if (str.length >= len) return str
    if (end) return str.padEnd(len, pad)
    else return str.padStart(len, pad)
}

declare global {
    var clear: () => void
    var newLine: (lines?: number) => void
    var filterDuplicateOBJ: (objstr: string, maxCount?: number) => boolean
    var getThreadName: (tid: number) => string
}

globalThis.clear = clear
globalThis.newLine = newLine
globalThis.filterDuplicateOBJ = filterDuplicateOBJ
globalThis.getThreadName = getThreadName