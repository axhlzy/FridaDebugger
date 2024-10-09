import { GPRState } from "./arm64-v8a/share/qbdiAARCH64/frida-qbdi"

export type GContext = Arm64CpuContext | ArmCpuContext | GPRState

export class ExtraInfo {

    private handle: NativePointer

    private index_ptr: NativePointer = NULL            // int64_t 记录 index
    private startTime_ptr: NativePointer = NULL        // int64_t 开始时间
    private runInstCount_ptr: NativePointer = NULL     // int64_t 记录 run inst count
    private lastAddress_ptr: NativePointer = NULL      // int64_t 记录上一次的地址

    private firstTime: number = 0

    constructor() {
        this.handle = Memory.alloc(Process.pointerSize * 4)
        this.index_ptr = this.handle
        this.startTime_ptr = this.index_ptr.add(Process.pointerSize)
        this.runInstCount_ptr = this.startTime_ptr.add(Process.pointerSize)
        this.lastAddress_ptr = this.runInstCount_ptr.add(Process.pointerSize)
        this.reSet()
    }

    public reSet = () => {
        this.index_ptr.writePointer(NULL)
        this.startTime_ptr.writePointer(NULL)
        this.runInstCount_ptr.writePointer(NULL)
        this.lastAddress_ptr.writePointer(NULL)
    }

    get index(): number {
        return this.index_ptr.readPointer().toUInt32()
    }

    set index(value: number) {
        this.index_ptr.writePointer(ptr(value))
    }

    get startTime(): number {
        return this.startTime_ptr.readU64().toNumber()
    }

    set startTime(value: number) {
        if (this.firstTime == 0) this.firstTime = value
        this.startTime_ptr.writeU64(value)
    }

    setStartTimeNow = () => { this.startTime = Date.now() }

    get runInstCount(): number {
        return this.runInstCount_ptr.readPointer().toUInt32()
    }

    set runInstCount(value: number) {
        this.runInstCount_ptr.writePointer(ptr(value))
    }

    get lastAddress(): NativePointer {
        return this.lastAddress_ptr.readPointer()
    }

    set lastAddress(value: NativePointer) {
        this.lastAddress_ptr.writePointer(value)
    }

}

export class ContextItem {

    inst: AnalysisType
    spOffset: NativePointer
    context: GContext

    constructor(inst: AnalysisType, spOffset: NativePointer, context: GContext) {
        this.inst = inst
        this.spOffset = spOffset
        this.context = context
    }

}

/**
 * {
        "address": "515861919452",
        "affectControlFlow": false,
        "condition": 0,
        "cpuMode": 0,
        "disassembly": "\tstr\tx19, [sp, #-32]!",
        "flagsAccess": 0,
        "instSize": 4,
        "isBranch": false,
        "isCall": false,
        "isCompare": false,
        "isMoveImm": false,
        "isPredicable": false,
        "isReturn": false,
        "loadSize": 0,
        "mayLoad": false,
        "mayStore": true,
        "mnemonic": "STRXpre",
        "module": "",
        "operands": [],
        "storeSize": 8,
        "symbol": "",
        "symbolOffset": 0
    }
 */
export class AnalysisType {

    address!: number
    affectControlFlow!: boolean
    condition!: number
    cpuMode!: number
    disassembly!: string
    flagsAccess!: number
    instSize!: number
    isBranch!: boolean
    isCall!: boolean
    isCompare!: boolean
    isMoveImm!: boolean
    isPredicable!: boolean
    isReturn!: boolean
    loadSize!: number
    mayLoad!: boolean
    mayStore!: boolean
    mnemonic!: string
    module!: string
    operands!: Array<any>
    storeSize!: number
    symbol!: string
    symbolOffset!: number

}