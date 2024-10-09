import { logd, logz } from "../logger.js"
import { BPStatus } from "./BPStatus.js"

type _Unwind_Context_PTR = NativePointer

export class BackTrace {

    private constructor() { }

    // impl by frida
    static BackTraceByFrida = (ctx: CpuContext = BPStatus.getCurrentContext(), fuzzy: boolean = false, retText: boolean = false, slice: number = 6): string | void => {
        let tmpText: string = Thread.backtrace(ctx, fuzzy ? Backtracer.FUZZY : Backtracer.ACCURATE)
            .slice(0, slice)
            .map(DebugSymbol.fromAddress)
            .map((sym: DebugSymbol, index: number) => {
                let strRet: string = `${PD(`[${index}]`, 5)} ${sym}`
                return strRet
            })
            .join(`\n`)
        return !retText ? logd(tmpText) : tmpText
    }

    // impl by system
    static BackTraceBySystem = () => {

        /**
         * typedef enum {
            _URC_NO_REASON = 0,
            #if defined(__arm__) && !defined(__USING_SJLJ_EXCEPTIONS__) && \
                !defined(__ARM_DWARF_EH__)
            _URC_OK = 0, // used by ARM EHABI
            #endif
            _URC_FOREIGN_EXCEPTION_CAUGHT = 1,

            _URC_FATAL_PHASE2_ERROR = 2,
            _URC_FATAL_PHASE1_ERROR = 3,
            _URC_NORMAL_STOP = 4,

            _URC_END_OF_STACK = 5,
            _URC_HANDLER_FOUND = 6,
            _URC_INSTALL_CONTEXT = 7,
            _URC_CONTINUE_UNWIND = 8,
            #if defined(__arm__) && !defined(__USING_SJLJ_EXCEPTIONS__) && \
            !defined(__ARM_DWARF_EH__)
            _URC_FAILURE = 9 // used by ARM EHABI
            #endif
         */
        enum _Unwind_Reason_Code {
            _URC_NO_REASON = 0,
            _URC_FOREIGN_EXCEPTION_CAUGHT = 1,
            _URC_FATAL_PHASE2_ERROR = 2,
            _URC_FATAL_PHASE1_ERROR = 3,
            _URC_NORMAL_STOP = 4,
            _URC_END_OF_STACK = 5,
            _URC_HANDLER_FOUND = 6,
            _URC_INSTALL_CONTEXT = 7,
            _URC_CONTINUE_UNWIND = 8,
        }

        // using _Unwind_Backtrace
        const _Unwind_Backtrace = new NativeFunction(DebugSymbol.fromName("_Unwind_Backtrace")!.address, 'int', ['pointer', 'pointer'])
        // _Unwind_Word _Unwind_GetIP(struct _Unwind_Context *);
        const _Unwind_GetIP = new NativeFunction(DebugSymbol.fromName("_Unwind_GetIP")!.address, 'pointer', ['pointer'])
        // void _Unwind_SetIP(struct _Unwind_Context *, _Unwind_Word);
        const _Unwind_SetIP = new NativeFunction(DebugSymbol.fromName("_Unwind_SetIP")!.address, 'void', ['pointer', 'pointer'])
        // _Unwind_Word _Unwind_GetGR(struct _Unwind_Context *, int);
        const _Unwind_GetGR = new NativeFunction(DebugSymbol.fromName("_Unwind_GetGR")!.address, 'pointer', ['pointer', 'int'])
        // void _Unwind_SetGR(struct _Unwind_Context *, int, _Unwind_Word);
        const _Unwind_SetGR = new NativeFunction(DebugSymbol.fromName("_Unwind_SetGR")!.address, 'void', ['pointer', 'int', 'pointer'])
        // _Unwind_Word _Unwind_GetIPInfo(struct _Unwind_Context *, int *);
        const _Unwind_GetIPInfo = new NativeFunction(DebugSymbol.fromName("_Unwind_GetIPInfo")!.address, 'pointer', ['pointer', 'pointer'])
        // _Unwind_Word _Unwind_GetCFA(struct _Unwind_Context *);
        const _Unwind_GetCFA = new NativeFunction(DebugSymbol.fromName("_Unwind_GetCFA")!.address, 'pointer', ['pointer'])
        // _Unwind_Word _Unwind_GetBSP(struct _Unwind_Context *);
        const _Unwind_GetBSP = new NativeFunction(DebugSymbol.fromName("_Unwind_GetBSP")!.address, 'pointer', ['pointer'])

        // _Unwind_Ptr _Unwind_GetDataRelBase(struct _Unwind_Context *);
        const _Unwind_GetDataRelBase = new NativeFunction(DebugSymbol.fromName("_Unwind_GetDataRelBase")!.address, 'pointer', ['pointer'])
        // _Unwind_Ptr _Unwind_GetTextRelBase(struct _Unwind_Context *);
        const _Unwind_GetTextRelBase = new NativeFunction(DebugSymbol.fromName("_Unwind_GetTextRelBase")!.address, 'pointer', ['pointer'])

        logd(`DataRelBase ${_Unwind_GetDataRelBase} | TextRelBase ${_Unwind_GetTextRelBase}`)

        var count: number = 0
        _Unwind_Backtrace(new NativeCallback((ctx: _Unwind_Context_PTR, _arg: NativePointer) => {
            try {
                const ip: NativePointer = _Unwind_GetIP(ctx) // lr
                logd(`Frame ${PD(`# ${++count}`, 5)}\n\t${DebugSymbol.fromAddress(ip)} | ${Instruction.parse(ip)}`)
                // InstructionParser.printCurrentInstruction(ip, 5)
                if (Process.arch == 'arm64') {
                    // x19 - x31 (64-bit) Non-Volatile Register
                    const x19: NativePointer = _Unwind_GetGR(ctx, 19)
                    const x20: NativePointer = _Unwind_GetGR(ctx, 20)
                    const x21: NativePointer = _Unwind_GetGR(ctx, 21)
                    const x22: NativePointer = _Unwind_GetGR(ctx, 22)
                    const x23: NativePointer = _Unwind_GetGR(ctx, 23)
                    const x24: NativePointer = _Unwind_GetGR(ctx, 24)
                    const x25: NativePointer = _Unwind_GetGR(ctx, 25)
                    const x26: NativePointer = _Unwind_GetGR(ctx, 26)
                    const x27: NativePointer = _Unwind_GetGR(ctx, 27)
                    const x28: NativePointer = _Unwind_GetGR(ctx, 28)
                    const fp: NativePointer = _Unwind_GetGR(ctx, 29)
                    const lr: NativePointer = _Unwind_GetGR(ctx, 30)
                    // const sp: NativePointer = _Unwind_GetGR(ctx, 31) // misapplication  
                    const cfa: NativePointer = _Unwind_GetCFA(ctx)
                    // const bsp: NativePointer = _Unwind_GetBSP(ctx)
                    logz(`\t${PD(`x19: ${x19}`)} ${PD(`x20: ${x20}`)} ${PD(`x21: ${x21}`)} ${PD(`x22: ${x22}`)} ${PD(`x23: ${x23}`)} ${PD(`x24: ${x24}`)}\n\t${PD(`x25: ${x25}`)} ${PD(`x26: ${x26}`)} ${PD(`x27: ${x27}`)} ${PD(`x28: ${x28}`)}`)
                    logz(`\t${PD(`fp: ${fp}`)} ${PD(`lr: ${lr}`)} ${PD(`sp: ${cfa}`)}`)
                }
            } catch {/* end of stack */ }
            newLine()
            return _Unwind_Reason_Code._URC_NO_REASON
        }, 'int', ['pointer', 'pointer']), NULL)

    }

}

// backtrace
Reflect.set(globalThis, "bt", BackTrace.BackTraceByFrida)
Reflect.set(globalThis, "btf", BackTrace.BackTraceByFrida)
Reflect.set(globalThis, "bts", BackTrace.BackTraceBySystem)