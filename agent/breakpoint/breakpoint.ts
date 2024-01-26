import { InstructionParser } from '../instructions/instruction'
import { BPStatus, BP_TYPE } from './BPStatus'
import { logd, loge, logw, logz } from '../logger'
import { padding as PD } from '../utils'
import { Debugger } from '../debugger'
import { Signal } from '../signal'

const DebugType: boolean = false

type _Unwind_Context_PTR = NativePointer

export class BreakPoint {

    private static InnerAttach(localPtr: NativePointer) {
        Interceptor.attach(localPtr, {
            onEnter(this: InvocationContext, _args: InvocationArguments) {
                Stalker.follow(Process.getCurrentThreadId(), {
                    events: {
                        call: false,
                        ret: false,
                        exec: true,
                        block: false,
                        compile: false,
                    },
                    transform: function (iterator: StalkerArm64Iterator) {
                        let instruction = iterator.next()
                        do {
                            if (Debugger.getModule(Process.getCurrentThreadId()).has(instruction!.address)) {
                                if (DebugType) logz(`${DebugSymbol.fromAddress(instruction?.address as NativePointer)} ${instruction}`)
                                iterator.putCallout(BreakPoint.CalloutInner)
                            }
                            iterator.keep()
                        } while ((instruction = iterator.next()) !== null)

                    }
                })
            },
            // only function bp need unfollow here
            onLeave: BPStatus.getBpType(localPtr) != BP_TYPE.Function ? undefined : function (this: InvocationContext, _retval: InvocationReturnValue) {
                Stalker.unfollow(Process.getCurrentThreadId())
            }
        })
    }

    static continueThread = (thread_id: number = BPStatus.currentThreadId) => {
        Stalker.unfollow(thread_id)
        Signal.sem_post_thread_id(thread_id)
        BPStatus.breakpoints.delete(BPStatus.currentPC.get(thread_id)!)
        BPStatus.currentThreadId = 0
        BPStatus.setPaused(thread_id, false)
    }

    static attchByFunction = (mPtr: NativePointer | number | string = NULL, mdName = null) => {
        let localPtr: NativePointer = NULL
        if (mPtr instanceof NativePointer) localPtr = mPtr
        else {
            if (typeof mPtr === 'string') {
                localPtr = typeof mPtr === 'string' ? (mPtr.startsWith("0x") ? ptr(mPtr) : (function () {
                    const md = Module.findExportByName(mdName, mPtr)
                    if (md == null) throw new Error("md is null")
                    return md
                })()) : mPtr
            }
            else localPtr = BreakPoint.checkArgs(mPtr)
        }

        BPStatus.addBp(localPtr, BP_TYPE.Function)
        BreakPoint.InnerAttach(localPtr)
    }

    private static checkArgs = (mPtr: NativePointer | number = NULL): NativePointer => {
        let localPtr: NativePointer | null = NULL
        if (mPtr instanceof NativePointer) return localPtr
        if (typeof mPtr === 'number') {
            localPtr = ptr(mPtr)
        } else {
            throw new Error("mPtr must be number")
        }
        if (localPtr == null) throw new Error("mPtr is null")
        return localPtr
    }

    // inlinehook unfollow by pc == lr
    static attachByLR = (mPtr: NativePointer | number = NULL) => {
        let localPtr: NativePointer | null = BreakPoint.checkArgs(mPtr)
        BPStatus.addBp(localPtr, BP_TYPE.LR)
        BreakPoint.InnerAttach(localPtr)
        throw new Error("not implement")
    }

    // inlinehook unfollow by stack < 0
    static attachBySP = (mPtr: NativePointer | number = NULL) => {
        let localPtr: NativePointer | null = BreakPoint.checkArgs(mPtr)
        BPStatus.addBp(localPtr, BP_TYPE.SP)
        BreakPoint.InnerAttach(localPtr)
        throw new Error("not implement")
    }

    // inlinehook unfollow by RANGE
    static attachByRange = (mPtr: NativePointer | number = NULL) => {
        let localPtr: NativePointer | null = BreakPoint.checkArgs(mPtr)
        BPStatus.addBp(localPtr, BP_TYPE.RANGE)
        BreakPoint.InnerAttach(localPtr)
        throw new Error("not implement")
    }

    private static CalloutInner = (context: CpuContext) => {
        // clear()
        const currentPC: NativePointer = context.pc

        // todo moduleFilters implement

        const thread_id: number = Process.getCurrentThreadId()
        BPStatus.addThreadContext(thread_id, context.pc, context)
        BPStatus.currentPC.set(thread_id, currentPC)
        // check hit
        BPStatus.setPaused(thread_id, true)
        if (BPStatus.breakpoints.has(currentPC.sub(4 * 4))) {
            logw(`Hit breakpoint at ${DebugSymbol.fromAddress(currentPC)} | ${Instruction.parse(currentPC)}`)
            Signal.sem_post_thread_id(thread_id)
        }
        if (Process.arch == "arm64") {
            BreakPoint.callOutInnerArm64(context as Arm64CpuContext)
        } else if (Process.arch == "arm") {
            BreakPoint.callOutInnerArm(context as ArmCpuContext)
        }
    }

    public static printRegs = (context: CpuContext) => {
        if (Process.arch == "arm64") {
            const tc = context as Arm64CpuContext
            logw(`${PD(`X0: ${tc.x0}`)} ${PD(`X1: ${tc.x1}`)} ${PD(`X2: ${tc.x2}`)} ${PD(`X3: ${tc.x3}`)} ${PD(`X4: ${tc.x4}`)} ${PD(`X5: ${tc.x5}`)} ${PD(`X6: ${tc.x6}`)} ${PD(`X7: ${tc.x7}`)}`)
            logw(`${PD(`x8(XR): ${tc.x8}`)} ${PD(`X9: ${tc.x9}`)} ${PD(`X10: ${tc.x10}`)} ${PD(`X11: ${tc.x11}`)} ${PD(`X12: ${tc.x12}`)} ${PD(`X13: ${tc.x13}`)} ${PD(`X14: ${tc.x14}`)} ${PD(`X15: ${tc.x15}`)}`)
            logw(`${PD(`X19: ${tc.x19}`)} ${PD(`X20: ${tc.x20}`)} ${PD(`X21: ${tc.x21}`)} ${PD(`X22: ${tc.x22}`)} ${PD(`X23: ${tc.x23}`)}`)
            logw(`${PD(`X24: ${tc.x24}`)} ${PD(`X25: ${tc.x25}`)} ${PD(`X26: ${tc.x26}`)} ${PD(`X27: ${tc.x27}`)} ${PD(`X28: ${tc.x28}`)}`)
            logw(`${PD(`FP(X29): ${tc.fp}`)}  ${PD(`LR(X30): ${tc.lr}`)}  ${PD(`SP(X31): ${tc.sp}`)}  |  ${PD(`PC: ${tc.pc}`)}`)
        } else if (Process.arch == "arm") {
            const tc = context as ArmCpuContext
            logw(`R0: ${PD(tc.r0)} R1: ${PD(tc.r1)} R2: ${PD(tc.r2)} R3: ${PD(tc.r3)}`)
            logw(`R4: ${PD(tc.r4)} R5: ${PD(tc.r5)} R6: ${PD(tc.r6)} R7: ${PD(tc.r7)}`)
            logw(`R8: ${PD(tc.r8)} R9: ${PD(tc.r9)} R10: ${PD(tc.r10)} R11: ${PD(tc.r11)}`)
            logw(`IP(R12): ${PD(tc.r12)} SP(R13): ${PD(tc.sp)} LR(R14): ${PD(tc.lr)} PC(R15): ${PD(tc.pc)}`)
        }
    }

    private static callOutInnerArm64 = (context: Arm64CpuContext) => {
        const tc = context as Arm64CpuContext
        const currentThread: number = Process.getCurrentThreadId()
        logd(`\n[ ${getThreadName(currentThread)} @ ${currentThread} }\n`)
        BreakPoint.printRegs(context)
        InstructionParser.printCurrentInstruction(tc.pc)
        BPStatus.getStepActions(currentThread).forEach((action) => action(tc))
        // BreakPoint.BackTraceBySystem() // recommend using in StepAction not there
        Signal.sem_wait_threadid(currentThread)
    }

    private static callOutInnerArm = (context: ArmCpuContext) => {
        throw new Error("not implement")
    }

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

Reflect.set(globalThis, "BreakPoint", BreakPoint)

Reflect.set(globalThis, "bp", BreakPoint)
Reflect.set(globalThis, "b", BreakPoint.attchByFunction) // breakpoint
Reflect.set(globalThis, "c", BreakPoint.continueThread) // continue
// backtrace
Reflect.set(globalThis, "bt", BreakPoint.BackTraceByFrida)
Reflect.set(globalThis, "btf", BreakPoint.BackTraceByFrida)
Reflect.set(globalThis, "bts", BreakPoint.BackTraceBySystem)