import { InstructionParser } from '../instructions/instruction.js'
import { logd, logh, logw, logz } from '../logger.js'
import { BPStatus, BP_TYPE } from './BPStatus.js'
import { padding as PD } from '../utils.js'
import { Debugger } from '../debugger.js'
import { Signal } from '../signal.js'

const DebugType: boolean = false

export class BreakPoint {

    private static InnerAttach(localPtr: NativePointer, threadid?: number) {
        if (DebugType) logw(`InnerAttach ${localPtr}`)
        Interceptor.attach(localPtr, {
            onEnter(this: InvocationContext, _args: InvocationArguments) {
                threadid = threadid == undefined ? Process.getCurrentThreadId() : threadid
                logw(`Enter ${localPtr} | threadid ${threadid} | MAIN ? ${Boolean(threadid === getMainThreadId())}`)
                Stalker.follow(threadid, {
                    events: {
                        call: false,
                        ret: false,
                        exec: true,
                        block: false,
                        compile: false,
                    },
                    transform: function (iterator: StalkerArm64Iterator | StalkerArmIterator) {
                        let instruction = iterator.next()!
                        if (DebugType) logw(instruction.toString())
                        do {
                            if (Debugger.getModule(threadid).has(instruction!.address)) {
                                if (DebugType) logz(`${DebugSymbol.fromAddress(instruction?.address as NativePointer)} ${instruction}`)
                                iterator.putCallout(BreakPoint.CalloutInner)
                            }
                            iterator.keep()
                        } while ((instruction = iterator.next()!) !== null)

                    }
                })
            },
            // only function bp need unfollow here
            onLeave: BPStatus.getBpType(localPtr) != BP_TYPE.Function ? undefined : function (this: InvocationContext, _retval: InvocationReturnValue) {
                Stalker.unfollow(threadid)
            }
        })
    }

    static continueThread = (thread_id: number = BPStatus.currentThreadId) => {
        if (!BPStatus.hasPausedThread()) throw new Error("no paused thread")
        Stalker.unfollow(thread_id)
        Signal.sem_post_thread_id(thread_id)
        BPStatus.breakpoints.delete(BPStatus.currentPC.get(thread_id)!)
        BPStatus.currentThreadId = 0
        BPStatus.setPaused(thread_id, false)
    }

    static attchByFunction = (mPtr: NativePointer | number | string = NULL, mdName = null, threadid?: number) => {
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

        try {
            BPStatus.addBp(localPtr, BP_TYPE.Function)
            BreakPoint.InnerAttach(localPtr, threadid)
        } catch (error) {
            // if err, don't add it to BPStatus
        }
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
    static attachByLR = (mPtr: NativePointer | number = NULL, threadid?: number) => {
        let localPtr: NativePointer | null = BreakPoint.checkArgs(mPtr)
        BPStatus.addBp(localPtr, BP_TYPE.LR)
        BreakPoint.InnerAttach(localPtr, threadid)
        throw new Error("not implement")
    }

    // inlinehook unfollow by stack < 0
    static attachBySP = (mPtr: NativePointer | number = NULL, threadid?: number) => {
        let localPtr: NativePointer | null = BreakPoint.checkArgs(mPtr)
        BPStatus.addBp(localPtr, BP_TYPE.SP)
        BreakPoint.InnerAttach(localPtr, threadid)
        throw new Error("not implement")
    }

    // inlinehook unfollow by RANGE
    static attachByRange = (mPtr: NativePointer | number = NULL, threadid?: number) => {
        let localPtr: NativePointer | null = BreakPoint.checkArgs(mPtr)
        BPStatus.addBp(localPtr, BP_TYPE.RANGE)
        BreakPoint.InnerAttach(localPtr, threadid)
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
            logw(`${PD(`X0:  ${tc.x0}`)} ${PD(`X1:  ${tc.x1}`)} ${PD(`X2:  ${tc.x2}`)} ${PD(`X3:  ${tc.x3}`)} ${PD(`X4:  ${tc.x4}`)} ${PD(`X5:  ${tc.x5}`)} ${PD(`X6:  ${tc.x6}`)}`)
            logw(`${PD(`X7:  ${tc.x7}`)} ${PD(`x8:  ${tc.x8}`)} ${PD(`X9:  ${tc.x9}`)} ${PD(`X10: ${tc.x10}`)} ${PD(`X11: ${tc.x11}`)} ${PD(`X12: ${tc.x12}`)} ${PD(`X13: ${tc.x13}`)}`)
            logw(`${PD(`X14: ${tc.x14}`)} ${PD(`X15: ${tc.x15}`)} ${PD(`X19: ${tc.x19}`)} ${PD(`X20: ${tc.x20}`)} ${PD(`X21: ${tc.x21}`)} ${PD(`X22: ${tc.x22}`)} ${PD(`X23: ${tc.x23}`)}`)
            logw(`${PD(`X24: ${tc.x24}`)} ${PD(`X25: ${tc.x25}`)} ${PD(`X26: ${tc.x26}`)} ${PD(`X27: ${tc.x27}`)} ${PD(`X28: ${tc.x28}`)}`)
            logh(`\n${PD(`FP(X29): ${tc.fp}`)}  ${PD(`LR(X30): ${tc.lr}`)}  ${PD(`SP(X31): ${tc.sp}`)} ${PD(`PC: ${tc.pc}`)}`)
        } else if (Process.arch == "arm") {
            const tc = context as ArmCpuContext
            logw(`R0: ${PD(tc.r0)} R1: ${PD(tc.r1)} R2: ${PD(tc.r2)} R3: ${PD(tc.r3)}`)
            logw(`R4: ${PD(tc.r4)} R5: ${PD(tc.r5)} R6: ${PD(tc.r6)} R7: ${PD(tc.r7)}`)
            logw(`R8: ${PD(tc.r8)} R9: ${PD(tc.r9)} R10: ${PD(tc.r10)} R11: ${PD(tc.r11)}`)
            logh(`\nIP(R12): ${PD(tc.r12)} SP(R13): ${PD(tc.sp)} LR(R14): ${PD(tc.lr)} PC(R15): ${PD(tc.pc)}`)
        }
    }

    private static callOutInnerArm64 = (context: Arm64CpuContext) => {
        const tc = context as Arm64CpuContext
        const currentThread: number = Process.getCurrentThreadId()
        logd(`\n[ ${getThreadName(currentThread)} @ ${currentThread} }\n`)
        BreakPoint.printRegs(context)
        InstructionParser.printCurrentInstruction(tc.pc)
        printStack(context)
        BPStatus.getStepActions(currentThread).forEach(action => action(tc))
        // BreakPoint.BackTraceBySystem() // recommend using in StepAction not there
        Signal.sem_wait_threadid(currentThread)
    }

    private static callOutInnerArm = (context: ArmCpuContext) => {
        throw new Error("not implement")
    }

}

// Reflect.set(globalThis, "BreakPoint", BreakPoint)
// Reflect.set(globalThis, "bp", BreakPoint)
Reflect.set(globalThis, "b", BreakPoint.attchByFunction) // breakpoint
Reflect.set(globalThis, "c", BreakPoint.continueThread) // continue