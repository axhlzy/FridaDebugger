import { VM, VMAction, GPRState, FPRState, CallbackPriority, VMError, InstPosition, SyncDirection }
    from './arm64-v8a/share/qbdiAARCH64/frida-qbdi.js'
import { AnalysisType, ContextItem, ExtraInfo } from './StructInfo.js'
import { logd, logz } from '../../logger.js'
import { ContextParser } from './ContextParser.js'

type ICBK_CALL = (vm: VM, gpr: GPRState, fpr: FPRState, data: NativePointer) => number

class QBDIManager {

    static StackSize = 0x1000 * 10

    static vm: VM
    static state: GPRState
    static stack: NativePointer = NULL
    static baseSP: NativePointer = NULL

    static extraInfo: ExtraInfo = new ExtraInfo()
    static contextInfo: Array<ContextItem> = []

    static initQBDI = (size: number = QBDIManager.StackSize) => {

        // fakeStackCheck()
        QBDIManager.vm = new VM()
        QBDIManager.state = QBDIManager.vm.getGPRState()
        QBDIManager.stack = QBDIManager.vm.allocateVirtualStack(QBDIManager.state, size)
        QBDIManager.baseSP = QBDIManager.state.getRegister("SP")!
        if (QBDIManager.stack == NULL) throw new Error("allocateVirtualStack failed")
        logd(`INIT QBDI VM -> Stack: ${QBDIManager.stack} | SP: ${QBDIManager.baseSP}`)

        QBDIManager.vm.clearAllCache()
        QBDIManager.extraInfo.reSet()
        QBDIManager.contextInfo = []
    }

    static default_icbk = function (vm: VM, gpr: GPRState, _fpr: FPRState, _data: NativePointer): number {
        const data: ExtraInfo = _data as unknown as ExtraInfo
        const inst: AnalysisType = vm.getInstAnalysis()
        const lastAddress: NativePointer = data.lastAddress
        if (lastAddress.isNull()) QBDIManager.baseSP = gpr.getRegister("SP")!
        const index: number = data.index
        const startTime_ICBK: number = data.startTime
        const currentAddress: NativePointer = ptr(inst.address)
        const custTime = index == 0 ? 0 : Date.now() - startTime_ICBK
        const preText = `[ ${index.toString().padEnd(3, ' ')} | ${custTime} ms ]`.padEnd(18, ' ')
        if (startTime_ICBK === 0) data.setStartTimeNow()

        // record
        const spOffset: NativePointer = QBDIManager.baseSP.sub(gpr.getRegister("SP"))
        QBDIManager.contextInfo.push(new ContextItem(inst, spOffset, gpr))

        // logz(`${preText} ${asmOffset.toString().padEnd(8, ' ')} ${currentAddress}| INSC: ${data.runInstCount.toString().padEnd(7, ' ')} | ${inst.disassembly}`)
        logz(`${preText} ${spOffset.toString().padEnd(8, ' ')} ${currentAddress} | ${inst.disassembly}`)
        ++data.runInstCount
        ++data.index
        data.lastAddress = currentAddress
        return VMAction.CONTINUE
    }

    static traceFunction = (mPtr: NativePointer | string | number, icbk_function: ICBK_CALL | NativePointer | number = QBDIManager.default_icbk, argsCount: number = 4, onece: boolean = true) => {
        if (mPtr == null) throw new Error("traceFunction : mPtr is null")
        let targetFunctionPtr: NativePointer = NULL
        if (mPtr instanceof NativePointer) targetFunctionPtr = mPtr
        if (typeof mPtr == "string" || typeof mPtr == "number") targetFunctionPtr = ptr(mPtr)

        QBDIManager.initQBDI()

        let syncRegs = false // not impl
        type callBackType = NativeFunction<NativePointer, [NativePointer, NativePointer, NativePointer, NativePointer, NativePointer]>
        let srcFunc: callBackType = new NativeFunction(targetFunctionPtr, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'])
        const callback = new NativeCallback(function (_arg0: NativePointer, _arg1: NativePointer, _arg2: NativePointer, _arg3: NativePointer, _arg4: NativePointer) {
            let args: NativePointer[] = []
            for (let i = 0; i < argsCount; i++) args.push(arguments[i]);
            logd(`\ncalled ${targetFunctionPtr} | args => ${args.join(' ')}`)
            // let ret: NativePointer = srcFunc.apply(null, arguments as any)
            Interceptor.revert(targetFunctionPtr)
            Interceptor.flush()
            if (syncRegs) QBDIManager.state.synchronizeContext(this.context, SyncDirection.FRIDA_TO_QBDI)

            // trace range
            // QBDIManager.vm.addInstrumentedModuleFromAddr(targetFunctionPtr)
            QBDIManager.vm.addInstrumentedRange(targetFunctionPtr, targetFunctionPtr.add(0x200))

            let icbk = QBDIManager.vm.newInstCallback(icbk_function)
            ++QBDIManager.extraInfo.index
            QBDIManager.extraInfo.setStartTimeNow()
            let status = QBDIManager.vm.addCodeCB(InstPosition.PREINST, icbk, QBDIManager.extraInfo, CallbackPriority.PRIORITY_DEFAULT)
            if (status == VMError.INVALID_EVENTID) throw new Error("addCodeCB failed")
            logd(`VM START | CALL -> ${srcFunc} | at ${new Date().toLocaleTimeString()}`)
            const vm_retval = Module.findBaseAddress("libil2cpp.so") ?
                QBDIManager.vm.call(srcFunc, args) :
                Il2Cpp.perform(() => {
                    return QBDIManager.vm.call(srcFunc, args)
                })
            if (syncRegs) QBDIManager.state.synchronizeContext(this.context, SyncDirection.QBDI_TO_FRIDA)
            logd(`VM STOP | RET => ${vm_retval}`)
            if (!onece) Interceptor.replace(targetFunctionPtr, callback)
            else Interceptor.detachAll()
            return vm_retval
        }, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'])

        try {
            Interceptor.replace(targetFunctionPtr, callback)
        } catch (error: any) {
            if (error.message.includes("already replaced")) {
                Interceptor.revert(targetFunctionPtr)
                Interceptor.flush()
                Interceptor.replace(targetFunctionPtr, callback)
            } else throw error
        }
    }

    static getContextParser = () => {
        return new ContextParser(QBDIManager.contextInfo)
    }

    static showIndentation = () => {
        QBDIManager.getContextParser().showIndentation()
    }

}

declare global {
    var traceFunction: (mPtr: NativePointer | string | number, icbk_function?: ICBK_CALL | NativePointer | number, argsCount?: number, onece?: boolean) => void
    var getContextParser: () => ContextParser
}

globalThis.traceFunction = QBDIManager.traceFunction
globalThis.getContextParser = QBDIManager.getContextParser

Reflect.set(globalThis, 'QBDIManager', QBDIManager)