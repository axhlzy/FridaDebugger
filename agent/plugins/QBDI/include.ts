import { VM, VMAction, GPRState, FPRState, CallbackPriority, VMError, InstPosition, SyncDirection } from './arm64-v8a/share/qbdiAARCH64/frida-qbdi'
import { logd, logz } from '../../logger'

type ICBK_CALL = (vm: VM, gpr: GPRState, fpr: FPRState, data: NativePointer) => number
class QBDIManager {

    static UINT64_SIZE = 0x8         // 定义存放数据基本块大小
    static StackSize = 0x1000 * 10   // 定义栈大小

    static QBDI_INIT = false
    static vm: VM
    static state: GPRState
    static stack: NativePointer = NULL
    static baseSP: NativePointer = NULL

    static initQBDI = (size: number = QBDIManager.StackSize) => {
        if (QBDIManager.QBDI_INIT) {
            QBDIManager.vm.clearAllCache()
            return
        }
        // fakeStackCheck()
        QBDIManager.vm = new VM()
        QBDIManager.state = QBDIManager.vm.getGPRState()
        QBDIManager.stack = QBDIManager.vm.allocateVirtualStack(QBDIManager.state, size)
        QBDIManager.baseSP = QBDIManager.state.getRegister("SP")!
        if (QBDIManager.stack == NULL) throw new Error("allocateVirtualStack failed")
        logd(`INIT QBDI VM -> Stack: ${QBDIManager.stack} | SP: ${QBDIManager.baseSP}`)
        QBDIManager.QBDI_INIT = true
    }

    // not use
    static testFunction = () => {

        const vm: VM = new VM()


    }


    static default_icbk = function (vm: VM, gpr: GPRState, _fpr: FPRState, _data: NativePointer) {
        let inst = vm.getInstAnalysis()
        let lastAddress: NativePointer = _data.readPointer()
        if (lastAddress == NULL) QBDIManager.baseSP = gpr.getRegister("SP")!
        let index: UInt64 = _data.add(QBDIManager.UINT64_SIZE * 1).readU64()
        let startTime_ICBK: UInt64 = _data.add(QBDIManager.UINT64_SIZE * 2).readU64()
        let run_inst_count: UInt64 = _data.add(QBDIManager.UINT64_SIZE * 3).readU64()
        let currentAddress: NativePointer = ptr(inst.address)
        let currentTime: UInt64 = new UInt64(Date.now())
        let custTime = index.equals(0) ? 0 : currentTime.sub(startTime_ICBK)
        let preText = `[ ${index.toString().padEnd(3, ' ')} | ${custTime} ms ]`.padEnd(18, ' ')
        if (startTime_ICBK.equals(0)) _data.add(QBDIManager.UINT64_SIZE * 2).writeU64(Date.now())

        let asmOffset = QBDIManager.baseSP.sub(gpr.getRegister("SP"))
        logz(`${preText} ${asmOffset.toString().padEnd(8, ' ')} ${currentAddress} | INSC: ${run_inst_count.toString().padEnd(7, ' ')} | ${inst.disassembly}`)
        _data.add(QBDIManager.UINT64_SIZE * 3).writeU64(run_inst_count.add(1))
        _data.writePointer(currentAddress)
        return VMAction.CONTINUE
    }

    static traceFunction = (mPtr: NativePointer | string | number, icbk_function: ICBK_CALL | NativePointer = QBDIManager.default_icbk, argsCount: number = 4, once: boolean = true) => {
        if (mPtr == null) throw new Error("traceFunction : mPtr is null")
        let function_ptr: NativePointer = NULL
        if (mPtr instanceof NativePointer) function_ptr = mPtr
        if (typeof mPtr == "string" || typeof mPtr == "number") function_ptr = ptr(mPtr)
        if (icbk_function == NULL) icbk_function = QBDIManager.default_icbk

        QBDIManager.initQBDI()

        let syncRegs = true
        type callBackType = NativeFunction<NativePointer, [NativePointer, NativePointer, NativePointer, NativePointer, NativePointer]>
        let srcFunc: callBackType = new NativeFunction(function_ptr, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'])
        var callback = new NativeCallback(function (_arg0, _arg1, _arg2, _arg3, _arg4) {
            let args: NativePointer[] = []
            for (let i = 0; i < argsCount; i++) args.push(arguments[i]);
            logd(`\ncalled ${function_ptr} | args => ${args.join(' ')}`)
            // let ret: NativePointer = srcFunc.apply(null, arguments as any)
            Interceptor.revert(function_ptr)
            Interceptor.flush()
            if (syncRegs) QBDIManager.state.synchronizeContext(this.context, SyncDirection.FRIDA_TO_QBDI)
            QBDIManager.vm.addInstrumentedModuleFromAddr(function_ptr)
            let icbk = QBDIManager.vm.newInstCallback(icbk_function)
            var extraInfo: NativePointer = Memory.alloc(QBDIManager.UINT64_SIZE * 4)
            extraInfo.add(QBDIManager.UINT64_SIZE * 0).writePointer(NULL) // int64_t 记录上一次的地址
            extraInfo.add(QBDIManager.UINT64_SIZE * 1).writePointer(NULL) // int64_t 记录 index
            extraInfo.add(QBDIManager.UINT64_SIZE * 2).writePointer(NULL) // int64_t 开始时间
            extraInfo.add(QBDIManager.UINT64_SIZE * 3).writePointer(NULL) // int64_t 记录 run inst count
            let status = QBDIManager.vm.addCodeCB(InstPosition.PREINST, icbk, extraInfo, CallbackPriority.PRIORITY_DEFAULT)
            if (status == VMError.INVALID_EVENTID) throw new Error("addCodeCB failed")
            var startTime = Date.now()
            logd(`VM START | CALL -> ${srcFunc} | at ${new Date().toLocaleTimeString()}`)
            let vm_retval = QBDIManager.vm.call(srcFunc, args)
            if (syncRegs) QBDIManager.state.synchronizeContext(this.context, SyncDirection.QBDI_TO_FRIDA)
            logd(`VM STOP | RET => ${vm_retval} | cust ${Date.now() - startTime}ms`)
            if (!once) Interceptor.replace(function_ptr, callback)
            return vm_retval
        }, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'])

        try {
            Interceptor.replace(function_ptr, callback)
        } catch (error: any) {
            if (error.message.includes("already replaced")) {
                Interceptor.revert(function_ptr)
                Interceptor.flush()
                Interceptor.replace(function_ptr, callback)
            } else throw error
        }
    }

}

declare global {
    var traceFunction: typeof QBDIManager.traceFunction
}

globalThis.traceFunction = QBDIManager.traceFunction