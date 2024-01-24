export namespace BreakPoint {

    var value: NativePointer = NULL

    export const setValue = (address: number | NativePointer) => {
        value = typeof address === 'number' ? new NativePointer(address) : address
    }

    export const attch = (mPtr: NativePointer | number = NULL) => {
        if (mPtr !== NULL) setValue(mPtr)
        Interceptor.attach(value, {
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
                            if (Debugger.getModule().has(instruction!.address)) {
                                console.log(`${DebugSymbol.fromAddress(instruction?.address as NativePointer)} ${instruction}`)
                                iterator.putCallout(CalloutInner)
                                // // bl #
                                // if (instruction?.toString().includes("bl #")) {
                                //     const addr = ptr(instruction?.toString().split("bl #")[1].toString()!)
                                //     console.warn(DebugSymbol.fromAddress(addr))
                                // }
                            }
                            iterator.keep()
                        } while ((instruction = iterator.next()) !== null)

                    }
                })
            },
            onLeave(this: InvocationContext, _retval: InvocationReturnValue) {
                Stalker.unfollow(Process.getCurrentThreadId())
            }
        })
    }

    export const CalloutInner = (context: CpuContext) => {
        clear()
        const thisContext = context as Arm64CpuContext
        console.warn(`x0: ${thisContext.x0} x1: ${thisContext.x1} x2: ${thisContext.x2} x3: ${thisContext.x3} pc: ${thisContext.pc} sp: ${thisContext.sp} fp: ${thisContext.fp} lr: ${thisContext.lr}`)
        console.log(`-> ${DebugSymbol.fromAddress(context.pc)} | ${Instruction.parse(context.pc)}`)
        Signal.sem_wait()
    }

}

declare global {
    var bp: any
}

globalThis.bp = BreakPoint