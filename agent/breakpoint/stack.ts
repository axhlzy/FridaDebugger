import { logd } from '../logger.js'

const printStack = (ctx:CpuContext)=>{
    if (ctx == undefined) throw new Error("ctx can not be undefined")
    import("frida-stack").then(md=>{
        logd(`[+]${md.Stack.getModuleInfo(ctx.pc)}`)
        logd(md.Stack.native(ctx)) 
    }) 
}

declare global {
    var printStack: (ctx:CpuContext)=>void
}

globalThis.printStack = printStack