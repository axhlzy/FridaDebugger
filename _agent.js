📦
368 /agent/main.js.map
281 /agent/main.js
5519 /agent/breakpoint/BPStatus.js.map
5372 /agent/breakpoint/BPStatus.js
4754 /agent/breakpoint/backtrace.js.map
6723 /agent/breakpoint/backtrace.js
8230 /agent/breakpoint/breakpoint.js.map
7731 /agent/breakpoint/breakpoint.js
251 /agent/breakpoint/include.js.map
95 /agent/breakpoint/include.js
588 /agent/breakpoint/stack.js.map
321 /agent/breakpoint/stack.js
163 /agent/cmoudles/include.js.map
10 /agent/cmoudles/include.js
1294 /agent/debugger.js.map
1076 /agent/debugger.js
188 /agent/instructions/include.js.map
26 /agent/instructions/include.js
3292 /agent/instructions/instruction.js.map
3124 /agent/instructions/instruction.js
4967 /agent/logger.js.map
6715 /agent/logger.js
472 /agent/parser/ArtParser.js.map
306 /agent/parser/ArtParser.js
349 /agent/parser/DynamicParser.js.map
183 /agent/parser/DynamicParser.js
356 /agent/parser/Il2cppParser.js.map
260 /agent/parser/Il2cppParser.js
380 /agent/parser/ParserBase.js.map
216 /agent/parser/ParserBase.js
2777 /agent/parser/StringParser.js.map
2437 /agent/parser/StringParser.js
459 /agent/parser/StructParser.js.map
285 /agent/parser/StructParser.js
521 /agent/parser/SymbolParser.js.map
333 /agent/parser/SymbolParser.js
320 /agent/parser/include.js.map
191 /agent/parser/include.js
167 /agent/plugins/LIEF/include.js.map
10 /agent/plugins/LIEF/include.js
2828 /agent/plugins/QBDI/ContextParser.js.map
2341 /agent/plugins/QBDI/ContextParser.js
5424 /agent/plugins/QBDI/QBDIMain.js.map
5710 /agent/plugins/QBDI/QBDIMain.js
2580 /agent/plugins/QBDI/StructInfo.js.map
2858 /agent/plugins/QBDI/StructInfo.js
47593 /agent/plugins/QBDI/arm64-v8a/share/qbdiAARCH64/frida-qbdi.js.map
69209 /agent/plugins/QBDI/arm64-v8a/share/qbdiAARCH64/frida-qbdi.js
209 /agent/plugins/QBDI/include.js.map
49 /agent/plugins/QBDI/include.js
165 /agent/plugins/V8/include.js.map
10 /agent/plugins/V8/include.js
171 /agent/plugins/capstone/include.js.map
10 /agent/plugins/capstone/include.js
167 /agent/plugins/curl/include.js.map
10 /agent/plugins/curl/include.js
342 /agent/plugins/include.js.map
224 /agent/plugins/include.js
171 /agent/plugins/keystone/include.js.map
10 /agent/plugins/keystone/include.js
230 /agent/plugins/main.js.map
54 /agent/plugins/main.js
170 /agent/plugins/openssl/include.js.map
10 /agent/plugins/openssl/include.js
244 /agent/plugins/plugin_main.js.map
54 /agent/plugins/plugin_main.js
3031 /agent/signal.js.map
2693 /agent/signal.js
3431 /agent/utils.js.map
3191 /agent/utils.js
1484 /node_modules/@frida/process/index.js
↻ process
4686 /node_modules/@frida/util/support/types.js
19179 /node_modules/@frida/util/util.js
↻ util
105701 /node_modules/frida-il2cpp-bridge/dist/index.js.map
143555 /node_modules/frida-il2cpp-bridge/dist/index.js
↻ frida-il2cpp-bridge
✄
{"version":3,"file":"main.js","sourceRoot":"C:/Users/admin/Desktop/git_project/FridaDebugger/","sources":["agent/main.ts"],"names":[],"mappings":"AAAA,OAAO,aAAa,CAAA;AACpB,OAAO,YAAY,CAAA;AACnB,OAAO,eAAe,CAAA;AACtB,OAAO,aAAa,CAAA;AAEpB,OAAO,yBAAyB,CAAA;AAChC,OAAO,2BAA2B,CAAA;AAClC,OAAO,uBAAuB,CAAA;AAC9B,OAAO,qBAAqB,CAAA;AAE5B,OAAO,sBAAsB,CAAA;AAE7B,OAAO,qBAAqB,CAAA"}
✄
import './logger.js';
import './utils.js';
import './debugger.js';
import './signal.js';
import './breakpoint/include.js';
import './instructions/include.js';
import './cmoudles/include.js';
import './parser/include.js';
import './plugins/include.js';
import "frida-il2cpp-bridge";
✄
{"version":3,"file":"BPStatus.js","sourceRoot":"C:/Users/admin/Desktop/git_project/FridaDebugger/","sources":["agent/breakpoint/BPStatus.ts"],"names":[],"mappings":"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"}
✄
import { logd, logw } from "../logger.js";
export class BPStatus {
    // is stuck at breakpoint
    static isPaused = new Map();
    // current using thread id
    static currentThreadId = 0;
    // record current pc
    static currentPC = new Map();
    // record breakpoints
    static breakpoints = new Set();
    // map bp type
    static bpType = new Map();
    // map action step function to thread
    static actionStep = new Map();
    // map thread to contextMap
    static threadContextMap = new Map();
    static addBp = (bp, type) => {
        BPStatus.breakpoints.add(bp);
        BPStatus.bpType.set(bp, type);
    };
    static removeBp = (bp) => {
        BPStatus.breakpoints.delete(bp);
        BPStatus.bpType.delete(bp);
    };
    static getBpType = (bp) => {
        const ret = BPStatus.bpType.get(bp);
        if (ret == null)
            throw new Error("bp type is null");
        return ret;
    };
    static setPaused = (thread_id, paused) => {
        BPStatus.isPaused.set(thread_id, paused);
        BPStatus.currentThreadId = thread_id;
    };
    static hasPausedThread = () => {
        for (const [_key, value] of BPStatus.isPaused) {
            if (value)
                return true;
        }
        return false;
    };
    static addStepAction = (action, thread_id = BPStatus.currentThreadId) => {
        let actions = BPStatus.actionStep.get(thread_id);
        if (actions == undefined) {
            actions = new Array();
            BPStatus.actionStep.set(thread_id, actions);
        }
        actions.push(action);
    };
    static listStepAction = (thread_id = BPStatus.currentThreadId) => {
        let index = -1;
        logw(`selectd thread_id: ${thread_id}`);
        BPStatus.actionStep.forEach((value, _key) => {
            logd(`[${++index}]\n\taction: ${value}`);
        });
    };
    static getStepActions = (thread_id = BPStatus.currentThreadId) => {
        const actions = BPStatus.actionStep.get(thread_id);
        if (actions == undefined)
            return [];
        return actions;
    };
    static removeAllStepAction = (thread_id = BPStatus.currentThreadId) => {
        const actions = BPStatus.actionStep.get(thread_id);
        if (actions == undefined)
            throw new Error("actions is null");
        actions.splice(0, actions.length);
    };
    static removeIndexStepAction = (index, thread_id = BPStatus.currentThreadId) => {
        const actions = BPStatus.actionStep.get(thread_id);
        if (actions == undefined)
            throw new Error("actions is null");
        actions.splice(index, 1);
    };
    static addThreadContext = (thread_id, address, context) => {
        let contextMap = BPStatus.threadContextMap.get(thread_id);
        if (contextMap == undefined) {
            contextMap = new Map();
            BPStatus.threadContextMap.set(thread_id, contextMap);
        }
        contextMap.set(address, context);
    };
    static getCurrentContext = (thread_id = BPStatus.currentThreadId) => {
        const contextMap = BPStatus.threadContextMap.get(thread_id);
        if (contextMap == undefined)
            throw new Error("contextMap is null");
        const address = BPStatus.currentPC.get(BPStatus.currentThreadId);
        if (address == undefined)
            throw new Error("address is null");
        let context = undefined;
        for (const [key, value] of contextMap) {
            if (key.equals(address)) {
                context = value;
                break;
            }
        }
        // contextMap.forEach((value, key) => logd(`key = ${key} value = ${value}`))
        if (context == undefined)
            throw new Error("context is null");
        return context;
    };
    static toString() {
        let disp = '\n';
        disp += `CurrentThreadId : ${BPStatus.currentThreadId}\n`;
        disp += `CurrentPC : ${JSON.stringify(Array.from(BPStatus.currentPC))}\n`;
        disp += `Breakpoints size : ${BPStatus.breakpoints.size}\n`;
        disp += `\t${JSON.stringify(Array.from(BPStatus.breakpoints.entries()))}\n`;
        disp += `threadContextMap size : ${BPStatus.threadContextMap.size}\n`;
        disp += `\t${JSON.stringify(Array.from(BPStatus.threadContextMap.entries()))}\n`;
        return disp;
    }
    static saveBuffer() {
        // mmap maps a section of memory to hold data(BPStatus)
        // todo ...
    }
    toBuffer() {
        const data = JSON.stringify({
            isPaused: BPStatus.isPaused,
            currentThreadId: BPStatus.currentThreadId,
            currentPC: Array.from(BPStatus.currentPC.entries())
            // ...
        });
        return Buffer.from(data);
    }
    static fromBuffer(buffer) {
        const json = buffer.toString();
        const data = JSON.parse(json);
        BPStatus.isPaused = data.isPaused;
        BPStatus.currentThreadId = data.currentThreadId;
        BPStatus.currentPC = new Map(data.currentPC);
        // ...
    }
}
export var BP_TYPE;
(function (BP_TYPE) {
    BP_TYPE[BP_TYPE["LR"] = 0] = "LR";
    BP_TYPE[BP_TYPE["SP"] = 1] = "SP";
    BP_TYPE[BP_TYPE["RANGE"] = 2] = "RANGE";
    BP_TYPE[BP_TYPE["Function"] = 3] = "Function";
})(BP_TYPE || (BP_TYPE = {}));
Reflect.set(globalThis, "BPStatus", BPStatus);
Reflect.set(globalThis, "status", () => { logd(BPStatus.toString()); });
Reflect.set(globalThis, "bps", BPStatus);
✄
{"version":3,"file":"backtrace.js","sourceRoot":"C:/Users/admin/Desktop/git_project/FridaDebugger/","sources":["agent/breakpoint/backtrace.ts"],"names":[],"mappings":"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"}
✄
import { logd, logz } from "../logger.js";
import { BPStatus } from "./BPStatus.js";
export class BackTrace {
    constructor() { }
    // impl by frida
    static BackTraceByFrida = (ctx = BPStatus.getCurrentContext(), fuzzy = false, retText = false, slice = 6) => {
        let tmpText = Thread.backtrace(ctx, fuzzy ? Backtracer.FUZZY : Backtracer.ACCURATE)
            .slice(0, slice)
            .map(DebugSymbol.fromAddress)
            .map((sym, index) => {
            let strRet = `${PD(`[${index}]`, 5)} ${sym}`;
            return strRet;
        })
            .join(`\n`);
        return !retText ? logd(tmpText) : tmpText;
    };
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
        let _Unwind_Reason_Code;
        (function (_Unwind_Reason_Code) {
            _Unwind_Reason_Code[_Unwind_Reason_Code["_URC_NO_REASON"] = 0] = "_URC_NO_REASON";
            _Unwind_Reason_Code[_Unwind_Reason_Code["_URC_FOREIGN_EXCEPTION_CAUGHT"] = 1] = "_URC_FOREIGN_EXCEPTION_CAUGHT";
            _Unwind_Reason_Code[_Unwind_Reason_Code["_URC_FATAL_PHASE2_ERROR"] = 2] = "_URC_FATAL_PHASE2_ERROR";
            _Unwind_Reason_Code[_Unwind_Reason_Code["_URC_FATAL_PHASE1_ERROR"] = 3] = "_URC_FATAL_PHASE1_ERROR";
            _Unwind_Reason_Code[_Unwind_Reason_Code["_URC_NORMAL_STOP"] = 4] = "_URC_NORMAL_STOP";
            _Unwind_Reason_Code[_Unwind_Reason_Code["_URC_END_OF_STACK"] = 5] = "_URC_END_OF_STACK";
            _Unwind_Reason_Code[_Unwind_Reason_Code["_URC_HANDLER_FOUND"] = 6] = "_URC_HANDLER_FOUND";
            _Unwind_Reason_Code[_Unwind_Reason_Code["_URC_INSTALL_CONTEXT"] = 7] = "_URC_INSTALL_CONTEXT";
            _Unwind_Reason_Code[_Unwind_Reason_Code["_URC_CONTINUE_UNWIND"] = 8] = "_URC_CONTINUE_UNWIND";
        })(_Unwind_Reason_Code || (_Unwind_Reason_Code = {}));
        // using _Unwind_Backtrace
        const _Unwind_Backtrace = new NativeFunction(DebugSymbol.fromName("_Unwind_Backtrace").address, 'int', ['pointer', 'pointer']);
        // _Unwind_Word _Unwind_GetIP(struct _Unwind_Context *);
        const _Unwind_GetIP = new NativeFunction(DebugSymbol.fromName("_Unwind_GetIP").address, 'pointer', ['pointer']);
        // void _Unwind_SetIP(struct _Unwind_Context *, _Unwind_Word);
        const _Unwind_SetIP = new NativeFunction(DebugSymbol.fromName("_Unwind_SetIP").address, 'void', ['pointer', 'pointer']);
        // _Unwind_Word _Unwind_GetGR(struct _Unwind_Context *, int);
        const _Unwind_GetGR = new NativeFunction(DebugSymbol.fromName("_Unwind_GetGR").address, 'pointer', ['pointer', 'int']);
        // void _Unwind_SetGR(struct _Unwind_Context *, int, _Unwind_Word);
        const _Unwind_SetGR = new NativeFunction(DebugSymbol.fromName("_Unwind_SetGR").address, 'void', ['pointer', 'int', 'pointer']);
        // _Unwind_Word _Unwind_GetIPInfo(struct _Unwind_Context *, int *);
        const _Unwind_GetIPInfo = new NativeFunction(DebugSymbol.fromName("_Unwind_GetIPInfo").address, 'pointer', ['pointer', 'pointer']);
        // _Unwind_Word _Unwind_GetCFA(struct _Unwind_Context *);
        const _Unwind_GetCFA = new NativeFunction(DebugSymbol.fromName("_Unwind_GetCFA").address, 'pointer', ['pointer']);
        // _Unwind_Word _Unwind_GetBSP(struct _Unwind_Context *);
        const _Unwind_GetBSP = new NativeFunction(DebugSymbol.fromName("_Unwind_GetBSP").address, 'pointer', ['pointer']);
        // _Unwind_Ptr _Unwind_GetDataRelBase(struct _Unwind_Context *);
        const _Unwind_GetDataRelBase = new NativeFunction(DebugSymbol.fromName("_Unwind_GetDataRelBase").address, 'pointer', ['pointer']);
        // _Unwind_Ptr _Unwind_GetTextRelBase(struct _Unwind_Context *);
        const _Unwind_GetTextRelBase = new NativeFunction(DebugSymbol.fromName("_Unwind_GetTextRelBase").address, 'pointer', ['pointer']);
        logd(`DataRelBase ${_Unwind_GetDataRelBase} | TextRelBase ${_Unwind_GetTextRelBase}`);
        var count = 0;
        _Unwind_Backtrace(new NativeCallback((ctx, _arg) => {
            try {
                const ip = _Unwind_GetIP(ctx); // lr
                logd(`Frame ${PD(`# ${++count}`, 5)}\n\t${DebugSymbol.fromAddress(ip)} | ${Instruction.parse(ip)}`);
                // InstructionParser.printCurrentInstruction(ip, 5)
                if (Process.arch == 'arm64') {
                    // x19 - x31 (64-bit) Non-Volatile Register
                    const x19 = _Unwind_GetGR(ctx, 19);
                    const x20 = _Unwind_GetGR(ctx, 20);
                    const x21 = _Unwind_GetGR(ctx, 21);
                    const x22 = _Unwind_GetGR(ctx, 22);
                    const x23 = _Unwind_GetGR(ctx, 23);
                    const x24 = _Unwind_GetGR(ctx, 24);
                    const x25 = _Unwind_GetGR(ctx, 25);
                    const x26 = _Unwind_GetGR(ctx, 26);
                    const x27 = _Unwind_GetGR(ctx, 27);
                    const x28 = _Unwind_GetGR(ctx, 28);
                    const fp = _Unwind_GetGR(ctx, 29);
                    const lr = _Unwind_GetGR(ctx, 30);
                    // const sp: NativePointer = _Unwind_GetGR(ctx, 31) // misapplication  
                    const cfa = _Unwind_GetCFA(ctx);
                    // const bsp: NativePointer = _Unwind_GetBSP(ctx)
                    logz(`\t${PD(`x19: ${x19}`)} ${PD(`x20: ${x20}`)} ${PD(`x21: ${x21}`)} ${PD(`x22: ${x22}`)} ${PD(`x23: ${x23}`)} ${PD(`x24: ${x24}`)}\n\t${PD(`x25: ${x25}`)} ${PD(`x26: ${x26}`)} ${PD(`x27: ${x27}`)} ${PD(`x28: ${x28}`)}`);
                    logz(`\t${PD(`fp: ${fp}`)} ${PD(`lr: ${lr}`)} ${PD(`sp: ${cfa}`)}`);
                }
            }
            catch { /* end of stack */ }
            newLine();
            return _Unwind_Reason_Code._URC_NO_REASON;
        }, 'int', ['pointer', 'pointer']), NULL);
    };
}
// backtrace
Reflect.set(globalThis, "bt", BackTrace.BackTraceByFrida);
Reflect.set(globalThis, "btf", BackTrace.BackTraceByFrida);
Reflect.set(globalThis, "bts", BackTrace.BackTraceBySystem);
✄
{"version":3,"file":"breakpoint.js","sourceRoot":"C:/Users/admin/Desktop/git_project/FridaDebugger/","sources":["agent/breakpoint/breakpoint.ts"],"names":[],"mappings":"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"}
✄
import { InstructionParser } from '../instructions/instruction.js';
import { logd, logh, logw, logz } from '../logger.js';
import { BPStatus, BP_TYPE } from './BPStatus.js';
import { padding as PD } from '../utils.js';
import { Debugger } from '../debugger.js';
import { Signal } from '../signal.js';
const DebugType = false;
export class BreakPoint {
    static InnerAttach(localPtr, threadid) {
        if (DebugType)
            logw(`InnerAttach ${localPtr}`);
        Interceptor.attach(localPtr, {
            onEnter(_args) {
                threadid = threadid == undefined ? Process.getCurrentThreadId() : threadid;
                logw(`Enter ${localPtr} | threadid ${threadid} | MAIN ? ${Boolean(threadid === getMainThreadId())}`);
                Stalker.follow(threadid, {
                    events: {
                        call: false,
                        ret: false,
                        exec: true,
                        block: false,
                        compile: false,
                    },
                    transform: function (iterator) {
                        let instruction = iterator.next();
                        if (DebugType)
                            logw(instruction.toString());
                        do {
                            if (Debugger.getModule(threadid).has(instruction.address)) {
                                if (DebugType)
                                    logz(`${DebugSymbol.fromAddress(instruction?.address)} ${instruction}`);
                                iterator.putCallout(BreakPoint.CalloutInner);
                            }
                            iterator.keep();
                        } while ((instruction = iterator.next()) !== null);
                    }
                });
            },
            // only function bp need unfollow here
            onLeave: BPStatus.getBpType(localPtr) != BP_TYPE.Function ? undefined : function (_retval) {
                Stalker.unfollow(threadid);
            }
        });
    }
    static continueThread = (thread_id = BPStatus.currentThreadId) => {
        if (!BPStatus.hasPausedThread())
            throw new Error("no paused thread");
        Stalker.unfollow(thread_id);
        Signal.sem_post_thread_id(thread_id);
        BPStatus.breakpoints.delete(BPStatus.currentPC.get(thread_id));
        BPStatus.currentThreadId = 0;
        BPStatus.setPaused(thread_id, false);
    };
    static attchByFunction = (mPtr = NULL, mdName = null, threadid) => {
        let localPtr = NULL;
        if (mPtr instanceof NativePointer)
            localPtr = mPtr;
        else {
            if (typeof mPtr === 'string') {
                localPtr = typeof mPtr === 'string' ? (mPtr.startsWith("0x") ? ptr(mPtr) : (function () {
                    const md = Module.findExportByName(mdName, mPtr);
                    if (md == null)
                        throw new Error("md is null");
                    return md;
                })()) : mPtr;
            }
            else
                localPtr = BreakPoint.checkArgs(mPtr);
        }
        try {
            BPStatus.addBp(localPtr, BP_TYPE.Function);
            BreakPoint.InnerAttach(localPtr, threadid);
        }
        catch (error) {
            // if err, don't add it to BPStatus
        }
    };
    static checkArgs = (mPtr = NULL) => {
        let localPtr = NULL;
        if (mPtr instanceof NativePointer)
            return localPtr;
        if (typeof mPtr === 'number') {
            localPtr = ptr(mPtr);
        }
        else {
            throw new Error("mPtr must be number");
        }
        if (localPtr == null)
            throw new Error("mPtr is null");
        return localPtr;
    };
    // inlinehook unfollow by pc == lr
    static attachByLR = (mPtr = NULL, threadid) => {
        let localPtr = BreakPoint.checkArgs(mPtr);
        BPStatus.addBp(localPtr, BP_TYPE.LR);
        BreakPoint.InnerAttach(localPtr, threadid);
        throw new Error("not implement");
    };
    // inlinehook unfollow by stack < 0
    static attachBySP = (mPtr = NULL, threadid) => {
        let localPtr = BreakPoint.checkArgs(mPtr);
        BPStatus.addBp(localPtr, BP_TYPE.SP);
        BreakPoint.InnerAttach(localPtr, threadid);
        throw new Error("not implement");
    };
    // inlinehook unfollow by RANGE
    static attachByRange = (mPtr = NULL, threadid) => {
        let localPtr = BreakPoint.checkArgs(mPtr);
        BPStatus.addBp(localPtr, BP_TYPE.RANGE);
        BreakPoint.InnerAttach(localPtr, threadid);
        throw new Error("not implement");
    };
    static CalloutInner = (context) => {
        // clear()
        const currentPC = context.pc;
        // todo moduleFilters implement
        const thread_id = Process.getCurrentThreadId();
        BPStatus.addThreadContext(thread_id, context.pc, context);
        BPStatus.currentPC.set(thread_id, currentPC);
        // check hit
        BPStatus.setPaused(thread_id, true);
        if (BPStatus.breakpoints.has(currentPC.sub(4 * 4))) {
            logw(`Hit breakpoint at ${DebugSymbol.fromAddress(currentPC)} | ${Instruction.parse(currentPC)}`);
            Signal.sem_post_thread_id(thread_id);
        }
        if (Process.arch == "arm64") {
            BreakPoint.callOutInnerArm64(context);
        }
        else if (Process.arch == "arm") {
            BreakPoint.callOutInnerArm(context);
        }
    };
    static printRegs = (context) => {
        if (Process.arch == "arm64") {
            const tc = context;
            logw(`${PD(`X0:  ${tc.x0}`)} ${PD(`X1:  ${tc.x1}`)} ${PD(`X2:  ${tc.x2}`)} ${PD(`X3:  ${tc.x3}`)} ${PD(`X4:  ${tc.x4}`)} ${PD(`X5:  ${tc.x5}`)} ${PD(`X6:  ${tc.x6}`)}`);
            logw(`${PD(`X7:  ${tc.x7}`)} ${PD(`x8:  ${tc.x8}`)} ${PD(`X9:  ${tc.x9}`)} ${PD(`X10: ${tc.x10}`)} ${PD(`X11: ${tc.x11}`)} ${PD(`X12: ${tc.x12}`)} ${PD(`X13: ${tc.x13}`)}`);
            logw(`${PD(`X14: ${tc.x14}`)} ${PD(`X15: ${tc.x15}`)} ${PD(`X19: ${tc.x19}`)} ${PD(`X20: ${tc.x20}`)} ${PD(`X21: ${tc.x21}`)} ${PD(`X22: ${tc.x22}`)} ${PD(`X23: ${tc.x23}`)}`);
            logw(`${PD(`X24: ${tc.x24}`)} ${PD(`X25: ${tc.x25}`)} ${PD(`X26: ${tc.x26}`)} ${PD(`X27: ${tc.x27}`)} ${PD(`X28: ${tc.x28}`)}`);
            logh(`\n${PD(`FP(X29): ${tc.fp}`)}  ${PD(`LR(X30): ${tc.lr}`)}  ${PD(`SP(X31): ${tc.sp}`)} ${PD(`PC: ${tc.pc}`)}`);
        }
        else if (Process.arch == "arm") {
            const tc = context;
            logw(`R0: ${PD(tc.r0)} R1: ${PD(tc.r1)} R2: ${PD(tc.r2)} R3: ${PD(tc.r3)}`);
            logw(`R4: ${PD(tc.r4)} R5: ${PD(tc.r5)} R6: ${PD(tc.r6)} R7: ${PD(tc.r7)}`);
            logw(`R8: ${PD(tc.r8)} R9: ${PD(tc.r9)} R10: ${PD(tc.r10)} R11: ${PD(tc.r11)}`);
            logh(`\nIP(R12): ${PD(tc.r12)} SP(R13): ${PD(tc.sp)} LR(R14): ${PD(tc.lr)} PC(R15): ${PD(tc.pc)}`);
        }
    };
    static callOutInnerArm64 = (context) => {
        const tc = context;
        const currentThread = Process.getCurrentThreadId();
        logd(`\n[ ${getThreadName(currentThread)} @ ${currentThread} }\n`);
        BreakPoint.printRegs(context);
        InstructionParser.printCurrentInstruction(tc.pc);
        printStack(context);
        BPStatus.getStepActions(currentThread).forEach(action => action(tc));
        // BreakPoint.BackTraceBySystem() // recommend using in StepAction not there
        Signal.sem_wait_threadid(currentThread);
    };
    static callOutInnerArm = (context) => {
        throw new Error("not implement");
    };
}
// Reflect.set(globalThis, "BreakPoint", BreakPoint)
// Reflect.set(globalThis, "bp", BreakPoint)
Reflect.set(globalThis, "b", BreakPoint.attchByFunction); // breakpoint
Reflect.set(globalThis, "c", BreakPoint.continueThread); // continue
✄
{"version":3,"file":"include.js","sourceRoot":"C:/Users/admin/Desktop/git_project/FridaDebugger/","sources":["agent/breakpoint/include.ts"],"names":[],"mappings":"AAAA,OAAO,eAAe,CAAA;AACtB,OAAO,iBAAiB,CAAA;AACxB,OAAO,gBAAgB,CAAA;AACvB,OAAO,YAAY,CAAA"}
✄
import './BPStatus.js';
import './breakpoint.js';
import './backtrace.js';
import './stack.js';
✄
{"version":3,"file":"stack.js","sourceRoot":"C:/Users/admin/Desktop/git_project/FridaDebugger/","sources":["agent/breakpoint/stack.ts"],"names":[],"mappings":"AAAA,OAAO,EAAE,IAAI,EAAE,MAAM,cAAc,CAAA;AAEnC,MAAM,UAAU,GAAG,CAAC,GAAc,EAAC,EAAE;IACjC,IAAI,GAAG,IAAI,SAAS;QAAE,MAAM,IAAI,KAAK,CAAC,0BAA0B,CAAC,CAAA;IACjE,MAAM,CAAC,aAAa,CAAC,CAAC,IAAI,CAAC,EAAE,CAAA,EAAE;QAC3B,IAAI,CAAC,MAAM,EAAE,CAAC,KAAK,CAAC,aAAa,CAAC,GAAG,CAAC,EAAE,CAAC,EAAE,CAAC,CAAA;QAC5C,IAAI,CAAC,EAAE,CAAC,KAAK,CAAC,MAAM,CAAC,GAAG,CAAC,CAAC,CAAA;IAC9B,CAAC,CAAC,CAAA;AACN,CAAC,CAAA;AAMD,UAAU,CAAC,UAAU,GAAG,UAAU,CAAA"}
✄
import { logd } from '../logger.js';
const printStack = (ctx) => {
    if (ctx == undefined)
        throw new Error("ctx can not be undefined");
    import("frida-stack").then(md => {
        logd(`[+]${md.Stack.getModuleInfo(ctx.pc)}`);
        logd(md.Stack.native(ctx));
    });
};
globalThis.printStack = printStack;
✄
{"version":3,"file":"include.js","sourceRoot":"C:/Users/admin/Desktop/git_project/FridaDebugger/","sources":["agent/cmoudles/include.ts"],"names":[],"mappings":""}
✄
export {};
✄
{"version":3,"file":"debugger.js","sourceRoot":"C:/Users/admin/Desktop/git_project/FridaDebugger/","sources":["agent/debugger.ts"],"names":[],"mappings":"AAAA,OAAO,EAAE,QAAQ,EAAE,MAAM,0BAA0B,CAAA;AACnD,OAAO,EAAE,IAAI,EAAE,MAAM,aAAa,CAAA;AAElC,MAAM,OAAO,QAAQ;IAEjB,MAAM,CAAC,aAAa,GAAG,IAAI,GAAG,CAAS,CAAC,cAAc,CAAC,CAAC,CAAA;IAExD,MAAM,CAAC,eAAe,GAAG,IAAI,GAAG,EAAqB,CAAA;IAErD,MAAM,CAAC,SAAS,GAAG,CAAC,YAAoB,QAAQ,CAAC,eAAe,EAAa,EAAE;QAC3E,IAAI,QAAQ,CAAC,eAAe,CAAC,GAAG,CAAC,SAAS,CAAC,EAAE;YACzC,OAAO,QAAQ,CAAC,eAAe,CAAC,GAAG,CAAC,SAAS,CAAE,CAAA;SAClD;aAAM;YACH,MAAM,GAAG,GAAG,IAAI,SAAS,CAAC,CAAC,EAAU,EAAE,EAAE,CAAC,QAAQ,CAAC,aAAa,CAAC,GAAG,CAAC,EAAE,CAAC,IAAI,CAAC,CAAC,CAAA;YAC9E,QAAQ,CAAC,eAAe,CAAC,GAAG,CAAC,SAAS,EAAE,GAAG,CAAC,CAAA;YAC5C,OAAO,GAAG,CAAA;SACb;IACL,CAAC,CAAA;IAED,MAAM,CAAC,qBAAqB,GAAG,CAAC,IAAmB,EAAa,EAAE;QAC9D,MAAM,OAAO,GAAG,WAAW,CAAC,WAAW,CAAC,IAAI,CAAC,CAAA;QAC7C,IAAI,OAAO,IAAI,IAAI,IAAI,OAAO,CAAC,UAAU,IAAI,IAAI,EAAE;YAC/C,IAAI,CAAC,iBAAiB,CAAC,CAAA;YACvB,OAAO,IAAI,CAAC,SAAS,EAAE,CAAA;SAC1B;QACD,QAAQ,CAAC,aAAa,CAAC,OAAO,CAAC,UAAU,CAAC,CAAA;QAC1C,OAAO,QAAQ,CAAC,SAAS,EAAE,CAAA;IAC/B,CAAC,CAAA;IAED,MAAM,CAAC,aAAa,GAAG,CAAC,IAAY,EAAE,EAAE;QACpC,QAAQ,CAAC,aAAa,CAAC,GAAG,CAAC,IAAI,CAAC,CAAA;IACpC,CAAC,CAAA;;AAIL,OAAO,CAAC,GAAG,CAAC,UAAU,EAAE,UAAU,EAAE,QAAQ,CAAC,CAAA"}
✄
import { BPStatus } from "./breakpoint/BPStatus.js";
import { loge } from "./logger.js";
export class Debugger {
    static moduleFilters = new Set(["libil2cpp.so"]);
    static CacheByThreadId = new Map();
    static getModule = (thread_id = BPStatus.currentThreadId) => {
        if (Debugger.CacheByThreadId.has(thread_id)) {
            return Debugger.CacheByThreadId.get(thread_id);
        }
        else {
            const ret = new ModuleMap((md) => Debugger.moduleFilters.has(md.name));
            Debugger.CacheByThreadId.set(thread_id, ret);
            return ret;
        }
    };
    static getModuleMapByAddress = (mPtr) => {
        const dbgInfo = DebugSymbol.fromAddress(mPtr);
        if (dbgInfo == null || dbgInfo.moduleName == null) {
            loge(`dbgInfo is null`);
            return this.getModule();
        }
        Debugger.addModuleName(dbgInfo.moduleName);
        return Debugger.getModule();
    };
    static addModuleName = (name) => {
        Debugger.moduleFilters.add(name);
    };
}
Reflect.set(globalThis, "Debugger", Debugger);
✄
{"version":3,"file":"include.js","sourceRoot":"C:/Users/admin/Desktop/git_project/FridaDebugger/","sources":["agent/instructions/include.ts"],"names":[],"mappings":"AAAA,OAAO,kBAAkB,CAAA"}
✄
import './instruction.js';
✄
{"version":3,"file":"instruction.js","sourceRoot":"C:/Users/admin/Desktop/git_project/FridaDebugger/","sources":["agent/instructions/instruction.ts"],"names":[],"mappings":"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"}
✄
import { BPStatus } from "../breakpoint/BPStatus.js";
import { loge, logl, logz } from "../logger.js";
export class InstructionParser {
    constructor() { }
    static printCurrentInstruction = (pc = BPStatus.currentPC.get(BPStatus.currentThreadId), extraIns = 8, ret = false) => {
        if (!ret)
            newLine();
        if (typeof pc === 'number')
            pc = ptr(pc);
        let count = extraIns;
        // fake start
        let instruction_start = pc.sub(4 * ((extraIns / 2)));
        const arrayRet = [];
        // got real start
        let offset = 0;
        do {
            try {
                const ins = Instruction.parse(instruction_start.add(offset * 4));
                instruction_start = ins.address;
                break;
            }
            catch (error) {
                ++offset;
            }
        } while (true);
        let ins = Instruction.parse(instruction_start);
        do {
            // // error ins
            // if (ins.toString().includes('udf')) {
            //     logl(`   ${DebugSymbol.fromAddress(ins.address)} | [ ${getErrorDisc(ins.address)} ]`)
            //     ins = Instruction.parse(ins.address.add(0x4))
            //     continue
            // }
            let ins_str = `${DebugSymbol.fromAddress(ins.address)} | ${ins.toString()}`;
            const ins_op = InstructionParser.InsParser(ins.address);
            if (ins_op.length != 0)
                ins_str += `\t-> ${ins_op}`;
            ins.address.equals(pc) ? loge(`-> ${ins_str}`) : logz(`   ${ins_str}`);
            if (ret)
                arrayRet.push({ address: ins.address, dis: ins_str });
            try {
                ins = Instruction.parse(ins.next);
            }
            catch (error) {
                logl(`   ${DebugSymbol.fromAddress(ins.next)} | [ ${getErrorDisc(ins.next)} ]`);
                ins = Instruction.parse(ins.address.add(0x4));
            }
        } while (--count > 0);
        if (!ret)
            newLine();
        if (ret)
            return arrayRet;
        function getErrorDisc(mPtr) {
            const bt_array = mPtr.readByteArray(4);
            const bt_array_str = Array.from(new Uint8Array(bt_array)).map((item) => item.toString(16).padStart(2, '0')).join(' ');
            return bt_array_str;
        }
    };
    static InsParser(address) {
        try {
            const ins = Instruction.parse(address);
            if (ins.mnemonic == "bl") {
                const opstr = ins.opStr;
                const op = opstr.split("#")[1];
                const sym = DebugSymbol.fromAddress(ptr(op));
                return sym.toString();
            }
        }
        catch (error) {
            return '';
        }
        return '';
    }
}
Reflect.set(globalThis, "InstructionParser", InstructionParser);
Reflect.set(globalThis, "ins", InstructionParser);
Reflect.set(globalThis, "dism", (mPtr, extraIns) => { InstructionParser.printCurrentInstruction(mPtr, extraIns); }); // dism
Reflect.set(globalThis, "pi", (mPtr, extraIns) => { InstructionParser.printCurrentInstruction(mPtr, extraIns); }); // dism 
✄
{"version":3,"file":"logger.js","sourceRoot":"C:/Users/admin/Desktop/git_project/FridaDebugger/","sources":["agent/logger.ts"],"names":[],"mappings":"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"}
✄
export var LogRedirect;
(function (LogRedirect) {
    LogRedirect[LogRedirect["LOGCAT"] = 0] = "LOGCAT";
    LogRedirect[LogRedirect["CMD"] = 1] = "CMD";
    LogRedirect[LogRedirect["BOTH"] = 2] = "BOTH";
    LogRedirect[LogRedirect["TOAST"] = 3] = "TOAST";
    LogRedirect[LogRedirect["NOP"] = 4] = "NOP";
})(LogRedirect || (LogRedirect = {}));
export var android_LogPriority;
(function (android_LogPriority) {
    /** For internal use only.  */
    android_LogPriority[android_LogPriority["ANDROID_LOG_UNKNOWN"] = 0] = "ANDROID_LOG_UNKNOWN";
    /** The default priority, for internal use only.  */
    android_LogPriority[android_LogPriority["ANDROID_LOG_DEFAULT"] = 1] = "ANDROID_LOG_DEFAULT";
    /** Verbose logging. Should typically be disabled for a release apk. */
    android_LogPriority[android_LogPriority["ANDROID_LOG_VERBOSE"] = 2] = "ANDROID_LOG_VERBOSE";
    /** Debug logging. Should typically be disabled for a release apk. */
    android_LogPriority[android_LogPriority["ANDROID_LOG_DEBUG"] = 3] = "ANDROID_LOG_DEBUG";
    /** Informational logging. Should typically be disabled for a release apk. */
    android_LogPriority[android_LogPriority["ANDROID_LOG_INFO"] = 4] = "ANDROID_LOG_INFO";
    /** Warning logging. For use with recoverable failures. */
    android_LogPriority[android_LogPriority["ANDROID_LOG_WARN"] = 5] = "ANDROID_LOG_WARN";
    /** Error logging. For use with unrecoverable failures. */
    android_LogPriority[android_LogPriority["ANDROID_LOG_ERROR"] = 6] = "ANDROID_LOG_ERROR";
    /** Fatal logging. For use when aborting. */
    android_LogPriority[android_LogPriority["ANDROID_LOG_FATAL"] = 7] = "ANDROID_LOG_FATAL";
    /** For internal use only.  */
    android_LogPriority[android_LogPriority["ANDROID_LOG_SILENT"] = 8] = "ANDROID_LOG_SILENT"; /* only for SetMinPriority(); must be last */
})(android_LogPriority || (android_LogPriority = {}));
export var LogColor;
(function (LogColor) {
    LogColor[LogColor["TRACE"] = 0] = "TRACE";
    LogColor[LogColor["MARK"] = 1] = "MARK";
    LogColor[LogColor["FATAL"] = 2] = "FATAL";
    LogColor[LogColor["WHITE"] = 0] = "WHITE";
    LogColor[LogColor["RED"] = 1] = "RED";
    LogColor[LogColor["YELLOW"] = 3] = "YELLOW";
    LogColor[LogColor["C31"] = 31] = "C31";
    LogColor[LogColor["C32"] = 32] = "C32";
    LogColor[LogColor["C33"] = 33] = "C33";
    LogColor[LogColor["C34"] = 34] = "C34";
    LogColor[LogColor["C35"] = 35] = "C35";
    LogColor[LogColor["C36"] = 36] = "C36";
    LogColor[LogColor["C41"] = 41] = "C41";
    LogColor[LogColor["C42"] = 42] = "C42";
    LogColor[LogColor["C43"] = 43] = "C43";
    LogColor[LogColor["C44"] = 44] = "C44";
    LogColor[LogColor["C45"] = 45] = "C45";
    LogColor[LogColor["C46"] = 46] = "C46";
    LogColor[LogColor["C90"] = 90] = "C90";
    LogColor[LogColor["C91"] = 91] = "C91";
    LogColor[LogColor["C92"] = 92] = "C92";
    LogColor[LogColor["C93"] = 93] = "C93";
    LogColor[LogColor["C94"] = 94] = "C94";
    LogColor[LogColor["C95"] = 95] = "C95";
    LogColor[LogColor["C96"] = 96] = "C96";
    LogColor[LogColor["C97"] = 97] = "C97";
    LogColor[LogColor["C100"] = 100] = "C100";
    LogColor[LogColor["C101"] = 101] = "C101";
    LogColor[LogColor["C102"] = 102] = "C102";
    LogColor[LogColor["C103"] = 103] = "C103";
    LogColor[LogColor["C104"] = 104] = "C104";
    LogColor[LogColor["C105"] = 105] = "C105";
    LogColor[LogColor["C106"] = 106] = "C106";
    LogColor[LogColor["C107"] = 107] = "C107";
})(LogColor || (LogColor = {}));
export const logw = (message) => log(message, LogColor.YELLOW);
export const logt = (message) => log(message, LogColor.TRACE);
export const logm = (message) => log(message, LogColor.MARK);
export const logf = (message) => log(message, LogColor.FATAL);
export const loge = (message) => log(message, LogColor.RED);
export const logg = (message) => log(message, LogColor.C32);
export const logo = (message) => log(message, LogColor.C33);
export const logl = (message) => log(message, LogColor.C34);
export const logn = (message) => log(message, LogColor.C35);
export const logd = (message) => log(message, LogColor.C36);
export const logh = (message) => log(message, LogColor.C96);
export const logz = (message) => log(message, LogColor.C90);
const LOG_TO = LogRedirect.CMD;
const LOG_COUNT_MAX = 20;
export function log(message, type = LogColor.WHITE, filter = false) {
    if (LOG_TO == LogRedirect.NOP)
        return;
    if (filter && !filterDuplicateOBJ(message, LOG_COUNT_MAX))
        return;
    switch (LOG_TO) {
        case LogRedirect.CMD:
            switch (type) {
                case LogColor.WHITE:
                    console.debug(message);
                    break;
                case LogColor.RED:
                    console.error(message);
                    break;
                case LogColor.YELLOW:
                    console.warn(message);
                    break;
                case LogColor.TRACE:
                    console.trace(message);
                    break;
                case LogColor.MARK:
                    console.debug(message);
                    break;
                case LogColor.FATAL:
                    console.error(message);
                    break;
                default:
                    console.log(`\x1b[${type}m${message}\x1b[0m`);
                    break;
            }
            break;
        case LogRedirect.LOGCAT:
            logcat(message);
            break;
        case LogRedirect.TOAST:
            showToast(message);
            break;
        default:
            console.log(`\x1b[${type}m${message}\x1b[0m`);
            break;
    }
}
export const logcat = (msg) => {
    Java.perform(() => {
        const jstr = Java.use("java.lang.String");
        Java.use("android.util.Log").d(jstr.$new("ZZZ"), jstr.$new(msg));
    });
};
const showToast = (message) => {
    Java.perform(() => {
        let Toast = Java.use("android.widget.Toast");
        let context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
        // .overload('android.content.Context', 'java.lang.CharSequence', 'int')
        Java.scheduleOnMainThread(() => Toast.makeText(context, Java.use("java.lang.String").$new(message), 1).show());
    });
};
var nameCountMap = new Map();
globalThis.filterDuplicateOBJ = (objstr, maxCount = 10) => {
    let count = nameCountMap.get(objstr.toString());
    if (count == undefined)
        count = 0;
    if (count < maxCount) {
        nameCountMap.set(objstr.toString(), count + 1);
        return true;
    }
    return false;
};
globalThis.logd = logd;
globalThis.loge = console.error;
globalThis.logw = console.warn;
globalThis.logi = console.info;
✄
{"version":3,"file":"ArtParser.js","sourceRoot":"C:/Users/admin/Desktop/git_project/FridaDebugger/","sources":["agent/parser/ArtParser.ts"],"names":[],"mappings":"AAAA,OAAO,EAAE,UAAU,EAAE,MAAM,iBAAiB,CAAA;AAE5C,MAAM,OAAO,SAAU,SAAQ,UAAU;IAErC,IAAI,CAAC,MAAqB;QACtB,IAAI,CAAC,MAAM,GAAG,MAAM,CAAA;IACxB,CAAC;IAED,WAAW;QACP,OAAO,IAAI,CAAC,MAAM,CAAA;IACtB,CAAC;IAED,QAAQ;QACJ,MAAM;QACN,OAAO,EAAE,CAAA;IACb,CAAC;CACJ;AAED,OAAO,CAAC,GAAG,CAAC,UAAU,EAAE,WAAW,EAAE,SAAS,CAAC,CAAA"}
✄
import { ParserBase } from "./ParserBase.js";
export class ArtParser extends ParserBase {
    from(handle) {
        this.handle = handle;
    }
    asArtMethod() {
        return this.handle;
    }
    asString() {
        //todo
        return '';
    }
}
Reflect.set(globalThis, "ArtParser", ArtParser);
✄
{"version":3,"file":"DynamicParser.js","sourceRoot":"C:/Users/admin/Desktop/git_project/FridaDebugger/","sources":["agent/parser/DynamicParser.ts"],"names":[],"mappings":"AAAA,OAAO,EAAE,UAAU,EAAE,MAAM,iBAAiB,CAAA;AAE5C,MAAM,OAAO,aAAc,SAAQ,UAAU;IAEzC,gBAA0B,KAAK,EAAE,CAAA,CAAC,CAAC;CAGtC;AAED,OAAO,CAAC,GAAG,CAAC,UAAU,EAAE,eAAe,EAAE,aAAa,CAAC,CAAA"}
✄
import { ParserBase } from "./ParserBase.js";
export class DynamicParser extends ParserBase {
    constructor() { super(); }
}
Reflect.set(globalThis, "DynamicParser", DynamicParser);
✄
{"version":3,"file":"Il2cppParser.js","sourceRoot":"C:/Users/admin/Desktop/git_project/FridaDebugger/","sources":["agent/parser/Il2cppParser.ts"],"names":[],"mappings":"AAAA,OAAO,EAAE,UAAU,EAAE,MAAM,iBAAiB,CAAA;AAE5C,MAAM,OAAO,YAAa,SAAQ,UAAU;CAoC3C;AAED,kDAAkD;AAElD,IAAI;AAEJ,iDAAiD;AAEjD,IAAI;AAEJ,OAAO,CAAC,GAAG,CAAC,UAAU,EAAE,cAAc,EAAE,YAAY,CAAC,CAAA"}
✄
import { ParserBase } from "./ParserBase.js";
export class Il2cppParser extends ParserBase {
}
// export class GameObject extends Il2Cpp.Object {
// }
// export class Transform extends Il2Cpp.Object {
// }
Reflect.set(globalThis, "Il2cppParser", Il2cppParser);
✄
{"version":3,"file":"ParserBase.js","sourceRoot":"C:/Users/admin/Desktop/git_project/FridaDebugger/","sources":["agent/parser/ParserBase.ts"],"names":[],"mappings":"AAAA,+BAA+B;AAE/B,MAAM,OAAgB,UAAU;IAElB,MAAM,GAAkB,IAAI,CAAA;IAEtC,gBAA0B,CAAC;IAE3B,IAAI,CAAC,MAAqB;QACtB,IAAI,CAAC,MAAM,GAAG,MAAM,CAAA;IACxB,CAAC;IAED,QAAQ;QACJ,OAAO,IAAI,CAAC,WAAW,CAAC,IAAI,CAAA;IAChC,CAAC;CAEJ"}
✄
// import 'frida-il2cpp-bridge'
export class ParserBase {
    handle = NULL;
    constructor() { }
    from(handle) {
        this.handle = handle;
    }
    toString() {
        return this.constructor.name;
    }
}
✄
{"version":3,"file":"StringParser.js","sourceRoot":"C:/Users/admin/Desktop/git_project/FridaDebugger/","sources":["agent/parser/StringParser.ts"],"names":[],"mappings":"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"}
✄
import { ParserBase } from "./ParserBase.js";
export class StringParser extends ParserBase {
    asU16String() {
        return this.handle.readUtf16String();
    }
    asU8String() {
        return this.handle.readUtf8String();
    }
    asStdSting() {
        return new StdString(this.handle).toString();
    }
    asCString() {
        return this.handle.readCString();
    }
    asUnityString() {
        // return new Il2Cpp.String(this.handle).content
        return '';
    }
}
Reflect.set(globalThis, "StringParser", StringParser);
export class StdString {
    static STD_STRING_SIZE = 3 * Process.pointerSize;
    handle;
    constructor(mPtr = Memory.alloc(StdString.STD_STRING_SIZE)) {
        this.handle = mPtr;
    }
    dispose() {
        const [data, isTiny] = this._getData();
        if (!isTiny)
            Java.api.$delete(data);
    }
    static fromPointer(ptrs) {
        return StdString.fromPointers([ptrs, ptrs.add(Process.pointerSize), ptrs.add(Process.pointerSize * 2)]);
    }
    static fromPointers(ptrs) {
        if (ptrs.length != 3)
            return '';
        return StdString.fromPointersRetInstance(ptrs).disposeToString();
    }
    static from(pointer) {
        try {
            return pointer.add(Process.pointerSize * 2).readCString();
        }
        catch (error) {
            // LOGE("StdString.from ERROR" + error)
            return 'ERROR';
        }
    }
    static fromPointersRetInstance(ptrs) {
        if (ptrs.length != 3)
            return new StdString();
        const stdString = new StdString();
        stdString.handle.writePointer(ptrs[0]);
        stdString.handle.add(Process.pointerSize).writePointer(ptrs[1]);
        stdString.handle.add(2 * Process.pointerSize).writePointer(ptrs[2]);
        return stdString;
    }
    disposeToString() {
        const result = this.toString();
        this.dispose();
        return result;
    }
    toString() {
        try {
            const data = this._getData()[0];
            return data.readUtf8String();
        }
        catch (error) {
            return StdString.from(this.handle.add(Process.pointerSize * 2));
        }
    }
    _getData() {
        const str = this.handle;
        const isTiny = (str.readU8() & 1) === 0;
        const data = isTiny ? str.add(1) : str.add(2 * Process.pointerSize).readPointer();
        return [data, isTiny];
    }
}
Reflect.set(globalThis, 'StdString', StdString);
✄
{"version":3,"file":"StructParser.js","sourceRoot":"C:/Users/admin/Desktop/git_project/FridaDebugger/","sources":["agent/parser/StructParser.ts"],"names":[],"mappings":"AAAA,OAAO,EAAE,UAAU,EAAE,MAAM,iBAAiB,CAAA;AAE5C,MAAM,OAAO,YAAa,SAAQ,UAAU;IAExC,gBAA0B,KAAK,EAAE,CAAA,CAAC,CAAC;IAEnC,SAAS,CAAC,MAAc;QACpB,MAAM,GAAG,GAAG,IAAI,OAAO,CAAC,MAAM,CAAC,CAAA;QAC/B,MAAM;QAEN,OAAO,EAAE,CAAA;IACb,CAAC;CACJ;AAED,OAAO,CAAC,GAAG,CAAC,UAAU,EAAE,cAAc,EAAE,YAAY,CAAC,CAAA"}
✄
import { ParserBase } from "./ParserBase.js";
export class StructParser extends ParserBase {
    constructor() { super(); }
    asCStruct(c_code) {
        const cmd = new CModule(c_code);
        //todo
        return '';
    }
}
Reflect.set(globalThis, "StructParser", StructParser);
✄
{"version":3,"file":"SymbolParser.js","sourceRoot":"C:/Users/admin/Desktop/git_project/FridaDebugger/","sources":["agent/parser/SymbolParser.ts"],"names":[],"mappings":"AAAA,OAAO,EAAE,UAAU,EAAE,MAAM,iBAAiB,CAAA;AAE5C,MAAM,OAAO,YAAa,SAAQ,UAAU;IAExC,gBAA0B,KAAK,EAAE,CAAA,CAAC,CAAC;IAEnC,aAAa;QACT,OAAO,WAAW,CAAC,WAAW,CAAC,IAAI,CAAC,MAAM,CAAC,CAAA;IAC/C,CAAC;IAED,WAAW,CAAC,GAA+B;QACvC,OAAO,GAAG,CAAC,GAAG,CAAC,IAAI,CAAC,MAAM,CAAC,IAAI,EAAE,CAAA;IACrC,CAAC;CACJ;AAED,OAAO,CAAC,GAAG,CAAC,UAAU,EAAE,cAAc,EAAE,YAAY,CAAC,CAAA"}
✄
import { ParserBase } from "./ParserBase.js";
export class SymbolParser extends ParserBase {
    constructor() { super(); }
    asDebugSymbol() {
        return DebugSymbol.fromAddress(this.handle);
    }
    asMapString(map) {
        return map.get(this.handle) || '';
    }
}
Reflect.set(globalThis, "SymbolParser", SymbolParser);
✄
{"version":3,"file":"include.js","sourceRoot":"C:/Users/admin/Desktop/git_project/FridaDebugger/","sources":["agent/parser/include.ts"],"names":[],"mappings":"AAAA,OAAO,iBAAiB,CAAA;AACxB,OAAO,gBAAgB,CAAA;AACvB,OAAO,oBAAoB,CAAA;AAC3B,OAAO,mBAAmB,CAAA;AAC1B,OAAO,mBAAmB,CAAA;AAC1B,OAAO,mBAAmB,CAAA;AAC1B,OAAO,mBAAmB,CAAA"}
✄
import './ParserBase.js';
import './ArtParser.js';
import './DynamicParser.js';
import './SymbolParser.js';
import './StructParser.js';
import './Il2cppParser.js';
import './StringParser.js';
✄
{"version":3,"file":"include.js","sourceRoot":"C:/Users/admin/Desktop/git_project/FridaDebugger/","sources":["agent/plugins/LIEF/include.ts"],"names":[],"mappings":""}
✄
export {};
✄
{"version":3,"file":"ContextParser.js","sourceRoot":"C:/Users/admin/Desktop/git_project/FridaDebugger/","sources":["agent/plugins/QBDI/ContextParser.ts"],"names":[],"mappings":"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"}
✄
import { logd } from "../../logger.js";
export class ContextParser {
    // saved src context
    contextInfo = [];
    constructor(contextInfo) {
        this.contextInfo = contextInfo;
    }
    get contextCount() {
        return this.contextInfo.length;
    }
    get SpOffset_Arr() {
        return this.contextInfo.map(item => item.spOffset);
    }
    get Address_Arr() {
        return this.contextInfo.map(item => ptr(item.inst.address));
    }
    get Context_Arr() {
        return this.contextInfo.map(item => item.context);
    }
    get enterItem() {
        return this.contextInfo.filter((value, index, array) => {
            return (index != 0) && value.spOffset > array[index - 1].spOffset;
        }).map((_value, index, array) => {
            return array[index - 1];
        });
    }
    get enterAddress() {
        return this.enterItem.map(item => ptr(item.inst.address));
    }
    // Indentation of function calls
    showIndentation = (indent = '  ') => {
        let indentationTimes = 0;
        let indentation = '';
        for (let i = 0; i < this.contextCount; i++) {
            const current = this.contextInfo[i];
            const last = i > 0 ? this.contextInfo[i - 1] : null;
            let showDeep;
            if (current.spOffset > (last ? last.spOffset : ptr(0))) {
                indentation = getIndentation(++indentationTimes, indent);
                showDeep = true;
            }
            else if (current.spOffset < (last ? last.spOffset : ptr(0))) {
                indentation = getIndentation(--indentationTimes, indent);
                showDeep = true;
            }
            else {
                showDeep = false;
            }
            const indentationTimesStr = showDeep ? `-> ${indentationTimes}` : ' '.repeat(`-> ${indentationTimes}`.length);
            logd(`${indentation} ${indentationTimesStr} | ${current.spOffset} | ${ptr(current.inst.address)} | ${current.inst.disassembly}`);
        }
        function getIndentation(times, indent) {
            return indent.repeat(times);
        }
    };
    getCalledSimbolList = () => {
        return this.contextInfo
            .map(item => DebugSymbol.fromAddress(ptr(item.inst.address)).name)
            .filter(item => !item.includes('0x'));
    };
}
Reflect.set(globalThis, 'ContextParser', ContextParser);
✄
{"version":3,"file":"QBDIMain.js","sourceRoot":"C:/Users/admin/Desktop/git_project/FridaDebugger/","sources":["agent/plugins/QBDI/QBDIMain.ts"],"names":[],"mappings":"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"}
✄
import { VM, VMAction, CallbackPriority, VMError, InstPosition, SyncDirection } from './arm64-v8a/share/qbdiAARCH64/frida-qbdi.js';
import { ContextItem, ExtraInfo } from './StructInfo.js';
import { logd, logz } from '../../logger.js';
import { ContextParser } from './ContextParser.js';
class QBDIManager {
    static StackSize = 0x1000 * 10;
    static vm;
    static state;
    static stack = NULL;
    static baseSP = NULL;
    static extraInfo = new ExtraInfo();
    static contextInfo = [];
    static initQBDI = (size = QBDIManager.StackSize) => {
        // fakeStackCheck()
        QBDIManager.vm = new VM();
        QBDIManager.state = QBDIManager.vm.getGPRState();
        QBDIManager.stack = QBDIManager.vm.allocateVirtualStack(QBDIManager.state, size);
        QBDIManager.baseSP = QBDIManager.state.getRegister("SP");
        if (QBDIManager.stack == NULL)
            throw new Error("allocateVirtualStack failed");
        logd(`INIT QBDI VM -> Stack: ${QBDIManager.stack} | SP: ${QBDIManager.baseSP}`);
        QBDIManager.vm.clearAllCache();
        QBDIManager.extraInfo.reSet();
        QBDIManager.contextInfo = [];
    };
    static default_icbk = function (vm, gpr, _fpr, _data) {
        const data = _data;
        const inst = vm.getInstAnalysis();
        const lastAddress = data.lastAddress;
        if (lastAddress.isNull())
            QBDIManager.baseSP = gpr.getRegister("SP");
        const index = data.index;
        const startTime_ICBK = data.startTime;
        const currentAddress = ptr(inst.address);
        const custTime = index == 0 ? 0 : Date.now() - startTime_ICBK;
        const preText = `[ ${index.toString().padEnd(3, ' ')} | ${custTime} ms ]`.padEnd(18, ' ');
        if (startTime_ICBK === 0)
            data.setStartTimeNow();
        // record
        const spOffset = QBDIManager.baseSP.sub(gpr.getRegister("SP"));
        QBDIManager.contextInfo.push(new ContextItem(inst, spOffset, gpr));
        // logz(`${preText} ${asmOffset.toString().padEnd(8, ' ')} ${currentAddress}| INSC: ${data.runInstCount.toString().padEnd(7, ' ')} | ${inst.disassembly}`)
        logz(`${preText} ${spOffset.toString().padEnd(8, ' ')} ${currentAddress} | ${inst.disassembly}`);
        ++data.runInstCount;
        ++data.index;
        data.lastAddress = currentAddress;
        return VMAction.CONTINUE;
    };
    static traceFunction = (mPtr, icbk_function = QBDIManager.default_icbk, argsCount = 4, onece = true) => {
        if (mPtr == null)
            throw new Error("traceFunction : mPtr is null");
        let targetFunctionPtr = NULL;
        if (mPtr instanceof NativePointer)
            targetFunctionPtr = mPtr;
        if (typeof mPtr == "string" || typeof mPtr == "number")
            targetFunctionPtr = ptr(mPtr);
        QBDIManager.initQBDI();
        let syncRegs = false; // not impl
        let srcFunc = new NativeFunction(targetFunctionPtr, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);
        const callback = new NativeCallback(function (_arg0, _arg1, _arg2, _arg3, _arg4) {
            let args = [];
            for (let i = 0; i < argsCount; i++)
                args.push(arguments[i]);
            logd(`\ncalled ${targetFunctionPtr} | args => ${args.join(' ')}`);
            // let ret: NativePointer = srcFunc.apply(null, arguments as any)
            Interceptor.revert(targetFunctionPtr);
            Interceptor.flush();
            if (syncRegs)
                QBDIManager.state.synchronizeContext(this.context, SyncDirection.FRIDA_TO_QBDI);
            // trace range
            // QBDIManager.vm.addInstrumentedModuleFromAddr(targetFunctionPtr)
            QBDIManager.vm.addInstrumentedRange(targetFunctionPtr, targetFunctionPtr.add(0x200));
            let icbk = QBDIManager.vm.newInstCallback(icbk_function);
            ++QBDIManager.extraInfo.index;
            QBDIManager.extraInfo.setStartTimeNow();
            let status = QBDIManager.vm.addCodeCB(InstPosition.PREINST, icbk, QBDIManager.extraInfo, CallbackPriority.PRIORITY_DEFAULT);
            if (status == VMError.INVALID_EVENTID)
                throw new Error("addCodeCB failed");
            logd(`VM START | CALL -> ${srcFunc} | at ${new Date().toLocaleTimeString()}`);
            const vm_retval = Module.findBaseAddress("libil2cpp.so") ?
                QBDIManager.vm.call(srcFunc, args) :
                Il2Cpp.perform(() => {
                    return QBDIManager.vm.call(srcFunc, args);
                });
            if (syncRegs)
                QBDIManager.state.synchronizeContext(this.context, SyncDirection.QBDI_TO_FRIDA);
            logd(`VM STOP | RET => ${vm_retval}`);
            if (!onece)
                Interceptor.replace(targetFunctionPtr, callback);
            else
                Interceptor.detachAll();
            return vm_retval;
        }, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);
        try {
            Interceptor.replace(targetFunctionPtr, callback);
        }
        catch (error) {
            if (error.message.includes("already replaced")) {
                Interceptor.revert(targetFunctionPtr);
                Interceptor.flush();
                Interceptor.replace(targetFunctionPtr, callback);
            }
            else
                throw error;
        }
    };
    static getContextParser = () => {
        return new ContextParser(QBDIManager.contextInfo);
    };
    static showIndentation = () => {
        QBDIManager.getContextParser().showIndentation();
    };
}
globalThis.traceFunction = QBDIManager.traceFunction;
globalThis.getContextParser = QBDIManager.getContextParser;
Reflect.set(globalThis, 'QBDIManager', QBDIManager);
✄
{"version":3,"file":"StructInfo.js","sourceRoot":"C:/Users/admin/Desktop/git_project/FridaDebugger/","sources":["agent/plugins/QBDI/StructInfo.ts"],"names":[],"mappings":"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"}
✄
export class ExtraInfo {
    handle;
    index_ptr = NULL; // int64_t 记录 index
    startTime_ptr = NULL; // int64_t 开始时间
    runInstCount_ptr = NULL; // int64_t 记录 run inst count
    lastAddress_ptr = NULL; // int64_t 记录上一次的地址
    firstTime = 0;
    constructor() {
        this.handle = Memory.alloc(Process.pointerSize * 4);
        this.index_ptr = this.handle;
        this.startTime_ptr = this.index_ptr.add(Process.pointerSize);
        this.runInstCount_ptr = this.startTime_ptr.add(Process.pointerSize);
        this.lastAddress_ptr = this.runInstCount_ptr.add(Process.pointerSize);
        this.reSet();
    }
    reSet = () => {
        this.index_ptr.writePointer(NULL);
        this.startTime_ptr.writePointer(NULL);
        this.runInstCount_ptr.writePointer(NULL);
        this.lastAddress_ptr.writePointer(NULL);
    };
    get index() {
        return this.index_ptr.readPointer().toUInt32();
    }
    set index(value) {
        this.index_ptr.writePointer(ptr(value));
    }
    get startTime() {
        return this.startTime_ptr.readU64().toNumber();
    }
    set startTime(value) {
        if (this.firstTime == 0)
            this.firstTime = value;
        this.startTime_ptr.writeU64(value);
    }
    setStartTimeNow = () => { this.startTime = Date.now(); };
    get runInstCount() {
        return this.runInstCount_ptr.readPointer().toUInt32();
    }
    set runInstCount(value) {
        this.runInstCount_ptr.writePointer(ptr(value));
    }
    get lastAddress() {
        return this.lastAddress_ptr.readPointer();
    }
    set lastAddress(value) {
        this.lastAddress_ptr.writePointer(value);
    }
}
export class ContextItem {
    inst;
    spOffset;
    context;
    constructor(inst, spOffset, context) {
        this.inst = inst;
        this.spOffset = spOffset;
        this.context = context;
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
    address;
    affectControlFlow;
    condition;
    cpuMode;
    disassembly;
    flagsAccess;
    instSize;
    isBranch;
    isCall;
    isCompare;
    isMoveImm;
    isPredicable;
    isReturn;
    loadSize;
    mayLoad;
    mayStore;
    mnemonic;
    module;
    operands;
    storeSize;
    symbol;
    symbolOffset;
}
✄
{"version":3,"file":"frida-qbdi.js","sourceRoot":"C:/Users/admin/Desktop/git_project/FridaDebugger/","sources":["agent/plugins/QBDI/arm64-v8a/share/qbdiAARCH64/frida-qbdi.js"],"names":[],"mappings":"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"}
✄
/*
 * Usage:
 * $ frida -n Twitter -l frida-qbdi.js
 *
 */
export var QBDI_MAJOR = 0;
export var QBDI_MINOR = 10;
export var QBDI_PATCH = 0;
/**
 * Minimum version of QBDI to use Frida bindings
 */
export var QBDI_MINIMUM_VERSION = (QBDI_MAJOR << 16) | (QBDI_MINOR << 8) | QBDI_PATCH;
if (typeof Duktape === 'object') {
    // Warn about duktape runtime (except on iOS...)
    if (Process.platform !== 'darwin' || Process.arch.indexOf("arm") !== 0) {
        console.warn("[!] Warning: using duktape runtime is much slower...");
        console.warn("    => Frida --enable-jit option should be used");
    }
}
// Provide a generic and "safe" (no exceptions if symbol is not found) way to load
// a library and bind/create a native function
class Binder {
    constructor() { }
    findLibrary(lib, paths) {
        if (lib === undefined) {
            return undefined;
        }
        var cpath = undefined;
        if (paths !== undefined) {
            var cnt = paths.length;
            var found = false;
            // try to find our library
            for (var i = 0; i < cnt; i++) {
                cpath = paths[i] + lib;
                // use Frida file interface to test if file exists...
                try {
                    var fp = new File(cpath, "rb");
                    fp.close();
                    found = true;
                    break;
                }
                catch (e) {
                    continue;
                }
            }
            if (!found) {
                return undefined;
            }
        }
        else {
            cpath = lib;
        }
        return cpath;
    }
    safeNativeFunction(cbk, ret, args) {
        var e = cbk();
        if (!e) {
            return undefined;
        }
        return new NativeFunction(e, ret, args);
    }
    load(lib, paths) {
        var cpath = this.findLibrary(lib, paths);
        if (cpath === undefined) {
            var errmsg = lib + ' library not found...';
            console.error(errmsg);
            throw new Error(errmsg);
        }
        // load library
        var handle = System.dlopen(cpath);
        if (handle.isNull()) {
            var errmsg = 'Failed to load ' + cpath + ' (' + System.dlerror() + ')';
            console.error(errmsg);
            throw new Error(errmsg);
        }
        return cpath;
    }
    bind(name, ret, args) {
        return this.safeNativeFunction(function () {
            return Module.findExportByName(null, name);
        }, ret, args);
    }
}
class QBDIBinder extends Binder {
    /**
     * QBDI library name
     */
    get QBDI_LIB() {
        return {
            'linux': 'libQBDI_64.so',
            'darwin': 'libQBDI.dylib',
            'windows': 'QBDI.dll',
        }[Process.platform];
    }
    // paths where QBDI library may be
    get QBDI_PATHS() {
        return [
            // UNIX default paths
            '/usr/lib/',
            '/usr/local/lib/',
            // advised Android path
            '/data/local/tmp/',
            // in case of a local archive
            './',
            './lib',
            // Windows default path
            'C:\\Program Files\\QBDI ' + QBDI_MAJOR + '.' + QBDI_MINOR + '.' + QBDI_PATCH + '\\lib\\'
        ];
    }
    bind(name, ret, args) {
        var libpath = this.QBDI_LIB;
        return this.safeNativeFunction(function () {
            return Module.findExportByName(libpath, name);
        }, ret, args);
    }
    load() {
        return super.load(this.QBDI_LIB, this.QBDI_PATHS);
    }
}
var _binder = new Binder();
var _qbdibinder = new QBDIBinder();
// Needed to load QBDI
var System_C = Object.freeze({
    LoadLibraryEx: _binder.bind('LoadLibraryExA', 'pointer', ['pointer', 'int', 'int']),
    GetLastError: _binder.bind('GetLastError', 'int', []),
    dlopen: _binder.bind('dlopen', 'pointer', ['pointer', 'int']),
    dlerror: _binder.bind('dlerror', 'pointer', []),
    free: _binder.bind('free', 'void', ['pointer']),
});
var System = Object.freeze({
    dlerror: function () {
        if (Process.platform === "windows") {
            var val = System_C.GetLastError();
            if (val === undefined) {
                return undefined;
            }
            return val.toString();
        }
        var strPtr = System_C.dlerror();
        return Memory.readCString(strPtr);
    },
    dlopen: function (library) {
        var RTLD_LOCAL = 0x0;
        var RTLD_LAZY = 0x1;
        var path = Memory.allocUtf8String(library);
        if (Process.platform === "windows") {
            return System_C.LoadLibraryEx(path, 0, 0);
        }
        return System_C.dlopen(path, RTLD_LOCAL | RTLD_LAZY);
    },
    free: function (ptr) {
        System_C.free(ptr);
    }
});
/**
 * Fullpath of the QBDI library
 */
// Load QBDI library
var QBDI_LIB_FULLPATH = _qbdibinder.load();
// Define rword type and interfaces
/**
 * An alias to Frida uint type with the size of general registers (**uint64** or **uint32**)
 */
export var rword = Process.pointerSize === 8 ? 'uint64' : 'uint32';
Memory.readRword = Process.pointerSize === 8 ? Memory.readU64 : Memory.readU32;
Memory.writeRword = Process.pointerSize === 8 ? Memory.writeU64 : Memory.writeU32;
// Convert a number to its register-sized representation
/**
 * Convert a NativePointer into a type with the size of a register (``Number`` or ``UInt64``).
 */
NativePointer.prototype.toRword = function () {
    // Nothing better really ?
    if (Process.pointerSize === 8) {
        return uint64("0x" + this.toString(16));
    }
    return parseInt(this.toString(16), 16);
};
/**
 * Convert a number into a type with the size of a register (``Number`` or ``UInt64``).
 * Can't be used for numbers > 32 bits, would cause weird results due to IEEE-754.
 */
Number.prototype.toRword = function () {
    if (this > 0x100000000) {
        throw new TypeError('For integer > 32 bits, please use Frida uint64 type.');
    }
    if (Process.pointerSize === 8) {
        return uint64(this);
    }
    return this;
};
/**
 * An identity function (returning the same ``UInt64`` object).
 * It exists only to provide a unified **toRword** interface.
 */
UInt64.prototype.toRword = function () {
    return this;
};
// Some helpers
String.prototype.leftPad = function (paddingValue, paddingLength) {
    paddingLength = paddingLength || paddingValue.length;
    if (paddingLength < this.length) {
        return String(this);
    }
    return String(paddingValue + this).slice(-paddingLength);
};
/**
 * Convert a String into a type with the size of a register (``Number`` or ``UInt64``).
 */
String.prototype.toRword = function () {
    return ptr(this).toRword();
};
/**
 * This function is used to pretty print a pointer, padded with 0 to the size of a register.
 *
 * @param ptr Pointer you want to pad
 *
 * @return pointer value as padded string (ex: "0x00004242")
 */
export function hexPointer(ptr) {
    return ptr.toString(16).leftPad("0000000000000000", Process.pointerSize * 2);
}
//
var QBDI_C = Object.freeze({
    // VM
    initVM: _qbdibinder.bind('qbdi_initVM', 'void', ['pointer', 'pointer', 'pointer', rword]),
    terminateVM: _qbdibinder.bind('qbdi_terminateVM', 'void', ['pointer']),
    getOptions: _qbdibinder.bind('qbdi_getOptions', rword, ['pointer']),
    setOptions: _qbdibinder.bind('qbdi_setOptions', 'void', ['pointer', rword]),
    addInstrumentedRange: _qbdibinder.bind('qbdi_addInstrumentedRange', 'void', ['pointer', rword, rword]),
    addInstrumentedModule: _qbdibinder.bind('qbdi_addInstrumentedModule', 'uchar', ['pointer', 'pointer']),
    addInstrumentedModuleFromAddr: _qbdibinder.bind('qbdi_addInstrumentedModuleFromAddr', 'uchar', ['pointer', rword]),
    instrumentAllExecutableMaps: _qbdibinder.bind('qbdi_instrumentAllExecutableMaps', 'uchar', ['pointer']),
    removeInstrumentedRange: _qbdibinder.bind('qbdi_removeInstrumentedRange', 'void', ['pointer', rword, rword]),
    removeInstrumentedModule: _qbdibinder.bind('qbdi_removeInstrumentedModule', 'uchar', ['pointer', 'pointer']),
    removeInstrumentedModuleFromAddr: _qbdibinder.bind('qbdi_removeInstrumentedModuleFromAddr', 'uchar', ['pointer', rword]),
    removeAllInstrumentedRanges: _qbdibinder.bind('qbdi_removeAllInstrumentedRanges', 'void', ['pointer']),
    run: _qbdibinder.bind('qbdi_run', 'uchar', ['pointer', rword, rword]),
    call: _qbdibinder.bind('qbdi_call', 'uchar', ['pointer', 'pointer', rword, 'uint32',
        rword, rword, rword, rword, rword, rword, rword, rword, rword, rword]),
    getGPRState: _qbdibinder.bind('qbdi_getGPRState', 'pointer', ['pointer']),
    getFPRState: _qbdibinder.bind('qbdi_getFPRState', 'pointer', ['pointer']),
    setGPRState: _qbdibinder.bind('qbdi_setGPRState', 'void', ['pointer', 'pointer']),
    setFPRState: _qbdibinder.bind('qbdi_setFPRState', 'void', ['pointer', 'pointer']),
    addMnemonicCB: _qbdibinder.bind('qbdi_addMnemonicCB', 'uint32', ['pointer', 'pointer', 'uint32', 'pointer', 'pointer', 'int32']),
    addMemAccessCB: _qbdibinder.bind('qbdi_addMemAccessCB', 'uint32', ['pointer', 'uint32', 'pointer', 'pointer', 'int32']),
    addInstrRule: _qbdibinder.bind('qbdi_addInstrRule', 'uint32', ['pointer', 'pointer', 'uint32', 'pointer']),
    addInstrRuleRange: _qbdibinder.bind('qbdi_addInstrRuleRange', 'uint32', ['pointer', rword, rword, 'pointer', 'uint32', 'pointer']),
    addInstrRuleData: _qbdibinder.bind('qbdi_addInstrRuleData', 'void', ['pointer', 'uint32', 'pointer', 'pointer', 'int32']),
    addMemAddrCB: _qbdibinder.bind('qbdi_addMemAddrCB', 'uint32', ['pointer', rword, 'uint32', 'pointer', 'pointer']),
    addMemRangeCB: _qbdibinder.bind('qbdi_addMemRangeCB', 'uint32', ['pointer', rword, rword, 'uint32', 'pointer', 'pointer']),
    addCodeCB: _qbdibinder.bind('qbdi_addCodeCB', 'uint32', ['pointer', 'uint32', 'pointer', 'pointer', 'int32']),
    addCodeAddrCB: _qbdibinder.bind('qbdi_addCodeAddrCB', 'uint32', ['pointer', rword, 'uint32', 'pointer', 'pointer', 'int32']),
    addCodeRangeCB: _qbdibinder.bind('qbdi_addCodeRangeCB', 'uint32', ['pointer', rword, rword, 'uint32', 'pointer', 'pointer', 'int32']),
    addVMEventCB: _qbdibinder.bind('qbdi_addVMEventCB', 'uint32', ['pointer', 'uint32', 'pointer', 'pointer']),
    deleteInstrumentation: _qbdibinder.bind('qbdi_deleteInstrumentation', 'uchar', ['pointer', 'uint32']),
    deleteAllInstrumentations: _qbdibinder.bind('qbdi_deleteAllInstrumentations', 'void', ['pointer']),
    getInstAnalysis: _qbdibinder.bind('qbdi_getInstAnalysis', 'pointer', ['pointer', 'uint32']),
    getCachedInstAnalysis: _qbdibinder.bind('qbdi_getCachedInstAnalysis', 'pointer', ['pointer', rword, 'uint32']),
    recordMemoryAccess: _qbdibinder.bind('qbdi_recordMemoryAccess', 'uchar', ['pointer', 'uint32']),
    getInstMemoryAccess: _qbdibinder.bind('qbdi_getInstMemoryAccess', 'pointer', ['pointer', 'pointer']),
    getBBMemoryAccess: _qbdibinder.bind('qbdi_getBBMemoryAccess', 'pointer', ['pointer', 'pointer']),
    // Memory
    allocateVirtualStack: _qbdibinder.bind('qbdi_allocateVirtualStack', 'uchar', ['pointer', 'uint32', 'pointer']),
    alignedAlloc: _qbdibinder.bind('qbdi_alignedAlloc', 'pointer', ['uint32', 'uint32']),
    alignedFree: _qbdibinder.bind('qbdi_alignedFree', 'void', ['pointer']),
    simulateCall: _qbdibinder.bind('qbdi_simulateCall', 'void', ['pointer', rword, 'uint32',
        rword, rword, rword, rword, rword, rword, rword, rword, rword, rword]),
    getModuleNames: _qbdibinder.bind('qbdi_getModuleNames', 'pointer', ['pointer']),
    // Logs
    setLogPriority: _qbdibinder.bind('qbdi_setLogPriority', 'void', ['uint32']),
    // Helpers
    getVersion: _qbdibinder.bind('qbdi_getVersion', 'pointer', ['pointer']),
    getGPR: _qbdibinder.bind('qbdi_getGPR', rword, ['pointer', 'uint32']),
    setGPR: _qbdibinder.bind('qbdi_setGPR', 'void', ['pointer', 'uint32', rword]),
    getMemoryAccessStructDesc: _qbdibinder.bind('qbdi_getMemoryAccessStructDesc', 'pointer', []),
    getVMStateStructDesc: _qbdibinder.bind('qbdi_getVMStateStructDesc', 'pointer', []),
    getOperandAnalysisStructDesc: _qbdibinder.bind('qbdi_getOperandAnalysisStructDesc', 'pointer', []),
    getInstAnalysisStructDesc: _qbdibinder.bind('qbdi_getInstAnalysisStructDesc', 'pointer', []),
    precacheBasicBlock: _qbdibinder.bind('qbdi_precacheBasicBlock', 'uchar', ['pointer', rword]),
    clearCache: _qbdibinder.bind('qbdi_clearCache', 'void', ['pointer', rword, rword]),
    clearAllCache: _qbdibinder.bind('qbdi_clearAllCache', 'void', ['pointer']),
});
// Init some globals
if (Process.arch === 'x64') {
    var GPR_NAMES_ = ["RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "RBP", "RSP", "RIP", "EFLAGS", "FS", "GS"];
    var REG_RETURN_ = "RAX";
    var REG_PC_ = "RIP";
    var REG_SP_ = "RSP";
}
else if (Process.arch === 'arm64') {
    var GPR_NAMES_ = ["X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7", "X8", "X9", "X10", "X11", "X12", "X13", "X14", "X15", "X16", "X17", "X18", "X19", "X20", "X21", "X22", "X23", "X24", "X25", "X26", "X27", "X28", "FP", "LR", "SP", "NZCV", "PC"];
    var REG_RETURN_ = "X0";
    var REG_PC_ = "PC";
    var REG_SP_ = "SP";
}
else if (Process.arch === 'arm') {
    var GPR_NAMES_ = ["R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9", "R10", "R12", "FP", "SP", "LR", "PC", "CPSR"];
    var REG_RETURN_ = "R0";
    var REG_PC_ = "PC";
    var REG_SP_ = "SP";
}
else if (Process.arch === 'ia32') {
    var GPR_NAMES_ = ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP", "EFLAGS"];
    var REG_RETURN_ = "EAX";
    var REG_PC_ = "EIP";
    var REG_SP_ = "ESP";
}
/**
 * An array holding register names.
 */
export var GPR_NAMES = GPR_NAMES_;
/**
 * A constant string representing the register carrying the return value of a function.
 */
export var REG_RETURN = REG_RETURN_;
/**
 * String of the instruction pointer register.
 */
export var REG_PC = REG_PC_;
/**
 * String of the stack pointer register.
 */
export var REG_SP = REG_SP_;
/**
 * Error return by the QBDI VM
 */
export var VMError = Object.freeze({
    /**
     * Returned event is invalid.
     */
    INVALID_EVENTID: 0xffffffff
});
/**
 * Synchronisation direction between Frida and QBDI GPR contexts
 */
export var SyncDirection = {
    /**
     * Constant variable used to synchronize QBDI's context to Frida's.
     *
     * .. warning:: This is currently not supported due to the lack of context updating in Frida.
     */
    QBDI_TO_FRIDA: 0,
    /**
     * Constant variable used to synchronize Frida's context to QBDI's.
     */
    FRIDA_TO_QBDI: 1
};
/**
 * The callback results.
 */
export var VMAction = Object.freeze({
    /**
     * The execution of the basic block continues.
     */
    CONTINUE: 0,
    /**
     * Available only with PREINST InstCallback.  The instruction and the
     * remained PREINST callbacks are skip. The execution continue with the
     * POSTINST instruction.
     *
     * We recommand to used this result with a low priority PREINST callback in
     * order to emulate the instruction without skipping the POSTINST callback.
     */
    SKIP_INST: 1,
    /*!*
     * Available only with InstCallback. The current instruction and the
     * reminding callback (PRE and POST) are skip. The execution continues to
     * the next instruction.
     *
     * For instruction that change the instruction pointer (jump/call/ret),
     * BREAK_TO_VM must be used insted of SKIP.
     *
     * SKIP can break the record of MemoryAccess for the current instruction.
     */
    SKIP_PATCH: 2,
    /**
     * The execution breaks and returns to the VM causing a complete
     * reevaluation of the execution state. A :js:data:`VMAction.BREAK_TO_VM` is
     * needed to ensure that modifications of the Program Counter or the program
     * code are taken into account.
     */
    BREAK_TO_VM: 3,
    /**
     * Stops the execution of the program. This causes the run function to
     * return early.
     */
    STOP: 4
});
/**
 * Position relative to an instruction.
 */
export var InstPosition = Object.freeze({
    /**
     * Positioned **before** the instruction.
     */
    PREINST: 0,
    /**
     * Positioned **after** the instruction.
     */
    POSTINST: 1
});
/**
 * Priority of callback
 */
export var CallbackPriority = Object.freeze({
    /**
     * Default priority for callback.
     */
    PRIORITY_DEFAULT: 0,
    /**
     * Maximum priority if getInstMemoryAccess is used in the callback.
     */
    PRIORITY_MEMACCESS_LIMIT: 0x1000000
});
/**
 * Events triggered by the virtual machine.
 */
export var VMEvent = Object.freeze({
    /**
     * Triggered when the execution enters a sequence.
     */
    SEQUENCE_ENTRY: 1,
    /**
     * Triggered when the execution exits from the current sequence.
     */
    SEQUENCE_EXIT: 1 << 1,
    /**
     * Triggered when the execution enters a basic block.
     */
    BASIC_BLOCK_ENTRY: 1 << 2,
    /**
     * Triggered when the execution exits from the current basic block.
     */
    BASIC_BLOCK_EXIT: 1 << 3,
    /**
     * Triggered when the execution enters a new (~unknown) basic block.
     */
    BASIC_BLOCK_NEW: 1 << 4,
    /**
     * Triggered when the ExecBroker executes an execution transfer.
     */
    EXEC_TRANSFER_CALL: 1 << 5,
    /**
     * Triggered when the ExecBroker returns from an execution transfer.
     */
    EXEC_TRANSFER_RETURN: 1 << 6,
    /**
     * Not implemented.
     */
    SYSCALL_ENTRY: 1 << 7,
    /**
     * Not implemented.
     */
    SYSCALL_EXIT: 1 << 8,
    /**
     * Not implemented.
     */
    SIGNAL: 1 << 9
});
/**
 * Memory access type (read / write / ...)
 */
export var MemoryAccessType = Object.freeze({
    /**
     * Memory read access.
     */
    MEMORY_READ: 1,
    /**
     * Memory write access.
     */
    MEMORY_WRITE: 2,
    /**
     * Memory read/write access.
     */
    MEMORY_READ_WRITE: 3
});
/**
 * Memory access flags
 */
export var MemoryAccessFlags = Object.freeze({
    /**
     * Empty flag.
     */
    MEMORY_NO_FLAGS: 0,
    /**
     * The size of the access isn't known.
     */
    MEMORY_UNKNOWN_SIZE: 1 << 0,
    /**
     * The given size is a minimum size.
     */
    MEMORY_MINIMUM_SIZE: 1 << 1,
    /**
     * The value of the access is unknown or hasn't been retrived.
     */
    MEMORY_UNKNOWN_VALUE: 1 << 2
});
/**
 * Register access type (read / write / rw)
 */
export var RegisterAccessType = Object.freeze({
    /**
     * Register is read.
     */
    REGISTER_READ: 1,
    /**
     * Register is written.
     */
    REGISTER_WRITE: 2,
    /**
     * Register is read/written.
     */
    REGISTER_READ_WRITE: 3
});
/**
 * Instruction Condition
 */
export var ConditionType = Object.freeze({
    /**
     * The instruction is unconditionnal
     */
    CONDITION_NONE: 0x0,
    /**
     * The instruction is always true
     */
    CONDITION_ALWAYS: 0x2,
    /**
     * The instruction is always false
     */
    CONDITION_NEVER: 0x3,
    /**
     * Equals ( '==' )
     */
    CONDITION_EQUALS: 0x4,
    /**
     * Not Equals ( '!=' )
     */
    CONDITION_NOT_EQUALS: 0x5,
    /**
     * Above ( '>' unsigned )
     */
    CONDITION_ABOVE: 0x6,
    /**
     * Below or Equals ( '<=' unsigned )
     */
    CONDITION_BELOW_EQUALS: 0x7,
    /**
     * Above or Equals ( '>=' unsigned )
     */
    CONDITION_ABOVE_EQUALS: 0x8,
    /**
     * Below ( '<' unsigned )
     */
    CONDITION_BELOW: 0x9,
    /**
     * Great ( '>' signed )
     */
    CONDITION_GREAT: 0xa,
    /**
     * Less or Equals ( '<=' signed )
     */
    CONDITION_LESS_EQUALS: 0xb,
    /**
     * Great or Equals ( '>=' signed )
     */
    CONDITION_GREAT_EQUALS: 0xc,
    /**
     * Less ( '<' signed )
     */
    CONDITION_LESS: 0xd,
    /**
     * Even
     */
    CONDITION_EVEN: 0xe,
    /**
     * Odd
     */
    CONDITION_ODD: 0xf,
    /**
     * Overflow
     */
    CONDITION_OVERFLOW: 0x10,
    /**
     * Not Overflow
     */
    CONDITION_NOT_OVERFLOW: 0x11,
    /**
     * Sign
     */
    CONDITION_SIGN: 0x12,
    /**
     * Not Sign
     */
    CONDITION_NOT_SIGN: 0x13
});
/**
 * Register access type (read / write / rw)
 */
export var OperandType = Object.freeze({
    /**
     * Invalid operand.
     */
    OPERAND_INVALID: 0,
    /**
     * Immediate operand.
     */
    OPERAND_IMM: 1,
    /**
     * General purpose register operand.
     */
    OPERAND_GPR: 2,
    /**
     * Predicate special operand.
     */
    OPERAND_PRED: 3,
    /**
     * Float register operand.
     */
    OPERAND_FPR: 4,
    /**
     * Segment or unsupported register operand
     */
    OPERAND_SEG: 5
});
/**
 * Operand flag
 */
export var OperandFlag = Object.freeze({
    /**
     * No flag
     */
    OPERANDFLAG_NONE: 0,
    /**
     * The operand is used to compute an address
     */
    OPERANDFLAG_ADDR: 1 << 0,
    /**
     * The value of the operand is PC relative
     */
    OPERANDFLAG_PCREL: 1 << 1,
    /**
     * The operand role isn't fully defined
     */
    OPERANDFLAG_UNDEFINED_EFFECT: 1 << 2,
    /**
     * The operand is implicit
     */
    OPERANDFLAG_IMPLICIT: 1 << 3
});
/**
 * Properties to retrieve during an instruction analysis.
 */
export var AnalysisType = Object.freeze({
    /**
     * Instruction analysis (address, mnemonic, ...).
     */
    ANALYSIS_INSTRUCTION: 1,
    /**
     * Instruction disassembly.
     */
    ANALYSIS_DISASSEMBLY: 1 << 1,
    /**
     * Instruction operands analysis.
     */
    ANALYSIS_OPERANDS: 1 << 2,
    /**
     * Instruction nearest symbol (and offset).
     */
    ANALYSIS_SYMBOL: 1 << 3
});
/**
 * QBDI VM Options
 */
export var Options = {
    /**
     * Default value
     */
    NO_OPT: 0,
    /**
     * Disable all operation on FPU (SSE, AVX, SIMD).
     * May break the execution if the target use the FPU.
     */
    OPT_DISABLE_FPR: 1 << 0,
    /**
     * Disable context switch optimisation when the target
     * execblock doesn't used FPR.
     */
    OPT_DISABLE_OPTIONAL_FPR: 1 << 1,
};
if (Process.arch === 'x64') {
    /**
     * Used the AT&T syntax for instruction disassembly (for X86 and X86_64)
     */
    Options.OPT_ATT_SYNTAX = 1 << 24;
    /**
     * Enable Backup/Restore of FS/GS segment.
     * This option uses the instructions (RD|WR)(FS|GS)BASE that must be
     * supported by the operating system.
     */
    Options.OPT_ENABLE_FS_GS = 1 << 25;
}
else if (Process.arch === 'ia32') {
    Options.OPT_ATT_SYNTAX = 1 << 24;
}
else if (Process.arch === 'arm64') {
    /**
     * Disable the emulation of the local monitor by QBDI
     */
    Options.OPT_DISABLE_LOCAL_MONITOR = 1 << 24;
    /**
     * Disable pointeur authentication
     */
    Options.OPT_BYPASS_PAUTH = 1 << 25;
    /**
     * Enable BTI on instrumented code
     */
    Options.OPT_ENABLE_BTI = 1 << 26;
}
else if (Process.arch === 'arm') {
    Options.OPT_DISABLE_LOCAL_MONITOR = 1 << 24;
    /**
     * Disable the used of D16-D31 register
     */
    Options.OPT_DISABLE_D16_D31 = 1 << 25;
    /**
     * Change between ARM and Thumb as an ARMv4 CPU
     */
    Options.OPT_ARMv4 = 3 << 26;
    /**
     * Change between ARM and Thumb as an ARMv5T or ARMv6 CPU
     */
    Options.OPT_ARMv5T_6 = 1 << 27;
    /**
     * Change between ARM and Thumb as an ARMv7 CPU (default)
     */
    Options.OPT_ARMv7 = 0;
    Options.OPT_ARM_MASK = 3 << 26;
}
Options = Object.freeze(Options);
export class InstrRuleDataCBK {
    /**
     * Object to define an :js:func:`InstCallback` in an :js:func:`InstrRuleCallback`
     *
     * @param {InstPosition} pos       Relative position of the callback (PreInst / PostInst).
     * @param {InstCallback} cbk       A **native** InstCallback returned by :js:func:`VM.newInstCallback`.
     * @param {Object}       data      User defined data passed to the callback.
     * @param {Int}          priority  The priority of the callback.
     */
    constructor(pos, cbk, data, priority = CallbackPriority.PRIORITY_DEFAULT) {
        this.position = pos;
        this.cbk = cbk;
        this.data = data;
        this.priority = priority;
    }
}
class State {
    constructor(state) {
        if (!NativePointer.prototype.isPrototypeOf(state) || state.isNull()) {
            throw new TypeError('Invalid state pointer');
        }
        this.statePtr = state;
    }
    get ptr() {
        return this.statePtr;
    }
    toRword() {
        return this.statePtr.toRword();
    }
    toString() {
        return this.statePtr.toString();
    }
}
/**
 * General Purpose Register context
 */
export class GPRState extends State {
    _getGPRId(rid) {
        if (typeof (rid) === 'string') {
            rid = GPR_NAMES.indexOf(rid.toUpperCase());
        }
        if (rid < 0 || rid > GPR_NAMES.length) {
            return undefined;
        }
        return rid;
    }
    /**
     * This function is used to get the value of a specific register.
     *
     * @param {String|Number} rid Register (register name or ID can be used e.g : "RAX", "rax", 0)
     *
     * @return GPR value (ex: 0x42)
     */
    getRegister(rid) {
        var rid = this._getGPRId(rid);
        if (rid === null) {
            return undefined;
        }
        return ptr(QBDI_C.getGPR(this.ptr, rid));
    }
    /**
     * This function is used to set the value of a specific register.
     *
     * @param {String|Number} rid   Register (register name or ID can be used e.g : "RAX", "rax", 0)
     * @param {String|Number} value Register value (use **strings** for big integers)
     */
    setRegister(rid, value) {
        var rid = this._getGPRId(rid);
        if (rid !== null) {
            QBDI_C.setGPR(this.ptr, rid, value.toRword());
        }
    }
    /**
     * This function is used to get values of all registers.
     *
     * @return GPRs of current context (ex: \{"RAX":0x42, ...\})
     */
    getRegisters() {
        var regCnt = GPR_NAMES.length;
        var gprs = {};
        for (var i = 0; i < regCnt; i++) {
            gprs[GPR_NAMES[i]] = this.getRegister(i);
        }
        return gprs;
    }
    /**
     * This function is used to set values of all registers.
     *
     * @param gprs Array of register values
     */
    setRegisters(gprs) {
        var regCnt = GPR_NAMES.length;
        for (var i = 0; i < regCnt; i++) {
            this.setRegister(i, gprs[GPR_NAMES[i]]);
        }
    }
    /**
     * This function is used to synchronise a specific register between Frida and QBDI.
     *
     * .. warning:: Currently QBDI_TO_FRIDA is experimental. (E.G : RIP cannot be synchronized)
     *
     * @param                   FridaCtx   Frida context
     * @param {String|Number}   rid        Register (register name or ID can be used e.g : "RAX", "rax", 0)
     * @param {SyncDirection}   direction  Synchronization direction. (:js:data:`FRIDA_TO_QBDI` or :js:data:`QBDI_TO_FRIDA`)
     */
    synchronizeRegister(FridaCtx, rid, direction) {
        if (direction === SyncDirection.FRIDA_TO_QBDI) {
            this.setRegister(rid, FridaCtx[rid.toLowerCase()].toRword());
        }
        else { // FRIDA_TO_QBDI
            FridaCtx[rid.toLowerCase()] = ptr(this.getRegister(rid).toString());
        }
    }
    /**
     * This function is used to synchronise context between Frida and QBDI.
     *
     * .. warning:: Currently QBDI_TO_FRIDA is not implemented (due to Frida limitations).
     *
     * @param                   FridaCtx   Frida context
     * @param {SyncDirection | number}   direction  Synchronization direction. (:js:data:`FRIDA_TO_QBDI` or :js:data:`QBDI_TO_FRIDA`)
     */
    synchronizeContext(FridaCtx, direction) {
        for (var i in GPR_NAMES) {
            if (GPR_NAMES[i] === "EFLAGS" || GPR_NAMES[i] === "FS" || GPR_NAMES[i] === "GS") {
                continue;
            }
            this.synchronizeRegister(FridaCtx, GPR_NAMES[i], direction);
        }
        if (direction === SyncDirection.QBDI_TO_FRIDA) {
            throw new Error('Not implemented (does not really work due to Frida)');
        }
    }
    /**
     * Pretty print QBDI context.
     *
     * @param {bool} [color] Will print a colored version of the context if set.
     *
     * @return dump of all GPRs in a pretty format
     */
    pp(color) {
        var RED = color ? "\x1b[31m" : "";
        var GREEN = color ? "\x1b[32m" : "";
        var RESET = color ? "\x1b[0m" : "";
        var regCnt = GPR_NAMES.length;
        var regs = this.getRegisters();
        var line = "";
        for (var i = 0; i < regCnt; i++) {
            var name = GPR_NAMES[i];
            if (!(i % 4) && i) {
                line += '\n';
            }
            line += GREEN; // Will be overwritten by RED if necessary
            if (name === "RIP" | name === "PC") {
                line += RED;
            }
            line += name.leftPad("   ") + RESET + "=0x" + hexPointer(regs[name]) + " ";
        }
        return line;
    }
    /**
     * Pretty print and log QBDI context.
     *
     * @param {bool} [color] Will print a colored version of the context if set.
     */
    dump(color) {
        console.log(this.pp(color));
    }
    static validOrThrow(state) {
        if (!GPRState.prototype.isPrototypeOf(state)) {
            throw new TypeError('Invalid GPRState');
        }
    }
}
/**
 * Floating Point Register context
 */
export class FPRState extends State {
    static validOrThrow(state) {
        if (!FPRState.prototype.isPrototypeOf(state)) {
            throw new TypeError('Invalid FPRState');
        }
    }
}
export class VM {
    // private member
    #vm = null;
    #memoryAccessDesc = null;
    #operandAnalysisStructDesc = null;
    #instAnalysisStructDesc = null;
    #vmStateStructDesc = null;
    #userDataPtrMap = {};
    #userDataIIdMap = {};
    #userDataPointer = 0;
    /**
     * Create a new instrumentation virtual machine using "**new VM()**"
     */
    constructor() {
        // Enforce a minimum QBDI version (API compatibility)
        if (!this.version || this.version.integer < QBDI_MINIMUM_VERSION) {
            throw new Error('Invalid QBDI version !');
        }
        // Create VM instance
        this.#vm = this._initVM();
        // Cache various remote structure descriptions
        // Parse remote structure descriptions
        this.#memoryAccessDesc = this._parseStructDesc(QBDI_C.getMemoryAccessStructDesc());
        this.#operandAnalysisStructDesc = this._parseStructDesc(QBDI_C.getOperandAnalysisStructDesc());
        this.#instAnalysisStructDesc = this._parseStructDesc(QBDI_C.getInstAnalysisStructDesc());
        this.#vmStateStructDesc = this._parseStructDesc(QBDI_C.getVMStateStructDesc());
        // add a destructor on garbage collection
        // The name of the API change with frida 15.0.0
        if (Number(Frida.version.split(".")[0]) < 15) {
            var that = this;
            WeakRef.bind(VM, function dispose() {
                if (that.ptr !== null) {
                    that._terminateVM(that.ptr);
                }
            });
        }
        else {
            var that = this;
            Script.bindWeak(VM, function dispose() {
                if (that.ptr !== null) {
                    that._terminateVM(that.ptr);
                }
            });
        }
    }
    get ptr() {
        return this.#vm;
    }
    /**
     * QBDI version (major, minor, patch).
     *
     * {string:String, integer:Number, major:Number, minor:Number, patch:Number}
     */
    get version() {
        if (!QBDI_C.getVersion) {
            return undefined;
        }
        var version = {};
        var versionPtr = Memory.alloc(4);
        var vStrPtr = QBDI_C.getVersion(versionPtr);
        var vInt = Memory.readU32(versionPtr);
        version.string = Memory.readCString(vStrPtr);
        version.integer = vInt;
        version.major = (vInt >> 16) & 0xff;
        version.minor = (vInt >> 8) & 0xff;
        version.patch = vInt & 0xff;
        Object.freeze(version);
        return version;
    }
    /**
     * Get the current options of the VM
     *
     * @return  {Options}  The current option
     */
    getOptions() {
        return QBDI_C.getOptions(this.#vm);
    }
    /**
     * Set the options of the VM
     *
     * @param  {Options}  options  The new options of the VM.
     */
    setOptions(options) {
        QBDI_C.setOptions(this.#vm, options);
    }
    /**
     * Add an address range to the set of instrumented address ranges.
     *
     * @param {String|Number|NativePointer} start  Start address of the range (included).
     * @param {String|Number|NativePointer} end    End address of the range (excluded).
     */
    addInstrumentedRange(start, end) {
        QBDI_C.addInstrumentedRange(this.#vm, start.toRword(), end.toRword());
    }
    /**
     * Add the executable address ranges of a module to the set of instrumented address ranges.
     *
     * @param  {String} name   The module's name.
     *
     * @return {bool} True if at least one range was added to the instrumented ranges.
     */
    addInstrumentedModule(name) {
        var namePtr = Memory.allocUtf8String(name);
        return QBDI_C.addInstrumentedModule(this.#vm, namePtr) == true;
    }
    /**
     * Add the executable address ranges of a module to the set of instrumented address ranges. using an address belonging to the module.
     *
     * @param  {String|Number|NativePointer} addr An address contained by module's range.
     *
     * @return {bool} True if at least one range was removed from the instrumented ranges.
     */
    addInstrumentedModuleFromAddr(addr) {
        return QBDI_C.addInstrumentedModuleFromAddr(this.#vm, addr.toRword()) == true;
    }
    /**
     * Adds all the executable memory maps to the instrumented range set.
     *
     * @return {bool} True if at least one range was added to the instrumented ranges.
     */
    instrumentAllExecutableMaps() {
        return QBDI_C.instrumentAllExecutableMaps(this.#vm) == true;
    }
    /**
     * Remove an address range from the set of instrumented address ranges.
     *
     * @param {String|Number} start  Start address of the range (included).
     * @param {String|Number} end    End address of the range (excluded).
     */
    removeInstrumentedRange(start, end) {
        QBDI_C.removeInstrumentedRange(this.#vm, start.toRword(), end.toRword());
    }
    /**
     * Remove the executable address ranges of a module from the set of instrumented address ranges.
     *
     * @param {String} name   The module's name.
     *
     * @return {bool} True if at least one range was added to the instrumented ranges.
     */
    removeInstrumentedModule(name) {
        var namePtr = Memory.allocUtf8String(name);
        return QBDI_C.removeInstrumentedModule(this.#vm, namePtr) == true;
    }
    /**
     * Remove the executable address ranges of a module from the set of instrumented address ranges using an address belonging to the module.
     *
     * @param {String|Number} addr: An address contained by module's range.
     *
     * @return {bool} True if at least one range was added to the instrumented ranges.
     */
    removeInstrumentedModuleFromAddr(addr) {
        return QBDI_C.removeInstrumentedModuleFromAddr(this.#vm, addr.toRword()) == true;
    }
    /**
     * Remove all instrumented ranges.
     */
    removeAllInstrumentedRanges() {
        QBDI_C.removeAllInstrumentedRanges(this.#vm);
    }
    /**
     * Start the execution by the DBI from a given address (and stop when another is reached).
     *
     * @param {String|Number} start  Address of the first instruction to execute.
     * @param {String|Number} stop   Stop the execution when this instruction is reached.
     *
     * @return {bool} True if at least one block has been executed.
     */
    run(start, stop) {
        return QBDI_C.run(this.#vm, start.toRword(), stop.toRword()) == true;
    }
    /**
     * Obtain the current general register state.
     *
     * @return {GPRState} An object containing the General Purpose Registers state.
     */
    getGPRState() {
        return new GPRState(QBDI_C.getGPRState(this.#vm));
    }
    /**
     * Obtain the current floating point register state.
     *
     * @return {FPRState} An object containing the Floating point Purpose Registers state.
     */
    getFPRState() {
        return new FPRState(QBDI_C.getFPRState(this.#vm));
    }
    /**
     * Set the GPR state
     *
     * @param {GPRState} state  Array of register values
     */
    setGPRState(state) {
        GPRState.validOrThrow(state);
        QBDI_C.setGPRState(this.#vm, state.ptr);
    }
    /**
     * Set the FPR state
     *
     * @param {FPRState} state  Array of register values
     */
    setFPRState(state) {
        FPRState.validOrThrow(state);
        QBDI_C.setFPRState(this.#vm, state.ptr);
    }
    /**
     * Pre-cache a known basic block.
     *
     * @param {String|Number} pc  Start address of a basic block
     *
     * @return {bool} True if basic block has been inserted in cache.
     */
    precacheBasicBlock(pc) {
        return QBDI_C.precacheBasicBlock(this.#vm, pc) == true;
    }
    /**
     * Clear a specific address range from the translation cache.
     *
     * @param {String|Number}  start  Start of the address range to clear from the cache.
     * @param {String|Number}  end    End of the address range to clear from the cache.
     */
    clearCache(start, end) {
        QBDI_C.clearCache(this.#vm, start, end);
    }
    /**
     * Clear the entire translation cache.
     */
    clearAllCache() {
        QBDI_C.clearAllCache(this.#vm);
    }
    /**
     * Register a callback event if the instruction matches the mnemonic.
     *
     * @param {String}       mnem      Mnemonic to match.
     * @param {InstPosition} pos       Relative position of the callback (PreInst / PostInst).
     * @param {InstCallback} cbk       A **native** InstCallback returned by :js:func:`VM.newInstCallback`.
     * @param {Object}       data      User defined data passed to the callback.
     * @param {Int}          priority  The priority of the callback.
     *
     * @return {Number} The id of the registered instrumentation (or VMError.INVALID_EVENTID in case of failure).
     */
    addMnemonicCB(mnem, pos, cbk, data, priority = CallbackPriority.PRIORITY_DEFAULT) {
        var mnemPtr = Memory.allocUtf8String(mnem);
        var vm = this.#vm;
        return this._retainUserData(data, function (dataPtr) {
            return QBDI_C.addMnemonicCB(vm, mnemPtr, pos, cbk, dataPtr, priority);
        });
    }
    /**
     * Register a callback event for every memory access matching the type bitfield made by the instruction in the range codeStart to codeEnd.
     *
     * @param {MemoryAccessType} type      A mode bitfield: either MEMORY_READ, MEMORY_WRITE or both (MEMORY_READ_WRITE).
     * @param {InstCallback}     cbk       A **native** InstCallback returned by :js:func:`VM.newInstCallback`.
     * @param {Object}           data      User defined data passed to the callback.
     * @param {Int}              priority  The priority of the callback.
     *
     * @return {Number} The id of the registered instrumentation (or VMError.INVALID_EVENTID in case of failure).
     */
    addMemAccessCB(type, cbk, data, priority = CallbackPriority.PRIORITY_DEFAULT) {
        var vm = this.#vm;
        return this._retainUserData(data, function (dataPtr) {
            return QBDI_C.addMemAccessCB(vm, type, cbk, dataPtr, priority);
        });
    }
    /**
     * Add a custom instrumentation rule to the VM.
     *
     * @param {InstrRuleCallback}  cbk    A **native** InstrRuleCallback returned by :js:func:`VM.newInstrRuleCallback`.
     * @param {AnalysisType}       type   Analyse type needed for this instruction function pointer to the callback
     * @param {Object}             data   User defined data passed to the callback.
     *
     * @return {Number} The id of the registered instrumentation (or VMError.INVALID_EVENTID in case of failure).
     */
    addInstrRule(cbk, type, data) {
        var vm = this.#vm;
        return this._retainUserDataForInstrRuleCB(data, function (dataPtr) {
            return QBDI_C.addInstrRule(vm, cbk, type, dataPtr);
        });
    }
    /**
     * Add a custom instrumentation rule to the VM for a range of address.
     *
     * @param {String|Number}      start  Begin of the range of address where apply the rule
     * @param {String|Number}      end    End of the range of address where apply the rule
     * @param {InstrRuleCallback}  cbk    A **native** InstrRuleCallback returned by :js:func:`VM.newInstrRuleCallback`.
     * @param {AnalysisType}       type   Analyse type needed for this instruction function pointer to the callback
     * @param {Object}             data   User defined data passed to the callback.
     *
     * @return {Number} The id of the registered instrumentation (or VMError.INVALID_EVENTID in case of failure).
     */
    addInstrRuleRange(start, end, cbk, type, data) {
        var vm = this.#vm;
        return this._retainUserDataForInstrRuleCB(data, function (dataPtr) {
            return QBDI_C.addInstrRuleRange(vm, start.toRword(), end.toRword(), cbk, type, dataPtr);
        });
    }
    /**
     * Add a virtual callback which is triggered for any memory access at a specific address matching the access type.
     * Virtual callbacks are called via callback forwarding by a gate callback triggered on every memory access. This incurs a high performance cost.
     *
     * @param {String|Number}     addr   Code address which will trigger the callback.
     * @param {MemoryAccessType}  type   A mode bitfield: either MEMORY_READ, MEMORY_WRITE or both (MEMORY_READ_WRITE).
     * @param {InstCallback}      cbk    A **native** InstCallback returned by :js:func:`VM.newInstCallback`.
     * @param {Object}            data   User defined data passed to the callback.
     *
     * @return {Number} The id of the registered instrumentation (or VMError.INVALID_EVENTID in case of failure).
     */
    addMemAddrCB(addr, type, cbk, data) {
        var vm = this.#vm;
        return this._retainUserData(data, function (dataPtr) {
            return QBDI_C.addMemAddrCB(vm, addr.toRword(), type, cbk, dataPtr);
        });
    }
    /**
     * Add a virtual callback which is triggered for any memory access in a specific address range matching the access type.
     * Virtual callbacks are called via callback forwarding by a gate callback triggered on every memory access. This incurs a high performance cost.
     *
     * @param {String|Number}     start    Start of the address range which will trigger the callback.
     * @param {String|Number}     end      End of the address range which will trigger the callback.
     * @param {MemoryAccessType}  type     A mode bitfield: either MEMORY_READ, MEMORY_WRITE or both (MEMORY_READ_WRITE).
     * @param {InstCallback}      cbk      A **native** InstCallback returned by :js:func:`VM.newInstCallback`.
     * @param {Object}            data     User defined data passed to the callback.
     *
     * @return {Number} The id of the registered instrumentation (or VMError.INVALID_EVENTID in case of failure).
     */
    addMemRangeCB(start, end, type, cbk, data) {
        var vm = this.#vm;
        return this._retainUserData(data, function (dataPtr) {
            return QBDI_C.addMemRangeCB(vm, start.toRword(), end.toRword(), type, cbk, dataPtr);
        });
    }
    /**
     * Register a callback event for a specific instruction event.
     *
     * @param {InstPosition|number} pos       Relative position of the callback (PreInst / PostInst).
     * @param {InstCallback} cbk       A **native** InstCallback returned by :js:func:`VM.newInstCallback`.
     * @param {Object}       data      User defined data passed to the callback.
     * @param {Int}          priority  The priority of the callback.
     *
     * @return {Number} The id of the registered instrumentation (or VMError.INVALID_EVENTID in case of failure).
     */
    addCodeCB(pos, cbk, data, priority = CallbackPriority.PRIORITY_DEFAULT) {
        var vm = this.#vm;
        return this._retainUserData(data, function (dataPtr) {
            return QBDI_C.addCodeCB(vm, pos, cbk, dataPtr, priority);
        });
    }
    /**
     * Register a callback for when a specific address is executed.
     *
     * @param {String|Number} addr      Code address which will trigger the callback.
     * @param {InstPosition}  pos       Relative position of the callback (PreInst / PostInst).
     * @param {InstCallback}  cbk       A **native** InstCallback returned by :js:func:`VM.newInstCallback`.
     * @param {Object}        data      User defined data passed to the callback.
     * @param {Int}           priority  The priority of the callback.
     *
     * @return {Number} The id of the registered instrumentation (or VMError.INVALID_EVENTID in case of failure).
     */
    addCodeAddrCB(addr, pos, cbk, data, priority = CallbackPriority.PRIORITY_DEFAULT) {
        var vm = this.#vm;
        return this._retainUserData(data, function (dataPtr) {
            return QBDI_C.addCodeAddrCB(vm, addr.toRword(), pos, cbk, dataPtr, priority);
        });
    }
    /**
     * Register a callback for when a specific address range is executed.
     *
     * @param {String|Number} start     Start of the address range which will trigger the callback.
     * @param {String|Number} end       End of the address range which will trigger the callback.
     * @param {InstPosition}  pos       Relative position of the callback (PreInst / PostInst).
     * @param {InstCallback}  cbk       A **native** InstCallback returned by :js:func:`VM.newInstCallback`.
     * @param {Object}        data      User defined data passed to the callback.
     * @param {Int}           priority  The priority of the callback.
     *
     * @return {Number} The id of the registered instrumentation (or VMError.INVALID_EVENTID in case of failure).
     */
    addCodeRangeCB(start, end, pos, cbk, data, priority = CallbackPriority.PRIORITY_DEFAULT) {
        var vm = this.#vm;
        return this._retainUserData(data, function (dataPtr) {
            return QBDI_C.addCodeRangeCB(vm, start.toRword(), end.toRword(), pos, cbk, dataPtr, priority);
        });
    }
    /**
     * Register a callback event for a specific VM event.
     *
     * @param {VMEvent}    mask   A mask of VM event type which will trigger the callback.
     * @param {VMCallback} cbk    A **native** VMCallback returned by :js:func:`VM.newVMCallback`.
     * @param {Object}     data   User defined data passed to the callback.
     *
     * @return {Number} The id of the registered instrumentation (or VMError.INVALID_EVENTID in case of failure).
     */
    addVMEventCB(mask, cbk, data) {
        var vm = this.#vm;
        return this._retainUserData(data, function (dataPtr) {
            return QBDI_C.addVMEventCB(vm, mask, cbk, dataPtr);
        });
    }
    /**
     * Remove an instrumentation.
     *
     * @param   {Number} id   The id of the instrumentation to remove.
     * @return  {bool} True if instrumentation has been removed.
     */
    deleteInstrumentation(id) {
        this._releaseUserData(id);
        return QBDI_C.deleteInstrumentation(this.#vm, id) == true;
    }
    /**
     * Remove all the registered instrumentations.
     */
    deleteAllInstrumentations() {
        this._releaseAllUserData();
        QBDI_C.deleteAllInstrumentations(this.#vm);
    }
    /**
     * Obtain the analysis of the current instruction. Analysis results are cached in the VM.
     * The validity of the returned pointer is only guaranteed until the end of the callback, else a deepcopy of the structure is required.
     *
     * @param {AnalysisType} [type] Properties to retrieve during analysis (default to ANALYSIS_INSTRUCTION | ANALYSIS_DISASSEMBLY).
     *
     * @return {InstAnalysis} A :js:class:`InstAnalysis` object containing the analysis result.
     */
    getInstAnalysis(type) {
        type = type || (AnalysisType.ANALYSIS_INSTRUCTION | AnalysisType.ANALYSIS_DISASSEMBLY);
        var analysis = QBDI_C.getInstAnalysis(this.#vm, type);
        if (analysis.isNull()) {
            return NULL;
        }
        return this._parseInstAnalysis(analysis);
    }
    /**
     * Obtain the analysis of a cached instruction. Analysis results are cached in the VM.
     * The validity of the returned pointer is only guaranteed until the end of the callback, else a deepcopy of the structure is required.
     *
     * @param {String|Number} addr    The address of the instruction to analyse.
     * @param {AnalysisType}  [type]  Properties to retrieve during analysis (default to ANALYSIS_INSTRUCTION | ANALYSIS_DISASSEMBLY).
     *
     * @return {InstAnalysis} A :js:class:`InstAnalysis` object containing the analysis result. null if the instruction isn't in the cache.
     */
    getCachedInstAnalysis(addr, type) {
        type = type || (AnalysisType.ANALYSIS_INSTRUCTION | AnalysisType.ANALYSIS_DISASSEMBLY);
        var analysis = QBDI_C.getCachedInstAnalysis(this.#vm, addr.toRword(), type);
        if (analysis.isNull()) {
            return NULL;
        }
        return this._parseInstAnalysis(analysis);
    }
    /**
     * Obtain the memory accesses made by the last executed instruction. Return NULL and a size of 0 if the instruction made no memory access.
     *
     * @param {MemoryAccessType} type Memory mode bitfield to activate the logging for: either MEMORY_READ, MEMORY_WRITE or both (MEMORY_READ_WRITE).
     */
    recordMemoryAccess(type) {
        return QBDI_C.recordMemoryAccess(this.#vm, type) == true;
    }
    /**
     * Obtain the memory accesses made by the last executed instruction. Return NULL and a size of 0 if the instruction made no memory access.
     *
     * @return {MemoryAccess[]} An array of :js:class:`MemoryAccess` made by the instruction.
     */
    getInstMemoryAccess() {
        return this._getMemoryAccess(QBDI_C.getInstMemoryAccess);
    }
    /**
     * Obtain the memory accesses made by the last executed sequence. Return NULL and a size of 0 if the basic block made no memory access.
     *
     * @return {MemoryAccess[]} An array of :js:class:`MemoryAccess` made by the sequence.
     */
    getBBMemoryAccess() {
        return this._getMemoryAccess(QBDI_C.getBBMemoryAccess);
    }
    // Memory
    /**
     * Allocate a new stack and setup the GPRState accordingly. The allocated stack needs to be freed with alignedFree().
     *
     * @param {GPRState} state      Array of register values
     * @param {Number}   stackSize  Size of the stack to be allocated.
     *
     * @return  Pointer (rword) to the allocated memory or NULL in case an error was encountered.
     */
    allocateVirtualStack(state, stackSize) {
        GPRState.validOrThrow(state);
        var stackPtr = Memory.alloc(Process.pointerSize);
        var ret = QBDI_C.allocateVirtualStack(state.ptr, stackSize, stackPtr);
        if (ret == false) {
            return NULL;
        }
        return Memory.readPointer(stackPtr);
    }
    /**
     * Allocate a block of memory of a specified sized with an aligned base address.
     *
     * @param {Number} size   Allocation size in bytes.
     * @param {Number} align  Base address alignement in bytes.
     *
     * @return  Pointer (rword) to the allocated memory or NULL in case an error was encountered.
     */
    alignedAlloc(size, align) {
        return QBDI_C.alignedAlloc(size, align);
    }
    /**
     * Free a block of aligned memory allocated with alignedAlloc or allocateVirtualStack
     *
     * @param {NativePtr} ptr  Pointer to the allocated memory.
     */
    alignedFree(ptr) {
        QBDI_C.alignedFree(ptr);
    }
    /**
     * Simulate a call by modifying the stack and registers accordingly.
     *
     * @param {GPRState}                state     Array of register values
     * @param {String|Number}           retAddr   Return address of the call to simulate.
     * @param {StringArray|NumberArray} args      A variadic list of arguments.
     */
    simulateCall(state, retAddr, args) {
        GPRState.validOrThrow(state);
        retAddr = retAddr.toRword();
        var fargs = this._formatVAArgs(args);
        // Use this weird construction to work around a bug in the duktape runtime
        var _simulateCall = function (a, b, c, d, e, f, g, h, i, j) {
            QBDI_C.simulateCall(state.ptr, retAddr, fargs[0], a, b, c, d, e, f, g, h, i, j);
        };
        _simulateCall.apply(null, fargs[1]);
    }
    /**
     * Use QBDI engine to retrieve loaded modules.
     *
     * @return list of module names (ex: ["ls", "libc", "libz"])
     */
    getModuleNames() {
        var sizePtr = Memory.alloc(4);
        var modsPtr = QBDI_C.getModuleNames(sizePtr);
        var size = Memory.readU32(sizePtr);
        if (modsPtr.isNull() || size === 0) {
            return [];
        }
        var mods = [];
        var p = modsPtr;
        for (var i = 0; i < size; i++) {
            var strPtr = Memory.readPointer(p);
            var str = Memory.readCString(strPtr);
            mods.push(str);
            System.free(strPtr);
            p = p.add(Process.pointerSize);
        }
        System.free(modsPtr);
        return mods;
    }
    // Logs
    setLogPriority(priority) {
        QBDI_C.setLogPriority(priority);
    }
    // Helpers
    /**
     * Create a native **Instruction rule callback** from a JS function.
     *
     * Example:
     *       >>> var icbk = vm.newInstrRuleCallback(function(vm, ana, data) {
     *       >>>   console.log("0x" + ana.address.toString(16) + " " + ana.disassembly);
     *       >>>   return [new InstrRuleDataCBK(InstPosition.POSTINST, printCB, ana.disassembly)];
     *       >>> });
     *
     * @param {InstrRuleCallback} cbk an instruction callback (ex: function(vm, ana, data) {};)
     *
     * @return an native InstrRuleCallback
     */
    newInstrRuleCallback(cbk) {
        if (typeof (cbk) !== 'function' || cbk.length !== 3) {
            return undefined;
        }
        // Use a closure to provide object
        var vm = this;
        var jcbk = function (vmPtr, anaPtr, cbksPtr, dataPtr) {
            var ana = vm._parseInstAnalysis(anaPtr);
            var data = vm._getUserData(dataPtr);
            var res = cbk(vm, ana, data.userdata);
            if (res === null) {
                return;
            }
            if (!Array.isArray(res)) {
                throw new TypeError('Invalid InstrRuleDataCBK Array');
            }
            if (res.length === 0) {
                return;
            }
            for (var i = 0; i < res.length; i++) {
                var d = vm._retainUserDataForInstrRuleCB2(res[i].data, data.id);
                QBDI_C.addInstrRuleData(cbksPtr, res[i].position, res[i].cbk, d, res[i].priority);
            }
        };
        return new NativeCallback(jcbk, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);
    }
    /**
     * Create a native **Instruction callback** from a JS function.
     *
     * Example:
     *       >>> var icbk = vm.newInstCallback(function(vm, gpr, fpr, data) {
     *       >>>   inst = vm.getInstAnalysis();
     *       >>>   console.log("0x" + inst.address.toString(16) + " " + inst.disassembly);
     *       >>>   return VMAction.CONTINUE;
     *       >>> });
     *
     * @param {InstCallback} cbk an instruction callback (ex: function(vm, gpr, fpr, data) {};)
     *
     * @return an native InstCallback
     */
    newInstCallback(cbk) {
        if (typeof (cbk) !== 'function' || cbk.length !== 4) {
            return undefined;
        }
        // Use a closure to provide object
        var vm = this;
        var jcbk = function (vmPtr, gprPtr, fprPtr, dataPtr) {
            var gpr = new GPRState(gprPtr);
            var fpr = new FPRState(fprPtr);
            var data = vm._getUserData(dataPtr);
            return cbk(vm, gpr, fpr, data);
        };
        return new NativeCallback(jcbk, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
    }
    /**
     * Create a native **VM callback** from a JS function.
     *
     * Example:
     *       >>> var vcbk = vm.newVMCallback(function(vm, evt, gpr, fpr, data) {
     *       >>>   if (evt.event & VMEvent.EXEC_TRANSFER_CALL) {
     *       >>>     console.warn("[!] External call to 0x" + evt.basicBlockStart.toString(16));
     *       >>>   }
     *       >>>   return VMAction.CONTINUE;
     *       >>> });
     *
     * @param {VMCallback} cbk a VM callback (ex: function(vm, state, gpr, fpr, data) {};)
     *
     * @return a native VMCallback
     */
    newVMCallback(cbk) {
        if (typeof (cbk) !== 'function' || cbk.length !== 5) {
            return undefined;
        }
        // Use a closure to provide object and a parsed event
        var vm = this;
        var jcbk = function (vmPtr, state, gprPtr, fprPtr, dataPtr) {
            var s = vm._parseVMState(state);
            var gpr = new GPRState(gprPtr);
            var fpr = new FPRState(fprPtr);
            var data = vm._getUserData(dataPtr);
            return cbk(vm, s, gpr, fpr, data);
        };
        return new NativeCallback(jcbk, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);
    }
    /**
     * Call a function by its address (or through a Frida ``NativePointer``).
     *
     * Arguments can be provided, but their types need to be compatible
     * with the ``.toRword()`` interface (like ``NativePointer`` or ``UInt64``).
     *
     * Example:
     *       >>> var vm = new VM();
     *       >>> var state = vm.getGPRState();
     *       >>> vm.allocateVirtualStack(state, 0x1000000);
     *       >>> var aFunction = Module.findExportByName(null, "Secret");
     *       >>> vm.addInstrumentedModuleFromAddr(aFunction);
     *       >>> vm.call(aFunction, [42]);
     *
     * @param {String|Number|NativePointer}           address function address (or Frida ``NativePointer``).
     * @param {StringArray|NumberArray} [args]  optional list of arguments
     */
    call(address, args) {
        address = address.toRword();
        var fargs = this._formatVAArgs(args);
        var vm = this.#vm;
        // Use this weird construction to work around a bug in the duktape runtime
        var _call = function (a, b, c, d, e, f, g, h, i, j) {
            var retPtr = Memory.alloc(Process.pointerSize);
            var res = QBDI_C.call(vm, retPtr, address, fargs[0], a, b, c, d, e, f, g, h, i, j);
            if (res == false) {
                throw new EvalError('Execution failed');
            }
            return ptr(Memory.readRword(retPtr));
        };
        return _call.apply(null, fargs[1]);
    }
    ////////////////////
    // private method //
    ////////////////////
    _parseStructDesc(ptr) {
        var desc = {};
        desc.size = Memory.readU32(ptr);
        ptr = ptr.add(4);
        desc.items = Memory.readU32(ptr);
        ptr = ptr.add(4);
        desc.offsets = [];
        for (var i = 0; i < desc.items; i++) {
            var offset = Memory.readU32(ptr);
            ptr = ptr.add(4);
            desc.offsets.push(offset);
        }
        Object.freeze(desc);
        return desc;
    }
    _initVM() {
        var vmPtr = Memory.alloc(Process.pointerSize);
        QBDI_C.initVM(vmPtr, NULL, NULL, 0);
        return Memory.readPointer(vmPtr);
    }
    _terminateVM(v) {
        QBDI_C.terminateVM(v);
    }
    // Retain (~reference) a user data object when an instrumentation is added.
    //
    // If a ``NativePointer`` is given, it will be used as raw user data and the
    // object will not be retained.
    _retainUserData(data, fn) {
        var dataPtr = ptr("0");
        var managed = false;
        if (data !== null && data !== undefined) {
            this.#userDataPointer += 1;
            dataPtr = dataPtr.add(this.#userDataPointer);
            managed = true;
        }
        var iid = fn(dataPtr);
        if (managed) {
            this.#userDataPtrMap[dataPtr] = data;
            this.#userDataIIdMap[iid] = dataPtr;
        }
        return iid;
    }
    _retainUserDataForInstrRuleCB(data, fn) {
        this.#userDataPointer += 1;
        var dataPtr = ptr("0").add(this.#userDataPointer);
        var iid = fn(dataPtr);
        this.#userDataPtrMap[dataPtr] = { userdata: data, id: iid };
        this.#userDataIIdMap[iid] = [dataPtr];
        return iid;
    }
    _retainUserDataForInstrRuleCB2(data, id) {
        if (data !== null && data !== undefined) {
            this.#userDataPointer += 1;
            var dataPtr = ptr("0").add(this.#userDataPointer);
            this.#userDataPtrMap[dataPtr] = data;
            this.#userDataIIdMap[id].push(dataPtr);
            return dataPtr;
        }
        else {
            return ptr("0");
        }
    }
    // Retrieve a user data object from its ``NativePointer`` reference.
    // If pointer is NULL or no data object is found, the ``NativePointer``
    // object will be returned.
    _getUserData(dataPtr) {
        var data = dataPtr;
        if (!data.isNull()) {
            var d = this.#userDataPtrMap[dataPtr];
            if (d !== undefined) {
                return d;
            }
        }
        return undefined;
    }
    // Release references to a user data object using the correponding
    // instrumentation id.
    _releaseUserData(id) {
        var dataPtr = this.#userDataIIdMap[id];
        if (dataPtr !== undefined) {
            if (Array.isArray(dataPtr)) {
                for (var i = 0; i < dataPtr.length; i++) {
                    delete this.#userDataPtrMap[dataPtr[i]];
                }
            }
            else {
                delete this.#userDataPtrMap[dataPtr];
            }
            delete this.#userDataIIdMap[id];
        }
    }
    // Release all references to user data objects.
    _releaseAllUserData() {
        this.#userDataPtrMap = {};
        this.#userDataIIdMap = {};
        this.#userDataPointer = 0;
    }
    _formatVAArgs(args) {
        if (args === undefined) {
            args = [];
        }
        var argsCnt = args.length;
        // We are limited to 10 arguments for now
        var fargs = new Array(10);
        var fargsCnt = fargs.length;
        for (var i = 0; i < fargsCnt; i++) {
            if (i < argsCnt) {
                fargs[i] = args[i].toRword();
            }
            else {
                fargs[i] = 0;
            }
        }
        return [argsCnt, fargs];
    }
    _parseMemoryAccess(ptr) {
        var access = {};
        var p = ptr.add(this.#instAnalysisStructDesc.offsets[0]);
        access.instAddress = Memory.readRword(p);
        p = ptr.add(this.#memoryAccessDesc.offsets[1]);
        access.accessAddress = Memory.readRword(p);
        p = ptr.add(this.#memoryAccessDesc.offsets[2]);
        access.value = Memory.readRword(p);
        p = ptr.add(this.#memoryAccessDesc.offsets[3]);
        access.size = Memory.readU16(p);
        p = ptr.add(this.#memoryAccessDesc.offsets[4]);
        access.type = Memory.readU8(p);
        p = ptr.add(this.#memoryAccessDesc.offsets[5]);
        access.flags = Memory.readU8(p);
        Object.freeze(access);
        return access;
    }
    _getMemoryAccess(f) {
        var accesses = [];
        var sizePtr = Memory.alloc(4);
        var accessPtr = f(this.#vm, sizePtr);
        if (accessPtr.isNull()) {
            return [];
        }
        var cnt = Memory.readU32(sizePtr);
        var sSize = this.#memoryAccessDesc.size;
        var p = accessPtr;
        for (var i = 0; i < cnt; i++) {
            var access = this._parseMemoryAccess(p);
            accesses.push(access);
            p = p.add(sSize);
        }
        System.free(accessPtr);
        return accesses;
    }
    _parseVMState(ptr) {
        var state = {};
        var p = ptr.add(this.#instAnalysisStructDesc.offsets[0]);
        state.event = Memory.readU8(p);
        p = ptr.add(this.#vmStateStructDesc.offsets[1]);
        state.sequenceStart = Memory.readRword(p);
        p = ptr.add(this.#vmStateStructDesc.offsets[2]);
        state.sequenceEnd = Memory.readRword(p);
        p = ptr.add(this.#vmStateStructDesc.offsets[3]);
        state.basicBlockStart = Memory.readRword(p);
        p = ptr.add(this.#vmStateStructDesc.offsets[4]);
        state.basicBlockEnd = Memory.readRword(p);
        p = ptr.add(this.#vmStateStructDesc.offsets[5]);
        state.lastSignal = Memory.readRword(p);
        Object.freeze(state);
        return state;
    }
    _parseOperandAnalysis(ptr) {
        var analysis = {};
        var p = ptr.add(this.#instAnalysisStructDesc.offsets[0]);
        analysis.type = Memory.readU32(p);
        p = ptr.add(this.#operandAnalysisStructDesc.offsets[1]);
        analysis.flag = Memory.readU8(p);
        p = ptr.add(this.#operandAnalysisStructDesc.offsets[2]);
        analysis.value = Memory.readRword(p);
        p = ptr.add(this.#operandAnalysisStructDesc.offsets[3]);
        analysis.size = Memory.readU8(p);
        p = ptr.add(this.#operandAnalysisStructDesc.offsets[4]);
        analysis.regOff = Memory.readU8(p);
        p = ptr.add(this.#operandAnalysisStructDesc.offsets[5]);
        analysis.regCtxIdx = Memory.readS16(p);
        p = ptr.add(this.#operandAnalysisStructDesc.offsets[6]);
        var regNamePtr = Memory.readPointer(p);
        if (regNamePtr.isNull()) {
            analysis.regName = undefined;
        }
        else {
            analysis.regName = Memory.readCString(regNamePtr);
        }
        p = ptr.add(this.#operandAnalysisStructDesc.offsets[7]);
        analysis.regAccess = Memory.readU8(p);
        Object.freeze(analysis);
        return analysis;
    }
    _parseInstAnalysis(ptr) {
        var analysis = {};
        var p = ptr.add(this.#instAnalysisStructDesc.offsets[0]);
        analysis.mnemonic = Memory.readCString(Memory.readPointer(p));
        p = ptr.add(this.#instAnalysisStructDesc.offsets[1]);
        analysis.disassembly = Memory.readCString(Memory.readPointer(p));
        p = ptr.add(this.#instAnalysisStructDesc.offsets[2]);
        analysis.address = Memory.readRword(p);
        p = ptr.add(this.#instAnalysisStructDesc.offsets[3]);
        analysis.instSize = Memory.readU32(p);
        p = ptr.add(this.#instAnalysisStructDesc.offsets[4]);
        analysis.affectControlFlow = Memory.readU8(p) == true;
        p = ptr.add(this.#instAnalysisStructDesc.offsets[5]);
        analysis.isBranch = Memory.readU8(p) == true;
        p = ptr.add(this.#instAnalysisStructDesc.offsets[6]);
        analysis.isCall = Memory.readU8(p) == true;
        p = ptr.add(this.#instAnalysisStructDesc.offsets[7]);
        analysis.isReturn = Memory.readU8(p) == true;
        p = ptr.add(this.#instAnalysisStructDesc.offsets[8]);
        analysis.isCompare = Memory.readU8(p) == true;
        p = ptr.add(this.#instAnalysisStructDesc.offsets[9]);
        analysis.isPredicable = Memory.readU8(p) == true;
        p = ptr.add(this.#instAnalysisStructDesc.offsets[10]);
        analysis.isMoveImm = Memory.readU8(p) == true;
        p = ptr.add(this.#instAnalysisStructDesc.offsets[11]);
        analysis.mayLoad = Memory.readU8(p) == true;
        p = ptr.add(this.#instAnalysisStructDesc.offsets[12]);
        analysis.mayStore = Memory.readU8(p) == true;
        p = ptr.add(this.#instAnalysisStructDesc.offsets[13]);
        analysis.loadSize = Memory.readU32(p);
        p = ptr.add(this.#instAnalysisStructDesc.offsets[14]);
        analysis.storeSize = Memory.readU32(p);
        p = ptr.add(this.#instAnalysisStructDesc.offsets[15]);
        analysis.condition = Memory.readU8(p);
        p = ptr.add(this.#instAnalysisStructDesc.offsets[16]);
        analysis.flagsAccess = Memory.readU8(p);
        p = ptr.add(this.#instAnalysisStructDesc.offsets[17]);
        var numOperands = Memory.readU8(p);
        p = ptr.add(this.#instAnalysisStructDesc.offsets[18]);
        var operandsPtr = Memory.readPointer(p);
        analysis.operands = new Array(numOperands);
        for (var i = 0; i < numOperands; i++) {
            analysis.operands[i] = this._parseOperandAnalysis(operandsPtr);
            operandsPtr = operandsPtr.add(this.#operandAnalysisStructDesc.size);
        }
        p = ptr.add(this.#instAnalysisStructDesc.offsets[19]);
        var symbolPtr = Memory.readPointer(p);
        if (!symbolPtr.isNull()) {
            analysis.symbol = Memory.readCString(symbolPtr);
        }
        else {
            analysis.symbol = "";
        }
        p = ptr.add(this.#instAnalysisStructDesc.offsets[20]);
        analysis.symbolOffset = Memory.readU32(p);
        p = ptr.add(this.#instAnalysisStructDesc.offsets[21]);
        var modulePtr = Memory.readPointer(p);
        if (!modulePtr.isNull()) {
            analysis.module = Memory.readCString(modulePtr);
        }
        else {
            analysis.module = "";
        }
        p = ptr.add(this.#instAnalysisStructDesc.offsets[22]);
        analysis.cpuMode = Memory.readU8(p);
        Object.freeze(analysis);
        return analysis;
    }
}
;
✄
{"version":3,"file":"include.js","sourceRoot":"C:/Users/admin/Desktop/git_project/FridaDebugger/","sources":["agent/plugins/QBDI/include.ts"],"names":[],"mappings":"AAAA,OAAO,iBAAiB,CAAA;AACxB,OAAO,eAAe,CAAA"}
✄
import './StructInfo.js';
import './QBDIMain.js';
✄
{"version":3,"file":"include.js","sourceRoot":"C:/Users/admin/Desktop/git_project/FridaDebugger/","sources":["agent/plugins/V8/include.ts"],"names":[],"mappings":""}
✄
export {};
✄
{"version":3,"file":"include.js","sourceRoot":"C:/Users/admin/Desktop/git_project/FridaDebugger/","sources":["agent/plugins/capstone/include.ts"],"names":[],"mappings":""}
✄
export {};
✄
{"version":3,"file":"include.js","sourceRoot":"C:/Users/admin/Desktop/git_project/FridaDebugger/","sources":["agent/plugins/curl/include.ts"],"names":[],"mappings":""}
✄
export {};
✄
{"version":3,"file":"include.js","sourceRoot":"C:/Users/admin/Desktop/git_project/FridaDebugger/","sources":["agent/plugins/include.ts"],"names":[],"mappings":"AAAA,OAAO,mBAAmB,CAAA;AAC1B,OAAO,mBAAmB,CAAA;AAC1B,OAAO,uBAAuB,CAAA;AAC9B,OAAO,uBAAuB,CAAA;AAC9B,OAAO,iBAAiB,CAAA;AAExB,OAAO,mBAAmB,CAAA;AAC1B,OAAO,sBAAsB,CAAA;AAE7B,OAAO,WAAW,CAAA"}
✄
import './LIEF/include.js';
import './QBDI/include.js';
import './capstone/include.js';
import './keystone/include.js';
import './V8/include.js';
import './curl/include.js';
import './openssl/include.js';
import './main.js';
✄
{"version":3,"file":"include.js","sourceRoot":"C:/Users/admin/Desktop/git_project/FridaDebugger/","sources":["agent/plugins/keystone/include.ts"],"names":[],"mappings":""}
✄
export {};
✄
{"version":3,"file":"main.js","sourceRoot":"C:/Users/admin/Desktop/git_project/FridaDebugger/","sources":["agent/plugins/main.ts"],"names":[],"mappings":"AAAA,OAAO,CAAC,GAAG,CAAC,UAAU,EAAE,GAAG,EAAE,WAAW,CAAC,SAAS,EAAE,CAAC,CAAA"}
✄
Reflect.set(globalThis, "D", Interceptor.detachAll());
✄
{"version":3,"file":"include.js","sourceRoot":"C:/Users/admin/Desktop/git_project/FridaDebugger/","sources":["agent/plugins/openssl/include.ts"],"names":[],"mappings":""}
✄
export {};
✄
{"version":3,"file":"plugin_main.js","sourceRoot":"C:/Users/admin/Desktop/git_project/FridaDebugger/","sources":["agent/plugins/plugin_main.ts"],"names":[],"mappings":"AAAA,OAAO,CAAC,GAAG,CAAC,UAAU,EAAE,GAAG,EAAE,WAAW,CAAC,SAAS,EAAE,CAAC,CAAA"}
✄
Reflect.set(globalThis, "D", Interceptor.detachAll());
✄
{"version":3,"file":"signal.js","sourceRoot":"C:/Users/admin/Desktop/git_project/FridaDebugger/","sources":["agent/signal.ts"],"names":[],"mappings":"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"}
✄
import { BPStatus } from "./breakpoint/BPStatus.js";
export var Signal;
(function (Signal) {
    var semlock_global = Memory.alloc(0x10);
    var semlock_thread_ids = new Map();
    const func_sem_init = new NativeFunction(Module.findExportByName("libc.so", "sem_init"), "int", ["pointer", "int", "uint"]);
    const func_sem_destroy = new NativeFunction(Module.findExportByName("libc.so", "sem_destroy"), "int", ["pointer"]);
    const func_sem_wait = new NativeFunction(Module.findExportByName("libc.so", "sem_wait"), "int", ["pointer"]);
    const func_sem_post = new NativeFunction(Module.findExportByName("libc.so", "sem_post"), "int", ["pointer"]);
    Signal.sem_post = () => {
        func_sem_post(semlock_global);
        func_sem_destroy(semlock_global);
    };
    Signal.sem_wait = () => {
        func_sem_init(semlock_global, 0, 0);
        func_sem_wait(semlock_global);
    };
    Signal.sem_post_thread_id = (thread_id) => {
        if (semlock_thread_ids.has(thread_id)) {
            func_sem_post(semlock_thread_ids.get(thread_id));
            func_sem_destroy(semlock_thread_ids.get(thread_id));
        }
    };
    Signal.sem_wait_threadid = (thread_id) => {
        if (!semlock_thread_ids.has(thread_id)) {
            var mem = Memory.alloc(0x10);
            semlock_thread_ids.set(thread_id, mem);
            func_sem_init(semlock_thread_ids.get(thread_id), 0, 0);
        }
        func_sem_wait(semlock_thread_ids.get(thread_id));
    };
    Signal.continue_instruction = (thread_id = BPStatus.currentThreadId) => {
        Signal.sem_post_thread_id(thread_id);
        newLine();
    };
})(Signal || (Signal = {}));
Reflect.set(globalThis, "Signal", Signal);
Reflect.set(globalThis, "step", Signal.continue_instruction);
Reflect.set(globalThis, "si", Signal.continue_instruction);
// using in local code
export class Semaphore {
    sem;
    sem_init;
    sem_wait;
    sem_post;
    sem_destroy;
    constructor(initialValue = 0) {
        this.sem = Memory.alloc(0x8);
        this.sem_init = new NativeFunction(Module.findExportByName("libc.so", "sem_init"), 'int', ['pointer', 'int', 'uint']);
        this.sem_wait = new NativeFunction(Module.findExportByName("libc.so", "sem_wait"), 'int', ['pointer']);
        this.sem_post = new NativeFunction(Module.findExportByName("libc.so", "sem_post"), 'int', ['pointer']);
        this.sem_destroy = new NativeFunction(Module.findExportByName("libc.so", "sem_destroy"), 'int', ['pointer']);
        this.sem_init(this.sem, 0, initialValue);
    }
    wait() {
        this.sem_wait(this.sem);
    }
    post() {
        this.sem_post(this.sem);
    }
    destroy() {
        this.sem_destroy(this.sem);
    }
}
✄
{"version":3,"file":"utils.js","sourceRoot":"C:/Users/admin/Desktop/git_project/FridaDebugger/","sources":["agent/utils.ts"],"names":[],"mappings":"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"}
✄
import { logd, logz } from "./logger.js";
import { Semaphore } from "./signal.js";
globalThis.clear = () => console.log('\x1Bc');
globalThis.newLine = (lines = 1) => {
    for (let i = 0; i < lines; i++)
        console.log('\n');
};
globalThis.d = () => { Interceptor.detachAll(); };
export function getThreadName(tid) {
    let threadName = "unknown";
    try {
        var file = new File("/proc/self/task/" + tid + "/comm", "r");
        threadName = file.readLine().toString().trimEnd();
        file.close();
    }
    catch (e) {
        throw e;
    }
    // var threadNamePtr: NativePointer = Memory.alloc(0x40)
    // var tid_p: NativePointer = Memory.alloc(p_size).writePointer(ptr(tid))
    // var pthread_getname_np = new NativeFunction(Module.findExportByName("libc.so", 'pthread_getname_np')!, 'int', ['pointer', 'pointer', 'int'])
    // pthread_getname_np(ptr(tid), threadNamePtr, 0x40)
    // threadName = threadNamePtr.readCString()!
    return threadName;
}
export function demangleName(expName) {
    let demangleAddress = Module.findExportByName("libc++.so", '__cxa_demangle');
    if (demangleAddress == null)
        demangleAddress = Module.findExportByName("libunwindstack.so", '__cxa_demangle');
    if (demangleAddress == null)
        demangleAddress = Module.findExportByName("libbacktrace.so", '__cxa_demangle');
    if (demangleAddress == null)
        demangleAddress = Module.findExportByName(null, '__cxa_demangle');
    if (demangleAddress == null)
        throw Error("can not find export function -> __cxa_demangle");
    let demangle = new NativeFunction(demangleAddress, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);
    let mangledName = Memory.allocUtf8String(expName);
    let outputBuffer = NULL;
    let length = NULL;
    let status = Memory.alloc(Process.pageSize);
    let result = demangle(mangledName, outputBuffer, length, status);
    if (status.readInt() === 0) {
        let resultStr = result.readUtf8String();
        return (resultStr == null || resultStr == expName) ? "" : resultStr;
    }
    else
        return "";
}
export const padding = (str, len = 25, pad = ' ', end = true) => {
    if (str instanceof NativePointer)
        str = str.toString();
    if (str.length >= len)
        return str;
    if (end)
        return str.padEnd(len, pad);
    else
        return str.padStart(len, pad);
};
export const packApiResove = (patter = "exports:*!*Unwind*") => {
    let index = 0;
    new ApiResolver("module").enumerateMatches(patter).forEach((exp) => {
        logd(`${padding(`[${++index}]`, 5)}${exp.name} ${exp.address}`);
        logz(`\t${demangleName(exp.name.split("!")[1])}`);
    });
};
export const getMainThreadId = () => {
    let retId = -1;
    const semaphore = new Semaphore();
    Java.scheduleOnMainThread(() => {
        retId = Process.getCurrentThreadId();
        semaphore.post();
    });
    semaphore.wait();
    return retId;
};
globalThis.d = d;
globalThis.PD = padding;
globalThis.clear = clear;
globalThis.padding = padding;
globalThis.newLine = newLine;
globalThis.getThreadName = getThreadName;
globalThis.getMainThreadId = getMainThreadId;
globalThis.demangleName = demangleName;
✄
export function nextTick(callback, ...args) {
  Script.nextTick(callback, ...args);
}

export const title = 'Frida';
export const browser = false;
export const platform = detectPlatform();
export const pid = Process.id;
export const env = {
  FRIDA_COMPILE: '1',
};
export const argv = [];
export const version = Frida.version;
export const versions = {};

function noop() {}

export const on = noop;
export const addListener = noop;
export const once = noop;
export const off = noop;
export const removeListener = noop;
export const removeAllListeners = noop;
export const emit = noop;
export const prependListener = noop;
export const prependOnceListener = noop;

export const listeners = function (name) { return []; }

export function binding(name) {
    throw new Error('process.binding is not supported');
}

export function cwd() {
    return (Process.platform === 'windows') ? 'C:\\' : '/';
}
export function chdir(dir) {
    throw new Error('process.chdir is not supported');
}
export function umask() { return 0; }

export default {
    nextTick,
    title,
    browser,
    platform,
    pid,
    env,
    argv,
    version,
    versions,
    on,
    addListener,
    once,
    off,
    removeListener,
    removeAllListeners,
    emit,
    prependListener,
    prependOnceListener,
    listeners,
    binding,
    cwd,
    chdir,
    umask,
};

function detectPlatform() {
    const platform = Process.platform;
    return (platform === 'windows') ? 'win32' : platform;
}

✄
// Currently in sync with Node.js lib/internal/util/types.js
// https://github.com/nodejs/node/commit/112cc7c27551254aa2b17098fb774867f05ed0d9

const ObjectToString = uncurryThis(Object.prototype.toString);

const numberValue = uncurryThis(Number.prototype.valueOf);
const stringValue = uncurryThis(String.prototype.valueOf);
const booleanValue = uncurryThis(Boolean.prototype.valueOf);

const bigIntValue = uncurryThis(BigInt.prototype.valueOf);

const symbolValue = uncurryThis(Symbol.prototype.valueOf);

const generatorPrototype = Object.getPrototypeOf(function* () {});
const typedArrayPrototype = Object.getPrototypeOf(Int8Array);

export function isArgumentsObject(value) {
  if (value !== null && typeof value === 'object' && Symbol.toStringTag in value) {
    return false;
  }
  return ObjectToString(value) === '[object Arguments]';
}

export function isGeneratorFunction(value) {
  return Object.getPrototypeOf(value) === generatorPrototype;
}

export function isTypedArray(value) {
  return value instanceof typedArrayPrototype;
}

export function isPromise(input) {
  return input instanceof Promise;
}

export function isArrayBufferView(value) {
  return ArrayBuffer.isView(value);
}

export function isUint8Array(value) {
  return value instanceof Uint8Array;
}

export function isUint8ClampedArray(value) {
  return value instanceof Uint8ClampedArray;
}

export function isUint16Array(value) {
  return value instanceof Uint16Array;
}

export function isUint32Array(value) {
  return value instanceof Uint32Array;
}

export function isInt8Array(value) {
  return value instanceof Int8Array;
}

export function isInt16Array(value) {
  return value instanceof Int16Array;
}

export function isInt32Array(value) {
  return value instanceof Int32Array;
}

export function isFloat32Array(value) {
  return value instanceof Float32Array;
}

export function isFloat64Array(value) {
  return value instanceof Float64Array;
}

export function isBigInt64Array(value) {
  return value instanceof BigInt64Array;
}

export function isBigUint64Array(value) {
  return value instanceof BigUint64Array;
}

export function isMap(value) {
  return ObjectToString(value) === '[object Map]';
}

export function isSet(value) {
  return ObjectToString(value) === '[object Set]';
}

export function isWeakMap(value) {
  return ObjectToString(value) === '[object WeakMap]';
}

export function isWeakSet(value) {
  return ObjectToString(value) === '[object WeakSet]';
}

export function isArrayBuffer(value) {
  return ObjectToString(value) === '[object ArrayBuffer]';
}

export function isDataView(value) {
  return ObjectToString(value) === '[object DataView]';
}

export function isSharedArrayBuffer(value) {
  return ObjectToString(value) === '[object SharedArrayBuffer]';
}

export function isAsyncFunction(value) {
  return ObjectToString(value) === '[object AsyncFunction]';
}

export function isMapIterator(value) {
  return ObjectToString(value) === '[object Map Iterator]';
}

export function isSetIterator(value) {
  return ObjectToString(value) === '[object Set Iterator]';
}

export function isGeneratorObject(value) {
  return ObjectToString(value) === '[object Generator]';
}

export function isWebAssemblyCompiledModule(value) {
  return ObjectToString(value) === '[object WebAssembly.Module]';
}

export function isNumberObject(value) {
  return checkBoxedPrimitive(value, numberValue);
}

export function isStringObject(value) {
  return checkBoxedPrimitive(value, stringValue);
}

export function isBooleanObject(value) {
  return checkBoxedPrimitive(value, booleanValue);
}

export function isBigIntObject(value) {
  return checkBoxedPrimitive(value, bigIntValue);
}

export function isSymbolObject(value) {
  return checkBoxedPrimitive(value, symbolValue);
}

function checkBoxedPrimitive(value, prototypeValueOf) {
  if (typeof value !== 'object') {
    return false;
  }
  try {
    prototypeValueOf(value);
    return true;
  } catch(e) {
    return false;
  }
}

export function isBoxedPrimitive(value) {
  return (
    isNumberObject(value) ||
    isStringObject(value) ||
    isBooleanObject(value) ||
    isBigIntObject(value) ||
    isSymbolObject(value)
  );
}

export function isAnyArrayBuffer(value) {
  return isArrayBuffer(value) || isSharedArrayBuffer(value);
}

export function isProxy(value) {
  throwNotSupported('isProxy');
}

export function isExternal(value) {
  throwNotSupported('isExternal');
}

export function isModuleNamespaceObject(value) {
  throwNotSupported('isModuleNamespaceObject');
}

function throwNotSupported(method) {
  throw new Error(`${method} is not supported in userland`);
}

function uncurryThis(f) {
  return f.call.bind(f);
}

✄
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

import * as _types from './support/types.js';

import process from 'process';

export const types = {
  ..._types,
  isRegExp,
  isDate,
  isNativeError: isError,
};

export default {
  format,
  deprecate,
  debuglog,
  inspect,
  types,
  isArray,
  isBoolean,
  isNull,
  isNullOrUndefined,
  isNumber,
  isString,
  isSymbol,
  isUndefined,
  isRegExp,
  isObject,
  isDate,
  isError,
  isFunction,
  isPrimitive,
  isBuffer,
  log,
  inherits,
  _extend,
  promisify,
  callbackify,
};

const formatRegExp = /%[sdj%]/g;

export function format(f) {
  if (!isString(f)) {
    const objects = [];
    for (let i = 0; i < arguments.length; i++) {
      objects.push(inspect(arguments[i]));
    }
    return objects.join(' ');
  }

  let i = 1;
  const args = arguments;
  const len = args.length;
  let str = String(f).replace(formatRegExp, function(x) {
    if (x === '%%') return '%';
    if (i >= len) return x;
    switch (x) {
      case '%s': return String(args[i++]);
      case '%d': return Number(args[i++]);
      case '%j':
        try {
          return JSON.stringify(args[i++]);
        } catch (_) {
          return '[Circular]';
        }
      default:
        return x;
    }
  });
  for (let x = args[i]; i < len; x = args[++i]) {
    if (isNull(x) || !isObject(x)) {
      str += ' ' + x;
    } else {
      str += ' ' + inspect(x);
    }
  }
  return str;
}


// Mark that a method should not be used.
// Returns a modified function which warns once by default.
// If --no-deprecation is set, then it is a no-op.
export function deprecate(fn, msg) {
  if (process.noDeprecation === true) {
    return fn;
  }

  let warned = false;
  function deprecated() {
    if (!warned) {
      if (process.throwDeprecation) {
        throw new Error(msg);
      } else if (process.traceDeprecation) {
        console.trace(msg);
      } else {
        console.error(msg);
      }
      warned = true;
    }
    return fn.apply(this, arguments);
  }

  return deprecated;
}


const debugs = {};
let debugEnvRegex = /^$/;

if (process.env.NODE_DEBUG) {
  let debugEnv = process.env.NODE_DEBUG;
  debugEnv = debugEnv.replace(/[|\\{}()[\]^$+?.]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/,/g, '$|^')
    .toUpperCase();
  debugEnvRegex = new RegExp('^' + debugEnv + '$', 'i');
}

export function debuglog(set) {
  set = set.toUpperCase();
  if (!debugs[set]) {
    if (debugEnvRegex.test(set)) {
      const pid = process.pid;
      debugs[set] = function() {
        const msg = format.apply(null, arguments);
        console.error('%s %d: %s', set, pid, msg);
      };
    } else {
      debugs[set] = function() {};
    }
  }
  return debugs[set];
}


/**
 * Echos the value of a value. Trys to print the value out
 * in the best way possible given the different types.
 *
 * @param {Object} obj The object to print out.
 * @param {Object} opts Optional options object that alters the output.
 */
/* legacy: obj, showHidden, depth, colors*/
export function inspect(obj, opts) {
  // default options
  const ctx = {
    seen: [],
    stylize: stylizeNoColor
  };
  // legacy...
  if (arguments.length >= 3) ctx.depth = arguments[2];
  if (arguments.length >= 4) ctx.colors = arguments[3];
  if (isBoolean(opts)) {
    // legacy...
    ctx.showHidden = opts;
  } else if (opts) {
    // got an "options" object
    _extend(ctx, opts);
  }
  // set default options
  if (isUndefined(ctx.showHidden)) ctx.showHidden = false;
  if (isUndefined(ctx.depth)) ctx.depth = 2;
  if (isUndefined(ctx.colors)) ctx.colors = false;
  if (isUndefined(ctx.customInspect)) ctx.customInspect = true;
  if (ctx.colors) ctx.stylize = stylizeWithColor;
  return formatValue(ctx, obj, ctx.depth);
}
inspect.custom = Symbol.for('nodejs.util.inspect.custom');


// http://en.wikipedia.org/wiki/ANSI_escape_code#graphics
inspect.colors = {
  'bold' : [1, 22],
  'italic' : [3, 23],
  'underline' : [4, 24],
  'inverse' : [7, 27],
  'white' : [37, 39],
  'grey' : [90, 39],
  'black' : [30, 39],
  'blue' : [34, 39],
  'cyan' : [36, 39],
  'green' : [32, 39],
  'magenta' : [35, 39],
  'red' : [31, 39],
  'yellow' : [33, 39]
};

// Don't use 'blue' not visible on cmd.exe
inspect.styles = {
  'special': 'cyan',
  'number': 'yellow',
  'boolean': 'yellow',
  'undefined': 'grey',
  'null': 'bold',
  'string': 'green',
  'date': 'magenta',
  // "name": intentionally not styling
  'regexp': 'red'
};


function stylizeWithColor(str, styleType) {
  const style = inspect.styles[styleType];

  if (style) {
    return '\u001b[' + inspect.colors[style][0] + 'm' + str +
           '\u001b[' + inspect.colors[style][1] + 'm';
  } else {
    return str;
  }
}


function stylizeNoColor(str, styleType) {
  return str;
}


function arrayToHash(array) {
  const hash = {};

  array.forEach(function(val, idx) {
    hash[val] = true;
  });

  return hash;
}


function formatValue(ctx, value, recurseTimes) {
  // Provide a hook for user-specified inspect functions.
  // Check that value is an object with an inspect function on it
  if (ctx.customInspect &&
      value &&
      isFunction(value.inspect) &&
      // Filter out the util module, it's inspect function is special
      value.inspect !== inspect &&
      // Also filter out any prototype objects using the circular check.
      !(value.constructor && value.constructor.prototype === value)) {
    let ret = value.inspect(recurseTimes, ctx);
    if (!isString(ret)) {
      ret = formatValue(ctx, ret, recurseTimes);
    }
    return ret;
  }

  // Primitive types cannot have properties
  const primitive = formatPrimitive(ctx, value);
  if (primitive) {
    return primitive;
  }

  // Look up the keys of the object.
  let keys = Object.keys(value);
  const visibleKeys = arrayToHash(keys);

  if (ctx.showHidden) {
    keys = Object.getOwnPropertyNames(value);
  }

  // IE doesn't make error fields non-enumerable
  // http://msdn.microsoft.com/en-us/library/ie/dww52sbt(v=vs.94).aspx
  if (isError(value)
      && (keys.indexOf('message') >= 0 || keys.indexOf('description') >= 0)) {
    return formatError(value);
  }

  // Some type of object without properties can be shortcutted.
  if (keys.length === 0) {
    if (isFunction(value)) {
      const name = value.name ? ': ' + value.name : '';
      return ctx.stylize('[Function' + name + ']', 'special');
    }
    if (isRegExp(value)) {
      return ctx.stylize(RegExp.prototype.toString.call(value), 'regexp');
    }
    if (isDate(value)) {
      return ctx.stylize(Date.prototype.toString.call(value), 'date');
    }
    if (isError(value)) {
      return formatError(value);
    }
  }

  let base = '', array = false, braces = ['{', '}'];

  // Make Array say that they are Array
  if (isArray(value)) {
    array = true;
    braces = ['[', ']'];
  }

  // Make functions say that they are functions
  if (isFunction(value)) {
    const n = value.name ? ': ' + value.name : '';
    base = ' [Function' + n + ']';
  }

  // Make RegExps say that they are RegExps
  if (isRegExp(value)) {
    base = ' ' + RegExp.prototype.toString.call(value);
  }

  // Make dates with properties first say the date
  if (isDate(value)) {
    base = ' ' + Date.prototype.toUTCString.call(value);
  }

  // Make error with message first say the error
  if (isError(value)) {
    base = ' ' + formatError(value);
  }

  if (keys.length === 0 && (!array || value.length == 0)) {
    return braces[0] + base + braces[1];
  }

  if (recurseTimes < 0) {
    if (isRegExp(value)) {
      return ctx.stylize(RegExp.prototype.toString.call(value), 'regexp');
    } else {
      return ctx.stylize('[Object]', 'special');
    }
  }

  ctx.seen.push(value);

  let output;
  if (array) {
    output = formatArray(ctx, value, recurseTimes, visibleKeys, keys);
  } else {
    output = keys.map(function(key) {
      return formatProperty(ctx, value, recurseTimes, visibleKeys, key, array);
    });
  }

  ctx.seen.pop();

  return reduceToSingleString(output, base, braces);
}


function formatPrimitive(ctx, value) {
  if (isUndefined(value))
    return ctx.stylize('undefined', 'undefined');
  if (isString(value)) {
    const simple = '\'' + JSON.stringify(value).replace(/^"|"$/g, '')
                                               .replace(/'/g, "\\'")
                                               .replace(/\\"/g, '"') + '\'';
    return ctx.stylize(simple, 'string');
  }
  if (isNumber(value))
    return ctx.stylize('' + value, 'number');
  if (isBoolean(value))
    return ctx.stylize('' + value, 'boolean');
  // For some reason typeof null is "object", so special case here.
  if (isNull(value))
    return ctx.stylize('null', 'null');
}


function formatError(value) {
  return '[' + Error.prototype.toString.call(value) + ']';
}


function formatArray(ctx, value, recurseTimes, visibleKeys, keys) {
  const output = [];
  for (let i = 0, l = value.length; i < l; ++i) {
    if (hasOwnProperty(value, String(i))) {
      output.push(formatProperty(ctx, value, recurseTimes, visibleKeys,
          String(i), true));
    } else {
      output.push('');
    }
  }
  keys.forEach(function(key) {
    if (!key.match(/^\d+$/)) {
      output.push(formatProperty(ctx, value, recurseTimes, visibleKeys,
          key, true));
    }
  });
  return output;
}


function formatProperty(ctx, value, recurseTimes, visibleKeys, key, array) {
  let name, str, desc;
  desc = Object.getOwnPropertyDescriptor(value, key) || { value: value[key] };
  if (desc.get) {
    if (desc.set) {
      str = ctx.stylize('[Getter/Setter]', 'special');
    } else {
      str = ctx.stylize('[Getter]', 'special');
    }
  } else {
    if (desc.set) {
      str = ctx.stylize('[Setter]', 'special');
    }
  }
  if (!hasOwnProperty(visibleKeys, key)) {
    name = '[' + key + ']';
  }
  if (!str) {
    if (ctx.seen.indexOf(desc.value) < 0) {
      if (isNull(recurseTimes)) {
        str = formatValue(ctx, desc.value, null);
      } else {
        str = formatValue(ctx, desc.value, recurseTimes - 1);
      }
      if (str.indexOf('\n') > -1) {
        if (array) {
          str = str.split('\n').map(function(line) {
            return '  ' + line;
          }).join('\n').substr(2);
        } else {
          str = '\n' + str.split('\n').map(function(line) {
            return '   ' + line;
          }).join('\n');
        }
      }
    } else {
      str = ctx.stylize('[Circular]', 'special');
    }
  }
  if (isUndefined(name)) {
    if (array && key.match(/^\d+$/)) {
      return str;
    }
    name = JSON.stringify('' + key);
    if (name.match(/^"([a-zA-Z_][a-zA-Z_0-9]*)"$/)) {
      name = name.substr(1, name.length - 2);
      name = ctx.stylize(name, 'name');
    } else {
      name = name.replace(/'/g, "\\'")
                 .replace(/\\"/g, '"')
                 .replace(/(^"|"$)/g, "'");
      name = ctx.stylize(name, 'string');
    }
  }

  return name + ': ' + str;
}


function reduceToSingleString(output, base, braces) {
  let numLinesEst = 0;
  const length = output.reduce(function(prev, cur) {
    numLinesEst++;
    if (cur.indexOf('\n') >= 0) numLinesEst++;
    return prev + cur.replace(/\u001b\[\d\d?m/g, '').length + 1;
  }, 0);

  if (length > 60) {
    return braces[0] +
           (base === '' ? '' : base + '\n ') +
           ' ' +
           output.join(',\n  ') +
           ' ' +
           braces[1];
  }

  return braces[0] + base + ' ' + output.join(', ') + ' ' + braces[1];
}

export function isArray(ar) {
  return Array.isArray(ar);
}

export function isBoolean(arg) {
  return typeof arg === 'boolean';
}

export function isNull(arg) {
  return arg === null;
}

export function isNullOrUndefined(arg) {
  return arg == null;
}

export function isNumber(arg) {
  return typeof arg === 'number';
}

export function isString(arg) {
  return typeof arg === 'string';
}

export function isSymbol(arg) {
  return typeof arg === 'symbol';
}

export function isUndefined(arg) {
  return arg === void 0;
}

export function isRegExp(re) {
  return isObject(re) && objectToString(re) === '[object RegExp]';
}

export function isObject(arg) {
  return typeof arg === 'object' && arg !== null;
}

export function isDate(d) {
  return isObject(d) && objectToString(d) === '[object Date]';
}

export function isError(e) {
  return isObject(e) &&
      (objectToString(e) === '[object Error]' || e instanceof Error);
}

export function isFunction(arg) {
  return typeof arg === 'function';
}

export function isPrimitive(arg) {
  return arg === null ||
         typeof arg === 'boolean' ||
         typeof arg === 'number' ||
         typeof arg === 'string' ||
         typeof arg === 'symbol' ||  // ES6 symbol
         typeof arg === 'undefined';
}

export function isBuffer(arg) {
  return arg instanceof Buffer;
}

function objectToString(o) {
  return Object.prototype.toString.call(o);
}


function pad(n) {
  return n < 10 ? '0' + n.toString(10) : n.toString(10);
}


const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep',
                'Oct', 'Nov', 'Dec'];

// 26 Feb 16:19:34
function timestamp() {
  const d = new Date();
  const time = [pad(d.getHours()),
                pad(d.getMinutes()),
                pad(d.getSeconds())].join(':');
  return [d.getDate(), months[d.getMonth()], time].join(' ');
}


// log is just a thin wrapper to console.log that prepends a timestamp
export function log() {
  console.log('%s - %s', timestamp(), format.apply(null, arguments));
}


/**
 * Inherit the prototype methods from one constructor into another.
 *
 * The Function.prototype.inherits from lang.js rewritten as a standalone
 * function (not on Function.prototype). NOTE: If this file is to be loaded
 * during bootstrapping this function needs to be rewritten using some native
 * functions as prototype setup using normal JavaScript does not work as
 * expected during bootstrapping (see mirror.js in r114903).
 *
 * @param {function} ctor Constructor function which needs to inherit the
 *     prototype.
 * @param {function} superCtor Constructor function to inherit prototype from.
 */
export function inherits(ctor, superCtor) {
  Object.defineProperty(ctor, 'super_', {
    value: superCtor,
    writable: true,
    configurable: true
  });
  Object.setPrototypeOf(ctor.prototype, superCtor.prototype);
}

export function _extend(origin, add) {
  // Don't do anything if add isn't an object
  if (!add || !isObject(add)) return origin;

  const keys = Object.keys(add);
  let i = keys.length;
  while (i--) {
    origin[keys[i]] = add[keys[i]];
  }
  return origin;
}

function hasOwnProperty(obj, prop) {
  return Object.prototype.hasOwnProperty.call(obj, prop);
}

const kCustomPromisifiedSymbol = Symbol('util.promisify.custom');

export function promisify(original) {
  if (typeof original !== 'function')
    throw new TypeError('The "original" argument must be of type Function');

  if (kCustomPromisifiedSymbol && original[kCustomPromisifiedSymbol]) {
    const fn = original[kCustomPromisifiedSymbol];
    if (typeof fn !== 'function') {
      throw new TypeError('The "util.promisify.custom" argument must be of type Function');
    }
    Object.defineProperty(fn, kCustomPromisifiedSymbol, {
      value: fn, enumerable: false, writable: false, configurable: true
    });
    return fn;
  }

  function fn() {
    let promiseResolve, promiseReject;
    const promise = new Promise(function (resolve, reject) {
      promiseResolve = resolve;
      promiseReject = reject;
    });

    const args = [];
    for (let i = 0; i < arguments.length; i++) {
      args.push(arguments[i]);
    }
    args.push(function (err, value) {
      if (err) {
        promiseReject(err);
      } else {
        promiseResolve(value);
      }
    });

    try {
      original.apply(this, args);
    } catch (err) {
      promiseReject(err);
    }

    return promise;
  }

  Object.setPrototypeOf(fn, Object.getPrototypeOf(original));

  if (kCustomPromisifiedSymbol) Object.defineProperty(fn, kCustomPromisifiedSymbol, {
    value: fn, enumerable: false, writable: false, configurable: true
  });
  return Object.defineProperties(
    fn,
    Object.getOwnPropertyDescriptors(original)
  );
}

promisify.custom = kCustomPromisifiedSymbol;

function callbackifyOnRejected(reason, cb) {
  // `!reason` guard inspired by bluebird (Ref: https://goo.gl/t5IS6M).
  // Because `null` is a special error value in callbacks which means "no error
  // occurred", we error-wrap so the callback consumer can distinguish between
  // "the promise rejected with null" or "the promise fulfilled with undefined".
  if (!reason) {
    const newReason = new Error('Promise was rejected with a falsy value');
    newReason.reason = reason;
    reason = newReason;
  }
  return cb(reason);
}

export function callbackify(original) {
  if (typeof original !== 'function') {
    throw new TypeError('The "original" argument must be of type Function');
  }

  // We DO NOT return the promise as it gives the user a false sense that
  // the promise is actually somehow related to the callback's execution
  // and that the callback throwing will reject the promise.
  function callbackified() {
    const args = [];
    for (let i = 0; i < arguments.length; i++) {
      args.push(arguments[i]);
    }

    const maybeCb = args.pop();
    if (typeof maybeCb !== 'function') {
      throw new TypeError('The last argument must be of type Function');
    }
    const self = this;
    const cb = function() {
      return maybeCb.apply(self, arguments);
    };
    // In true node style we process the callback on `nextTick` with all the
    // implications (stack, `uncaughtException`, `async_hooks`)
    original.apply(this, args)
      .then(function(ret) { process.nextTick(cb.bind(null, null, ret)) },
            function(rej) { process.nextTick(callbackifyOnRejected.bind(null, rej, cb)) });
  }

  Object.setPrototypeOf(callbackified, Object.getPrototypeOf(original));
  Object.defineProperties(callbackified,
                          Object.getOwnPropertyDescriptors(original));
  return callbackified;
}

✄
{"version":3,"file":"index.js","sourceRoot":"./","sources":["api.ts","application.ts","dump.ts","exception-listener.ts","filters.ts","gc.ts","utils/android.ts","utils/console.ts","utils/decorate.ts","utils/getter.ts","utils/lazy.ts","utils/native-struct.ts","utils/native-wait.ts","utils/offset-of.ts","utils/read-native-iterator.ts","utils/read-native-list.ts","utils/recycle.ts","utils/unity-version.ts","memory.ts","module.ts","perform.ts","tracer.ts","structs/array.ts","structs/assembly.ts","structs/class.ts","structs/delegate.ts","structs/domain.ts","structs/field.ts","structs/gc-handle.ts","structs/image.ts","structs/memory-snapshot.ts","structs/method.ts","structs/object.ts","structs/parameter.ts","structs/pointer.ts","structs/reference.ts","structs/string.ts","structs/thread.ts","structs/type.ts","structs/value-type.ts","index.ts"],"names":[],"mappings":"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"}
✄
"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var Il2Cpp;
(function (Il2Cpp) {
    /**
     * The **core** object where all the necessary IL2CPP native functions are
     * held. \
     * `frida-il2cpp-bridge` is built around this object by providing an
     * easy-to-use abstraction layer: the user isn't expected to use it directly,
     * but it can in case of advanced use cases.
     *
     * The APIs depends on the Unity version, hence some of them may be
     * unavailable; moreover, they are searched by **name** (e.g.
     * `il2cpp_class_from_name`) hence they might get stripped, hidden or
     * renamed by a nasty obfuscator.
     *
     * However, it is possible to override or set the handle of any of the
     * exports by using a global variable:
     * ```ts
     * declare global {
     *     let IL2CPP_EXPORTS: Record<string, () => NativePointer>;
     * }
     *
     * IL2CPP_EXPORTS = {
     *     il2cpp_image_get_class: () => Il2Cpp.module.base.add(0x1204c),
     *     il2cpp_class_get_parent: () => {
     *         return Memory.scanSync(Il2Cpp.module.base, Il2Cpp.module.size, "2f 10 ee 10 34 a8")[0].address;
     *     },
     * };
     *
     * Il2Cpp.perform(() => {
     *     // ...
     * });
     * ```
     */
    Il2Cpp.api = {
        get alloc() {
            return r("il2cpp_alloc", "pointer", ["size_t"]);
        },
        get arrayGetLength() {
            return r("il2cpp_array_length", "uint32", ["pointer"]);
        },
        get arrayNew() {
            return r("il2cpp_array_new", "pointer", ["pointer", "uint32"]);
        },
        get assemblyGetImage() {
            return r("il2cpp_assembly_get_image", "pointer", ["pointer"]);
        },
        get classForEach() {
            return r("il2cpp_class_for_each", "void", ["pointer", "pointer"]);
        },
        get classFromName() {
            return r("il2cpp_class_from_name", "pointer", ["pointer", "pointer", "pointer"]);
        },
        get classFromObject() {
            return r("il2cpp_class_from_system_type", "pointer", ["pointer"]);
        },
        get classGetArrayClass() {
            return r("il2cpp_array_class_get", "pointer", ["pointer", "uint32"]);
        },
        get classGetArrayElementSize() {
            return r("il2cpp_class_array_element_size", "int", ["pointer"]);
        },
        get classGetAssemblyName() {
            return r("il2cpp_class_get_assemblyname", "pointer", ["pointer"]);
        },
        get classGetBaseType() {
            return r("il2cpp_class_enum_basetype", "pointer", ["pointer"]);
        },
        get classGetDeclaringType() {
            return r("il2cpp_class_get_declaring_type", "pointer", ["pointer"]);
        },
        get classGetElementClass() {
            return r("il2cpp_class_get_element_class", "pointer", ["pointer"]);
        },
        get classGetFieldFromName() {
            return r("il2cpp_class_get_field_from_name", "pointer", ["pointer", "pointer"]);
        },
        get classGetFields() {
            return r("il2cpp_class_get_fields", "pointer", ["pointer", "pointer"]);
        },
        get classGetFlags() {
            return r("il2cpp_class_get_flags", "int", ["pointer"]);
        },
        get classGetImage() {
            return r("il2cpp_class_get_image", "pointer", ["pointer"]);
        },
        get classGetInstanceSize() {
            return r("il2cpp_class_instance_size", "int32", ["pointer"]);
        },
        get classGetInterfaces() {
            return r("il2cpp_class_get_interfaces", "pointer", ["pointer", "pointer"]);
        },
        get classGetMethodFromName() {
            return r("il2cpp_class_get_method_from_name", "pointer", ["pointer", "pointer", "int"]);
        },
        get classGetMethods() {
            return r("il2cpp_class_get_methods", "pointer", ["pointer", "pointer"]);
        },
        get classGetName() {
            return r("il2cpp_class_get_name", "pointer", ["pointer"]);
        },
        get classGetNamespace() {
            return r("il2cpp_class_get_namespace", "pointer", ["pointer"]);
        },
        get classGetNestedClasses() {
            return r("il2cpp_class_get_nested_types", "pointer", ["pointer", "pointer"]);
        },
        get classGetParent() {
            return r("il2cpp_class_get_parent", "pointer", ["pointer"]);
        },
        get classGetStaticFieldData() {
            return r("il2cpp_class_get_static_field_data", "pointer", ["pointer"]);
        },
        get classGetValueTypeSize() {
            return r("il2cpp_class_value_size", "int32", ["pointer", "pointer"]);
        },
        get classGetType() {
            return r("il2cpp_class_get_type", "pointer", ["pointer"]);
        },
        get classHasReferences() {
            return r("il2cpp_class_has_references", "bool", ["pointer"]);
        },
        get classInitialize() {
            return r("il2cpp_runtime_class_init", "void", ["pointer"]);
        },
        get classIsAbstract() {
            return r("il2cpp_class_is_abstract", "bool", ["pointer"]);
        },
        get classIsAssignableFrom() {
            return r("il2cpp_class_is_assignable_from", "bool", ["pointer", "pointer"]);
        },
        get classIsBlittable() {
            return r("il2cpp_class_is_blittable", "bool", ["pointer"]);
        },
        get classIsEnum() {
            return r("il2cpp_class_is_enum", "bool", ["pointer"]);
        },
        get classIsGeneric() {
            return r("il2cpp_class_is_generic", "bool", ["pointer"]);
        },
        get classIsInflated() {
            return r("il2cpp_class_is_inflated", "bool", ["pointer"]);
        },
        get classIsInterface() {
            return r("il2cpp_class_is_interface", "bool", ["pointer"]);
        },
        get classIsSubclassOf() {
            return r("il2cpp_class_is_subclass_of", "bool", ["pointer", "pointer", "bool"]);
        },
        get classIsValueType() {
            return r("il2cpp_class_is_valuetype", "bool", ["pointer"]);
        },
        get domainGetAssemblyFromName() {
            return r("il2cpp_domain_assembly_open", "pointer", ["pointer", "pointer"]);
        },
        get domainGet() {
            return r("il2cpp_domain_get", "pointer", []);
        },
        get domainGetAssemblies() {
            return r("il2cpp_domain_get_assemblies", "pointer", ["pointer", "pointer"]);
        },
        get fieldGetClass() {
            return r("il2cpp_field_get_parent", "pointer", ["pointer"]);
        },
        get fieldGetFlags() {
            return r("il2cpp_field_get_flags", "int", ["pointer"]);
        },
        get fieldGetName() {
            return r("il2cpp_field_get_name", "pointer", ["pointer"]);
        },
        get fieldGetOffset() {
            return r("il2cpp_field_get_offset", "int32", ["pointer"]);
        },
        get fieldGetStaticValue() {
            return r("il2cpp_field_static_get_value", "void", ["pointer", "pointer"]);
        },
        get fieldGetType() {
            return r("il2cpp_field_get_type", "pointer", ["pointer"]);
        },
        get fieldSetStaticValue() {
            return r("il2cpp_field_static_set_value", "void", ["pointer", "pointer"]);
        },
        get free() {
            return r("il2cpp_free", "void", ["pointer"]);
        },
        get gcCollect() {
            return r("il2cpp_gc_collect", "void", ["int"]);
        },
        get gcCollectALittle() {
            return r("il2cpp_gc_collect_a_little", "void", []);
        },
        get gcDisable() {
            return r("il2cpp_gc_disable", "void", []);
        },
        get gcEnable() {
            return r("il2cpp_gc_enable", "void", []);
        },
        get gcGetHeapSize() {
            return r("il2cpp_gc_get_heap_size", "int64", []);
        },
        get gcGetMaxTimeSlice() {
            return r("il2cpp_gc_get_max_time_slice_ns", "int64", []);
        },
        get gcGetUsedSize() {
            return r("il2cpp_gc_get_used_size", "int64", []);
        },
        get gcHandleGetTarget() {
            return r("il2cpp_gchandle_get_target", "pointer", ["uint32"]);
        },
        get gcHandleFree() {
            return r("il2cpp_gchandle_free", "void", ["uint32"]);
        },
        get gcHandleNew() {
            return r("il2cpp_gchandle_new", "uint32", ["pointer", "bool"]);
        },
        get gcHandleNewWeakRef() {
            return r("il2cpp_gchandle_new_weakref", "uint32", ["pointer", "bool"]);
        },
        get gcIsDisabled() {
            return r("il2cpp_gc_is_disabled", "bool", []);
        },
        get gcIsIncremental() {
            return r("il2cpp_gc_is_incremental", "bool", []);
        },
        get gcSetMaxTimeSlice() {
            return r("il2cpp_gc_set_max_time_slice_ns", "void", ["int64"]);
        },
        get gcStartIncrementalCollection() {
            return r("il2cpp_gc_start_incremental_collection", "void", []);
        },
        get gcStartWorld() {
            return r("il2cpp_start_gc_world", "void", []);
        },
        get gcStopWorld() {
            return r("il2cpp_stop_gc_world", "void", []);
        },
        get getCorlib() {
            return r("il2cpp_get_corlib", "pointer", []);
        },
        get imageGetAssembly() {
            return r("il2cpp_image_get_assembly", "pointer", ["pointer"]);
        },
        get imageGetClass() {
            return r("il2cpp_image_get_class", "pointer", ["pointer", "uint"]);
        },
        get imageGetClassCount() {
            return r("il2cpp_image_get_class_count", "uint32", ["pointer"]);
        },
        get imageGetName() {
            return r("il2cpp_image_get_name", "pointer", ["pointer"]);
        },
        get initialize() {
            return r("il2cpp_init", "void", ["pointer"]);
        },
        get livenessAllocateStruct() {
            return r("il2cpp_unity_liveness_allocate_struct", "pointer", ["pointer", "int", "pointer", "pointer", "pointer"]);
        },
        get livenessCalculationBegin() {
            return r("il2cpp_unity_liveness_calculation_begin", "pointer", ["pointer", "int", "pointer", "pointer", "pointer", "pointer"]);
        },
        get livenessCalculationEnd() {
            return r("il2cpp_unity_liveness_calculation_end", "void", ["pointer"]);
        },
        get livenessCalculationFromStatics() {
            return r("il2cpp_unity_liveness_calculation_from_statics", "void", ["pointer"]);
        },
        get livenessFinalize() {
            return r("il2cpp_unity_liveness_finalize", "void", ["pointer"]);
        },
        get livenessFreeStruct() {
            return r("il2cpp_unity_liveness_free_struct", "void", ["pointer"]);
        },
        get memorySnapshotCapture() {
            return r("il2cpp_capture_memory_snapshot", "pointer", []);
        },
        get memorySnapshotFree() {
            return r("il2cpp_free_captured_memory_snapshot", "void", ["pointer"]);
        },
        get memorySnapshotGetClasses() {
            return r("il2cpp_memory_snapshot_get_classes", "pointer", ["pointer", "pointer"]);
        },
        get memorySnapshotGetObjects() {
            return r("il2cpp_memory_snapshot_get_objects", "pointer", ["pointer", "pointer"]);
        },
        get methodGetClass() {
            return r("il2cpp_method_get_class", "pointer", ["pointer"]);
        },
        get methodGetFlags() {
            return r("il2cpp_method_get_flags", "uint32", ["pointer", "pointer"]);
        },
        get methodGetName() {
            return r("il2cpp_method_get_name", "pointer", ["pointer"]);
        },
        get methodGetObject() {
            return r("il2cpp_method_get_object", "pointer", ["pointer", "pointer"]);
        },
        get methodGetParameterCount() {
            return r("il2cpp_method_get_param_count", "uint8", ["pointer"]);
        },
        get methodGetParameterName() {
            return r("il2cpp_method_get_param_name", "pointer", ["pointer", "uint32"]);
        },
        get methodGetParameters() {
            return r("il2cpp_method_get_parameters", "pointer", ["pointer", "pointer"]);
        },
        get methodGetParameterType() {
            return r("il2cpp_method_get_param", "pointer", ["pointer", "uint32"]);
        },
        get methodGetReturnType() {
            return r("il2cpp_method_get_return_type", "pointer", ["pointer"]);
        },
        get methodIsGeneric() {
            return r("il2cpp_method_is_generic", "bool", ["pointer"]);
        },
        get methodIsInflated() {
            return r("il2cpp_method_is_inflated", "bool", ["pointer"]);
        },
        get methodIsInstance() {
            return r("il2cpp_method_is_instance", "bool", ["pointer"]);
        },
        get monitorEnter() {
            return r("il2cpp_monitor_enter", "void", ["pointer"]);
        },
        get monitorExit() {
            return r("il2cpp_monitor_exit", "void", ["pointer"]);
        },
        get monitorPulse() {
            return r("il2cpp_monitor_pulse", "void", ["pointer"]);
        },
        get monitorPulseAll() {
            return r("il2cpp_monitor_pulse_all", "void", ["pointer"]);
        },
        get monitorTryEnter() {
            return r("il2cpp_monitor_try_enter", "bool", ["pointer", "uint32"]);
        },
        get monitorTryWait() {
            return r("il2cpp_monitor_try_wait", "bool", ["pointer", "uint32"]);
        },
        get monitorWait() {
            return r("il2cpp_monitor_wait", "void", ["pointer"]);
        },
        get objectGetClass() {
            return r("il2cpp_object_get_class", "pointer", ["pointer"]);
        },
        get objectGetVirtualMethod() {
            return r("il2cpp_object_get_virtual_method", "pointer", ["pointer", "pointer"]);
        },
        get objectInitialize() {
            return r("il2cpp_runtime_object_init_exception", "void", ["pointer", "pointer"]);
        },
        get objectNew() {
            return r("il2cpp_object_new", "pointer", ["pointer"]);
        },
        get objectGetSize() {
            return r("il2cpp_object_get_size", "uint32", ["pointer"]);
        },
        get objectUnbox() {
            return r("il2cpp_object_unbox", "pointer", ["pointer"]);
        },
        get resolveInternalCall() {
            return r("il2cpp_resolve_icall", "pointer", ["pointer"]);
        },
        get stringGetChars() {
            return r("il2cpp_string_chars", "pointer", ["pointer"]);
        },
        get stringGetLength() {
            return r("il2cpp_string_length", "int32", ["pointer"]);
        },
        get stringNew() {
            return r("il2cpp_string_new", "pointer", ["pointer"]);
        },
        get valueTypeBox() {
            return r("il2cpp_value_box", "pointer", ["pointer", "pointer"]);
        },
        get threadAttach() {
            return r("il2cpp_thread_attach", "pointer", ["pointer"]);
        },
        get threadDetach() {
            return r("il2cpp_thread_detach", "void", ["pointer"]);
        },
        get threadGetAttachedThreads() {
            return r("il2cpp_thread_get_all_attached_threads", "pointer", ["pointer"]);
        },
        get threadGetCurrent() {
            return r("il2cpp_thread_current", "pointer", []);
        },
        get threadIsVm() {
            return r("il2cpp_is_vm_thread", "bool", ["pointer"]);
        },
        get typeGetClass() {
            return r("il2cpp_class_from_type", "pointer", ["pointer"]);
        },
        get typeGetName() {
            return r("il2cpp_type_get_name", "pointer", ["pointer"]);
        },
        get typeGetObject() {
            return r("il2cpp_type_get_object", "pointer", ["pointer"]);
        },
        get typeGetTypeEnum() {
            return r("il2cpp_type_get_type", "int", ["pointer"]);
        }
    };
    decorate(Il2Cpp.api, lazy);
    getter(Il2Cpp, "memorySnapshotApi", () => new CModule("#include <stdint.h>\n#include <string.h>\n\ntypedef struct Il2CppManagedMemorySnapshot Il2CppManagedMemorySnapshot;\ntypedef struct Il2CppMetadataType Il2CppMetadataType;\n\nstruct Il2CppManagedMemorySnapshot\n{\n  struct Il2CppManagedHeap\n  {\n    uint32_t section_count;\n    void * sections;\n  } heap;\n  struct Il2CppStacks\n  {\n    uint32_t stack_count;\n    void * stacks;\n  } stacks;\n  struct Il2CppMetadataSnapshot\n  {\n    uint32_t type_count;\n    Il2CppMetadataType * types;\n  } metadata_snapshot;\n  struct Il2CppGCHandles\n  {\n    uint32_t tracked_object_count;\n    void ** pointers_to_objects;\n  } gc_handles;\n  struct Il2CppRuntimeInformation\n  {\n    uint32_t pointer_size;\n    uint32_t object_header_size;\n    uint32_t array_header_size;\n    uint32_t array_bounds_offset_in_header;\n    uint32_t array_size_offset_in_header;\n    uint32_t allocation_granularity;\n  } runtime_information;\n  void * additional_user_information;\n};\n\nstruct Il2CppMetadataType\n{\n  uint32_t flags;\n  void * fields;\n  uint32_t field_count;\n  uint32_t statics_size;\n  uint8_t * statics;\n  uint32_t base_or_element_type_index;\n  char * name;\n  const char * assembly_name;\n  uint64_t type_info_address;\n  uint32_t size;\n};\n\nuintptr_t\nil2cpp_memory_snapshot_get_classes (\n    const Il2CppManagedMemorySnapshot * snapshot, Il2CppMetadataType ** iter)\n{\n  const int zero = 0;\n  const void * null = 0;\n\n  if (iter != NULL && snapshot->metadata_snapshot.type_count > zero)\n  {\n    if (*iter == null)\n    {\n      *iter = snapshot->metadata_snapshot.types;\n      return (uintptr_t) (*iter)->type_info_address;\n    }\n    else\n    {\n      Il2CppMetadataType * metadata_type = *iter + 1;\n\n      if (metadata_type < snapshot->metadata_snapshot.types +\n                              snapshot->metadata_snapshot.type_count)\n      {\n        *iter = metadata_type;\n        return (uintptr_t) (*iter)->type_info_address;\n      }\n    }\n  }\n  return 0;\n}\n\nvoid **\nil2cpp_memory_snapshot_get_objects (\n    const Il2CppManagedMemorySnapshot * snapshot, uint32_t * size)\n{\n  *size = snapshot->gc_handles.tracked_object_count;\n  return snapshot->gc_handles.pointers_to_objects;\n}\n"), lazy);
    function r(exportName, retType, argTypes) {
        const handle = globalThis.IL2CPP_EXPORTS?.[exportName]?.() ?? Il2Cpp.module.findExportByName(exportName) ?? Il2Cpp.memorySnapshotApi[exportName];
        return new NativeFunction(handle ?? raise(`couldn't resolve export ${exportName}`), retType, argTypes);
    }
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    /** */
    Il2Cpp.application = {
        /**
         * Gets the data path name of the current application, e.g.
         * `/data/emulated/0/Android/data/com.example.application/files`
         * on Android.
         *
         * **This information is not guaranteed to exist.**
         *
         * ```ts
         * Il2Cpp.perform(() => {
         *     // prints /data/emulated/0/Android/data/com.example.application/files
         *     console.log(Il2Cpp.application.dataPath);
         * });
         * ```
         */
        get dataPath() {
            return unityEngineCall("get_persistentDataPath");
        },
        /**
         * Gets the identifier name of the current application, e.g.
         * `com.example.application` on Android.
         *
         * **This information is not guaranteed to exist.**
         *
         * ```ts
         * Il2Cpp.perform(() => {
         *     // prints com.example.application
         *     console.log(Il2Cpp.application.identifier);
         * });
         * ```
         */
        get identifier() {
            return unityEngineCall("get_identifier") ?? unityEngineCall("get_bundleIdentifier");
        },
        /**
         * Gets the version name of the current application, e.g. `4.12.8`.
         *
         * **This information is not guaranteed to exist.**
         *
         * ```ts
         * Il2Cpp.perform(() => {
         *     // prints 4.12.8
         *     console.log(Il2Cpp.application.version);
         * });
         * ```
         */
        get version() {
            return unityEngineCall("get_version");
        }
    };
    // prettier-ignore
    getter(Il2Cpp, "unityVersion", () => {
        try {
            const unityVersion = globalThis.IL2CPP_UNITY_VERSION ?? unityEngineCall("get_unityVersion");
            if (unityVersion != null) {
                return unityVersion;
            }
        }
        catch (_) {
        }
        const searchPattern = "69 6c 32 63 70 70";
        for (const range of Il2Cpp.module.enumerateRanges("r--").concat(Process.getRangeByAddress(Il2Cpp.module.base))) {
            for (let { address } of Memory.scanSync(range.base, range.size, searchPattern)) {
                while (address.readU8() != 0) {
                    address = address.sub(1);
                }
                const match = UnityVersion.find(address.add(1).readCString());
                if (match != undefined) {
                    return match;
                }
            }
        }
        raise("couldn't determine the Unity version, please specify it manually");
    }, lazy);
    // prettier-ignore
    getter(Il2Cpp, "unityVersionIsBelow201830", () => {
        return UnityVersion.lt(Il2Cpp.unityVersion, "2018.3.0");
    }, lazy);
    // prettier-ignore
    getter(Il2Cpp, "unityVersionIsBelow202120", () => {
        return UnityVersion.lt(Il2Cpp.unityVersion, "2021.2.0");
    }, lazy);
    function unityEngineCall(method) {
        const handle = Il2Cpp.api.resolveInternalCall(Memory.allocUtf8String("UnityEngine.Application::" + method));
        const nativeFunction = new NativeFunction(handle, "pointer", []);
        return nativeFunction.isNull() ? null : new Il2Cpp.String(nativeFunction()).asNullable()?.content ?? null;
    }
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    /**
     * Dumps the application, i.e. it creates a dummy `.cs` file that contains
     * all the class, field and method declarations.
     *
     * The dump is very useful when it comes to inspecting the application as
     * you can easily search for succulent members using a simple text search,
     * hence this is typically the very first thing it should be done when
     * working with a new application. \
     * Keep in mind the dump is version, platform and arch dependentend, so
     * it has to be re-genereated if any of these changes.
     *
     * The file is generated in the **target** device, so you might need to
     * pull it to the host device afterwards.
     *
     * Dumping *may* require a file name and a directory path (a place where the
     * application can write to). If not provided, the target path is generated
     * automatically using the information from {@link Il2Cpp.application}.
     *
     * ```ts
     * Il2Cpp.perform(() => {
     *     Il2Cpp.dump();
     * });
     * ```
     *
     * For instance, the dump resembles the following:
     * ```
     * class Mono.DataConverter.PackContext : System.Object
     * {
     *     System.Byte[] buffer; // 0x10
     *     System.Int32 next; // 0x18
     *     System.String description; // 0x20
     *     System.Int32 i; // 0x28
     *     Mono.DataConverter conv; // 0x30
     *     System.Int32 repeat; // 0x38
     *     System.Int32 align; // 0x3c
     *
     *     System.Void Add(System.Byte[] group); // 0x012ef4f0
     *     System.Byte[] Get(); // 0x012ef6ec
     *     System.Void .ctor(); // 0x012ef78c
     *   }
     * ```
     */
    function dump(fileName, path) {
        fileName = fileName ?? `${Il2Cpp.application.identifier ?? "unknown"}_${Il2Cpp.application.version ?? "unknown"}.cs`;
        const destination = `${path ?? Il2Cpp.application.dataPath}/${fileName}`;
        const file = new File(destination, "w");
        for (const assembly of Il2Cpp.domain.assemblies) {
            inform(`dumping ${assembly.name}...`);
            for (const klass of assembly.image.classes) {
                file.write(`${klass}\n\n`);
            }
        }
        file.flush();
        file.close();
        ok(`dump saved to ${destination}`);
    }
    Il2Cpp.dump = dump;
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    /**
     * Installs a listener to track any thrown (unrecoverable) C# exception. \
     * This may be useful when incurring in `abort was called` errors.
     *
     * By default, it only tracks exceptions that were thrown by the *caller*
     * thread.
     *
     * **It may not work for every platform.**
     *
     * ```ts
     * Il2Cpp.perform(() => {
     *     Il2Cpp.installExceptionListener("all");
     *
     *     // rest of the code
     * });
     * ```
     *
     * For instance, it may print something along:
     * ```
     * System.NullReferenceException: Object reference not set to an instance of an object.
     *   at AddressableLoadWrapper+<LoadGameObject>d__3[T].MoveNext () [0x00000] in <00000000000000000000000000000000>:0
     *   at UnityEngine.SetupCoroutine.InvokeMoveNext (System.Collections.IEnumerator enumerator, System.IntPtr returnValueAddress) [0x00000] in <00000000000000000000000000000000>:0
     * ```
     */
    function installExceptionListener(targetThread = "current") {
        const currentThread = Il2Cpp.api.threadGetCurrent();
        return Interceptor.attach(Il2Cpp.module.getExportByName("__cxa_throw"), function (args) {
            if (targetThread == "current" && !Il2Cpp.api.threadGetCurrent().equals(currentThread)) {
                return;
            }
            inform(new Il2Cpp.Object(args[0].readPointer()));
        });
    }
    Il2Cpp.installExceptionListener = installExceptionListener;
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    /**
     * Creates a filter to include elements whose type can be assigned to a
     * variable of the given class. \
     * It relies on {@link Il2Cpp.Class.isAssignableFrom}.
     *
     * ```ts
     * const IComparable = Il2Cpp.corlib.class("System.IComparable");
     *
     * const objects = [
     *     Il2Cpp.corlib.class("System.Object").new(),
     *     Il2Cpp.corlib.class("System.String").new()
     * ];
     *
     * const comparables = objects.filter(Il2Cpp.is(IComparable));
     * ```
     */
    function is(klass) {
        return (element) => {
            if (element instanceof Il2Cpp.Class) {
                return klass.isAssignableFrom(element);
            }
            else {
                return klass.isAssignableFrom(element.class);
            }
        };
    }
    Il2Cpp.is = is;
    /**
     * Creates a filter to include elements whose type can be corresponds to
     * the given class. \
     * It compares the native handle of the element classes.
     *
     * ```ts
     * const String = Il2Cpp.corlib.class("System.String");
     *
     * const objects = [
     *     Il2Cpp.corlib.class("System.Object").new(),
     *     Il2Cpp.corlib.class("System.String").new()
     * ];
     *
     * const strings = objects.filter(Il2Cpp.isExactly(String));
     * ```
     */
    function isExactly(klass) {
        return (element) => {
            if (element instanceof Il2Cpp.Class) {
                return element.equals(klass);
            }
            else {
                return element.class.equals(klass);
            }
        };
    }
    Il2Cpp.isExactly = isExactly;
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    /**
     * The object literal to interacts with the garbage collector.
     */
    Il2Cpp.gc = {
        /**
         * Gets the heap size in bytes.
         */
        get heapSize() {
            return Il2Cpp.api.gcGetHeapSize();
        },
        /**
         * Determines whether the garbage collector is enabled.
         */
        get isEnabled() {
            return !Il2Cpp.api.gcIsDisabled();
        },
        /**
         * Determines whether the garbage collector is incremental
         * ([source](https://docs.unity3d.com/Manual/performance-incremental-garbage-collection.html)).
         */
        get isIncremental() {
            return !!Il2Cpp.api.gcIsIncremental();
        },
        /**
         * Gets the number of nanoseconds the garbage collector can spend in a
         * collection step.
         */
        get maxTimeSlice() {
            return Il2Cpp.api.gcGetMaxTimeSlice();
        },
        /**
         * Gets the used heap size in bytes.
         */
        get usedHeapSize() {
            return Il2Cpp.api.gcGetUsedSize();
        },
        /**
         * Enables or disables the garbage collector.
         */
        set isEnabled(value) {
            value ? Il2Cpp.api.gcEnable() : Il2Cpp.api.gcDisable();
        },
        /**
         *  Sets the number of nanoseconds the garbage collector can spend in
         * a collection step.
         */
        set maxTimeSlice(nanoseconds) {
            Il2Cpp.api.gcSetMaxTimeSlice(nanoseconds);
        },
        /**
         * Returns the heap allocated objects of the specified class. \
         * This variant reads GC descriptors.
         */
        choose(klass) {
            const matches = [];
            const callback = (objects, size) => {
                for (let i = 0; i < size; i++) {
                    matches.push(new Il2Cpp.Object(objects.add(i * Process.pointerSize).readPointer()));
                }
            };
            const chooseCallback = new NativeCallback(callback, "void", ["pointer", "int", "pointer"]);
            if (Il2Cpp.unityVersionIsBelow202120) {
                const onWorld = new NativeCallback(() => { }, "void", []);
                const state = Il2Cpp.api.livenessCalculationBegin(klass, 0, chooseCallback, NULL, onWorld, onWorld);
                Il2Cpp.api.livenessCalculationFromStatics(state);
                Il2Cpp.api.livenessCalculationEnd(state);
            }
            else {
                const realloc = (handle, size) => {
                    if (!handle.isNull() && size.compare(0) == 0) {
                        Il2Cpp.free(handle);
                        return NULL;
                    }
                    else {
                        return Il2Cpp.alloc(size);
                    }
                };
                const reallocCallback = new NativeCallback(realloc, "pointer", ["pointer", "size_t", "pointer"]);
                this.stopWorld();
                const state = Il2Cpp.api.livenessAllocateStruct(klass, 0, chooseCallback, NULL, reallocCallback);
                Il2Cpp.api.livenessCalculationFromStatics(state);
                Il2Cpp.api.livenessFinalize(state);
                this.startWorld();
                Il2Cpp.api.livenessFreeStruct(state);
            }
            return matches;
        },
        /**
         * Forces a garbage collection of the specified generation.
         */
        collect(generation) {
            Il2Cpp.api.gcCollect(generation < 0 ? 0 : generation > 2 ? 2 : generation);
        },
        /**
         * Forces a garbage collection.
         */
        collectALittle() {
            Il2Cpp.api.gcCollectALittle();
        },
        /**
         *  Resumes all the previously stopped threads.
         */
        startWorld() {
            return Il2Cpp.api.gcStartWorld();
        },
        /**
         * Performs an incremental garbage collection.
         */
        startIncrementalCollection() {
            return Il2Cpp.api.gcStartIncrementalCollection();
        },
        /**
         * Stops all threads which may access the garbage collected heap, other
         * than the caller.
         */
        stopWorld() {
            return Il2Cpp.api.gcStopWorld();
        }
    };
})(Il2Cpp || (Il2Cpp = {}));
/** @internal */
var Android;
(function (Android) {
    // prettier-ignore
    getter(Android, "apiLevel", () => {
        const value = getProperty("ro.build.version.sdk");
        return value ? parseInt(value) : null;
    }, lazy);
    function getProperty(name) {
        const handle = Module.findExportByName("libc.so", "__system_property_get");
        if (handle) {
            const __system_property_get = new NativeFunction(handle, "void", ["pointer", "pointer"]);
            const value = Memory.alloc(92).writePointer(NULL);
            __system_property_get(Memory.allocUtf8String(name), value);
            return value.readCString() ?? undefined;
        }
    }
})(Android || (Android = {}));
/** @internal */
function raise(message) {
    const error = new Error(`\x1b[0m${message}`);
    error.name = `\x1b[0m\x1b[38;5;9mil2cpp\x1b[0m`;
    error.stack = error.stack
        ?.replace(/^Error/, error.name)
        ?.replace(/\n    at (.+) \((.+):(.+)\)/, "\x1b[3m\x1b[2m")
        ?.concat("\x1B[0m");
    throw error;
}
/** @internal */
function warn(message) {
    globalThis.console.log(`\x1b[38;5;11mil2cpp\x1b[0m: ${message}`);
}
/** @internal */
function ok(message) {
    globalThis.console.log(`\x1b[38;5;10mil2cpp\x1b[0m: ${message}`);
}
/** @internal */
function inform(message) {
    globalThis.console.log(`\x1b[38;5;12mil2cpp\x1b[0m: ${message}`);
}
/** @internal */
function decorate(target, decorator, descriptors = Object.getOwnPropertyDescriptors(target)) {
    for (const key in descriptors) {
        descriptors[key] = decorator(target, key, descriptors[key]);
    }
    Object.defineProperties(target, descriptors);
    return target;
}
/** @internal */
function getter(target, key, get, decorator) {
    globalThis.Object.defineProperty(target, key, decorator?.(target, key, { get, configurable: true }) ?? { get, configurable: true });
}
/** @internal */
function lazy(_, propertyKey, descriptor) {
    const getter = descriptor.get;
    if (!getter) {
        throw new Error("@lazy can only be applied to getter accessors");
    }
    descriptor.get = function () {
        const value = getter.call(this);
        Object.defineProperty(this, propertyKey, {
            value,
            configurable: descriptor.configurable,
            enumerable: descriptor.enumerable,
            writable: false
        });
        return value;
    };
    return descriptor;
}
/** Scaffold class. */
class NativeStruct {
    handle;
    constructor(handleOrWrapper) {
        if (handleOrWrapper instanceof NativePointer) {
            this.handle = handleOrWrapper;
        }
        else {
            this.handle = handleOrWrapper.handle;
        }
    }
    equals(other) {
        return this.handle.equals(other.handle);
    }
    isNull() {
        return this.handle.isNull();
    }
    asNullable() {
        return this.isNull() ? null : this;
    }
}
/** @internal */
function forModule(...moduleNames) {
    function find(moduleName, name, readString = _ => _.readUtf8String()) {
        const handle = Module.findExportByName(moduleName, name) ?? NULL;
        if (!handle.isNull()) {
            return { handle, readString };
        }
    }
    return new Promise(resolve => {
        for (const moduleName of moduleNames) {
            const module = Process.findModuleByName(moduleName);
            if (module != null) {
                resolve(module);
                return;
            }
        }
        let targets = [];
        switch (Process.platform) {
            case "linux":
                if (Android.apiLevel == null) {
                    targets = [find(null, "dlopen")];
                    break;
                }
                // A5: device reboot, can't hook symbols
                // A6, A7: __dl_open
                // A8, A8.1: __dl__Z8__dlopenPKciPKv
                // A9, A10, A12, A13: __dl___loader_dlopen
                targets = (Process.findModuleByName("linker64") ?? Process.getModuleByName("linker"))
                    .enumerateSymbols()
                    .filter(_ => ["__dl___loader_dlopen", "__dl__Z8__dlopenPKciPKv", "__dl_open"].includes(_.name))
                    .map(_ => ({ handle: _.address, readString: _ => _.readCString() }));
                break;
            case "darwin":
                targets = [find("libdyld.dylib", "dlopen")];
                break;
            case "windows":
                targets = [
                    find("kernel32.dll", "LoadLibraryW", _ => _.readUtf16String()),
                    find("kernel32.dll", "LoadLibraryExW", _ => _.readUtf16String()),
                    find("kernel32.dll", "LoadLibraryA", _ => _.readAnsiString()),
                    find("kernel32.dll", "LoadLibraryExA", _ => _.readAnsiString())
                ];
                break;
        }
        targets = targets.filter(_ => _);
        if (targets.length == 0) {
            raise(`there are no targets to hook the loading of \x1b[3m${moduleNames}\x1b[0m, please file a bug`);
        }
        const timeout = setTimeout(() => {
            for (const moduleName of moduleNames) {
                const module = Process.findModuleByName(moduleName);
                if (module != null) {
                    warn(`\x1b[3m${module.name}\x1b[0m has been loaded, but such event hasn't been detected - please file a bug`);
                    clearTimeout(timeout);
                    interceptors.forEach(_ => _.detach());
                    resolve(module);
                    return;
                }
            }
            warn(`10 seconds have passed and \x1b[3m${moduleNames}\x1b[0m has not been loaded yet, is the app running?`);
        }, 10000);
        const interceptors = targets.map(_ => Interceptor.attach(_.handle, {
            onEnter(args) {
                this.modulePath = _.readString(args[0]) ?? "";
            },
            onLeave(_) {
                for (const moduleName of moduleNames) {
                    if (this.modulePath.endsWith(moduleName)) {
                        // Adding a fallback in case Frida cannot find the module by its full path
                        // https://github.com/vfsfitvnm/frida-il2cpp-bridge/issues/547
                        const module = Process.findModuleByName(this.modulePath) ?? Process.findModuleByName(moduleName);
                        if (module != null) {
                            setImmediate(() => {
                                clearTimeout(timeout);
                                interceptors.forEach(_ => _.detach());
                            });
                            resolve(module);
                            break;
                        }
                    }
                }
            }
        }));
    });
}
NativePointer.prototype.offsetOf = function (condition, depth) {
    depth ??= 512;
    for (let i = 0; depth > 0 ? i < depth : i < -depth; i++) {
        if (condition(depth > 0 ? this.add(i) : this.sub(i))) {
            return i;
        }
    }
    return null;
};
/** @internal */
function readNativeIterator(block) {
    const array = [];
    const iterator = Memory.alloc(Process.pointerSize);
    let handle = block(iterator);
    while (!handle.isNull()) {
        array.push(handle);
        handle = block(iterator);
    }
    return array;
}
/** @internal */
function readNativeList(block) {
    const lengthPointer = Memory.alloc(Process.pointerSize);
    const startPointer = block(lengthPointer);
    if (startPointer.isNull()) {
        return [];
    }
    const array = new Array(lengthPointer.readInt());
    for (let i = 0; i < array.length; i++) {
        array[i] = startPointer.add(i * Process.pointerSize).readPointer();
    }
    return array;
}
/** @internal */
function recycle(Class) {
    return new Proxy(Class, {
        cache: new Map(),
        construct(Target, argArray) {
            const handle = argArray[0].toUInt32();
            if (!this.cache.has(handle)) {
                this.cache.set(handle, new Target(argArray[0]));
            }
            return this.cache.get(handle);
        }
    });
}
/** @internal */
var UnityVersion;
(function (UnityVersion) {
    const pattern = /(20\d{2}|\d)\.(\d)\.(\d{1,2})(?:[abcfp]|rc){0,2}\d?/;
    function find(string) {
        return string?.match(pattern)?.[0];
    }
    UnityVersion.find = find;
    function gte(a, b) {
        return compare(a, b) >= 0;
    }
    UnityVersion.gte = gte;
    function lt(a, b) {
        return compare(a, b) < 0;
    }
    UnityVersion.lt = lt;
    function compare(a, b) {
        const aMatches = a.match(pattern);
        const bMatches = b.match(pattern);
        for (let i = 1; i <= 3; i++) {
            const a = Number(aMatches?.[i] ?? -1);
            const b = Number(bMatches?.[i] ?? -1);
            if (a > b)
                return 1;
            else if (a < b)
                return -1;
        }
        return 0;
    }
})(UnityVersion || (UnityVersion = {}));
var Il2Cpp;
(function (Il2Cpp) {
    /**
     * Allocates the given amount of bytes - it's equivalent to C's `malloc`. \
     * The allocated memory should be freed manually.
     */
    function alloc(size = Process.pointerSize) {
        return Il2Cpp.api.alloc(size);
    }
    Il2Cpp.alloc = alloc;
    /**
     * Frees a previously allocated memory using {@link Il2Cpp.alloc} - it's
     *  equivalent to C's `free`..
     *
     * ```ts
     * const handle = Il2Cpp.alloc(64);
     *
     * // ...
     *
     * Il2Cpp.free(handle);
     * ```
     */
    function free(pointer) {
        return Il2Cpp.api.free(pointer);
    }
    Il2Cpp.free = free;
    /** @internal */
    function read(pointer, type) {
        switch (type.typeEnum) {
            case Il2Cpp.Type.enum.boolean:
                return !!pointer.readS8();
            case Il2Cpp.Type.enum.byte:
                return pointer.readS8();
            case Il2Cpp.Type.enum.unsignedByte:
                return pointer.readU8();
            case Il2Cpp.Type.enum.short:
                return pointer.readS16();
            case Il2Cpp.Type.enum.unsignedShort:
                return pointer.readU16();
            case Il2Cpp.Type.enum.int:
                return pointer.readS32();
            case Il2Cpp.Type.enum.unsignedInt:
                return pointer.readU32();
            case Il2Cpp.Type.enum.char:
                return pointer.readU16();
            case Il2Cpp.Type.enum.long:
                return pointer.readS64();
            case Il2Cpp.Type.enum.unsignedLong:
                return pointer.readU64();
            case Il2Cpp.Type.enum.float:
                return pointer.readFloat();
            case Il2Cpp.Type.enum.double:
                return pointer.readDouble();
            case Il2Cpp.Type.enum.nativePointer:
            case Il2Cpp.Type.enum.unsignedNativePointer:
                return pointer.readPointer();
            case Il2Cpp.Type.enum.pointer:
                return new Il2Cpp.Pointer(pointer.readPointer(), type.class.baseType);
            case Il2Cpp.Type.enum.valueType:
                return new Il2Cpp.ValueType(pointer, type);
            case Il2Cpp.Type.enum.object:
            case Il2Cpp.Type.enum.class:
                return new Il2Cpp.Object(pointer.readPointer());
            case Il2Cpp.Type.enum.genericInstance:
                return type.class.isValueType ? new Il2Cpp.ValueType(pointer, type) : new Il2Cpp.Object(pointer.readPointer());
            case Il2Cpp.Type.enum.string:
                return new Il2Cpp.String(pointer.readPointer());
            case Il2Cpp.Type.enum.array:
            case Il2Cpp.Type.enum.multidimensionalArray:
                return new Il2Cpp.Array(pointer.readPointer());
        }
        raise(`couldn't read the value from ${pointer} using an unhandled or unknown type ${type.name} (${type.typeEnum}), please file an issue`);
    }
    Il2Cpp.read = read;
    /** @internal */
    function write(pointer, value, type) {
        switch (type.typeEnum) {
            case Il2Cpp.Type.enum.boolean:
                return pointer.writeS8(+value);
            case Il2Cpp.Type.enum.byte:
                return pointer.writeS8(value);
            case Il2Cpp.Type.enum.unsignedByte:
                return pointer.writeU8(value);
            case Il2Cpp.Type.enum.short:
                return pointer.writeS16(value);
            case Il2Cpp.Type.enum.unsignedShort:
                return pointer.writeU16(value);
            case Il2Cpp.Type.enum.int:
                return pointer.writeS32(value);
            case Il2Cpp.Type.enum.unsignedInt:
                return pointer.writeU32(value);
            case Il2Cpp.Type.enum.char:
                return pointer.writeU16(value);
            case Il2Cpp.Type.enum.long:
                return pointer.writeS64(value);
            case Il2Cpp.Type.enum.unsignedLong:
                return pointer.writeU64(value);
            case Il2Cpp.Type.enum.float:
                return pointer.writeFloat(value);
            case Il2Cpp.Type.enum.double:
                return pointer.writeDouble(value);
            case Il2Cpp.Type.enum.nativePointer:
            case Il2Cpp.Type.enum.unsignedNativePointer:
            case Il2Cpp.Type.enum.pointer:
            case Il2Cpp.Type.enum.string:
            case Il2Cpp.Type.enum.array:
            case Il2Cpp.Type.enum.multidimensionalArray:
                return pointer.writePointer(value);
            case Il2Cpp.Type.enum.valueType:
                return Memory.copy(pointer, value, type.class.valueTypeSize), pointer;
            case Il2Cpp.Type.enum.object:
            case Il2Cpp.Type.enum.class:
            case Il2Cpp.Type.enum.genericInstance:
                return value instanceof Il2Cpp.ValueType ? (Memory.copy(pointer, value, type.class.valueTypeSize), pointer) : pointer.writePointer(value);
        }
        raise(`couldn't write value ${value} to ${pointer} using an unhandled or unknown type ${type.name} (${type.typeEnum}), please file an issue`);
    }
    Il2Cpp.write = write;
    /** @internal */
    function fromFridaValue(value, type) {
        if (globalThis.Array.isArray(value)) {
            const handle = Memory.alloc(type.class.valueTypeSize);
            const fields = type.class.fields.filter(_ => !_.isStatic);
            for (let i = 0; i < fields.length; i++) {
                const convertedValue = fromFridaValue(value[i], fields[i].type);
                write(handle.add(fields[i].offset).sub(Il2Cpp.Object.headerSize), convertedValue, fields[i].type);
            }
            return new Il2Cpp.ValueType(handle, type);
        }
        else if (value instanceof NativePointer) {
            if (type.isByReference) {
                return new Il2Cpp.Reference(value, type);
            }
            switch (type.typeEnum) {
                case Il2Cpp.Type.enum.pointer:
                    return new Il2Cpp.Pointer(value, type.class.baseType);
                case Il2Cpp.Type.enum.string:
                    return new Il2Cpp.String(value);
                case Il2Cpp.Type.enum.class:
                case Il2Cpp.Type.enum.genericInstance:
                case Il2Cpp.Type.enum.object:
                    return new Il2Cpp.Object(value);
                case Il2Cpp.Type.enum.array:
                case Il2Cpp.Type.enum.multidimensionalArray:
                    return new Il2Cpp.Array(value);
                default:
                    return value;
            }
        }
        else if (type.typeEnum == Il2Cpp.Type.enum.boolean) {
            return !!value;
        }
        else if (type.typeEnum == Il2Cpp.Type.enum.valueType && type.class.isEnum) {
            return fromFridaValue([value], type);
        }
        else {
            return value;
        }
    }
    Il2Cpp.fromFridaValue = fromFridaValue;
    /** @internal */
    function toFridaValue(value) {
        if (typeof value == "boolean") {
            return +value;
        }
        else if (value instanceof Il2Cpp.ValueType) {
            if (value.type.class.isEnum) {
                return value.field("value__").value;
            }
            else {
                const _ = value.type.class.fields.filter(_ => !_.isStatic).map(_ => toFridaValue(_.withHolder(value).value));
                return _.length == 0 ? [0] : _;
            }
        }
        else {
            return value;
        }
    }
    Il2Cpp.toFridaValue = toFridaValue;
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    getter(Il2Cpp, "module", () => {
        const [moduleName, fallback] = getExpectedModuleNames();
        return Process.findModuleByName(moduleName) ?? Process.getModuleByName(fallback);
    });
    /**
     * @internal
     * Waits for the IL2CPP native library to be loaded and initialized.
     */
    async function initialize(blocking = false) {
        Reflect.defineProperty(Il2Cpp, "module", {
            // prettier-ignore
            value: Process.platform == "darwin"
                ? Process.findModuleByAddress(DebugSymbol.fromName("il2cpp_init").address)
                    ?? await forModule(...getExpectedModuleNames())
                : await forModule(...getExpectedModuleNames())
        });
        // At this point, the IL2CPP native library has been loaded, but we
        // cannot interact with IL2CPP until `il2cpp_init` is done.
        // It looks like `il2cpp_get_corlib` returns NULL only when the
        // initialization is not completed yet.
        if (Il2Cpp.api.getCorlib().isNull()) {
            return await new Promise(resolve => {
                const interceptor = Interceptor.attach(Il2Cpp.api.initialize, {
                    onLeave() {
                        interceptor.detach();
                        blocking ? resolve(true) : setImmediate(() => resolve(false));
                    }
                });
            });
        }
        return false;
    }
    Il2Cpp.initialize = initialize;
    function getExpectedModuleNames() {
        if (globalThis.IL2CPP_MODULE_NAME) {
            return [globalThis.IL2CPP_MODULE_NAME];
        }
        switch (Process.platform) {
            case "linux":
                return [Android.apiLevel ? "libil2cpp.so" : "GameAssembly.so"];
            case "windows":
                return ["GameAssembly.dll"];
            case "darwin":
                return ["UnityFramework", "GameAssembly.dylib"];
        }
        raise(`${Process.platform} is not supported yet`);
    }
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    /** Attaches the caller thread to Il2Cpp domain and executes the given block.  */
    async function perform(block, flag = "bind") {
        try {
            const isInMainThread = await Il2Cpp.initialize(flag == "main");
            if (flag == "main" && !isInMainThread) {
                return perform(() => Il2Cpp.mainThread.schedule(block), "free");
            }
            let thread = Il2Cpp.currentThread;
            const isForeignThread = thread == null;
            thread ??= Il2Cpp.domain.attach();
            const result = block();
            if (isForeignThread) {
                if (flag == "free") {
                    thread.detach();
                }
                else if (flag == "bind") {
                    Script.bindWeak(globalThis, () => thread.detach());
                }
            }
            return result instanceof Promise ? await result : result;
        }
        catch (error) {
            Script.nextTick(_ => { throw _; }, error); // prettier-ignore
            return Promise.reject(error);
        }
    }
    Il2Cpp.perform = perform;
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    class Tracer {
        /** @internal */
        #state = {
            depth: 0,
            buffer: [],
            history: new Set(),
            flush: () => {
                if (this.#state.depth == 0) {
                    const message = `\n${this.#state.buffer.join("\n")}\n`;
                    if (this.#verbose) {
                        inform(message);
                    }
                    else {
                        const hash = cyrb53(message);
                        if (!this.#state.history.has(hash)) {
                            this.#state.history.add(hash);
                            inform(message);
                        }
                    }
                    this.#state.buffer.length = 0;
                }
            }
        };
        /** @internal */
        #threadId = Il2Cpp.mainThread.id;
        /** @internal */
        #verbose = false;
        /** @internal */
        #applier;
        /** @internal */
        #targets = [];
        /** @internal */
        #domain;
        /** @internal */
        #assemblies;
        /** @internal */
        #classes;
        /** @internal */
        #methods;
        /** @internal */
        #assemblyFilter;
        /** @internal */
        #classFilter;
        /** @internal */
        #methodFilter;
        /** @internal */
        #parameterFilter;
        constructor(applier) {
            this.#applier = applier;
        }
        /** */
        thread(thread) {
            this.#threadId = thread.id;
            return this;
        }
        /** Determines whether print duplicate logs. */
        verbose(value) {
            this.#verbose = value;
            return this;
        }
        /** Sets the application domain as the place where to find the target methods. */
        domain() {
            this.#domain = Il2Cpp.domain;
            return this;
        }
        /** Sets the passed `assemblies` as the place where to find the target methods. */
        assemblies(...assemblies) {
            this.#assemblies = assemblies;
            return this;
        }
        /** Sets the passed `classes` as the place where to find the target methods. */
        classes(...classes) {
            this.#classes = classes;
            return this;
        }
        /** Sets the passed `methods` as the target methods. */
        methods(...methods) {
            this.#methods = methods;
            return this;
        }
        /** Filters the assemblies where to find the target methods. */
        filterAssemblies(filter) {
            this.#assemblyFilter = filter;
            return this;
        }
        /** Filters the classes where to find the target methods. */
        filterClasses(filter) {
            this.#classFilter = filter;
            return this;
        }
        /** Filters the target methods. */
        filterMethods(filter) {
            this.#methodFilter = filter;
            return this;
        }
        /** Filters the target methods. */
        filterParameters(filter) {
            this.#parameterFilter = filter;
            return this;
        }
        /** Commits the current changes by finding the target methods. */
        and() {
            const filterMethod = (method) => {
                if (this.#parameterFilter == undefined) {
                    this.#targets.push(method);
                    return;
                }
                for (const parameter of method.parameters) {
                    if (this.#parameterFilter(parameter)) {
                        this.#targets.push(method);
                        break;
                    }
                }
            };
            const filterMethods = (values) => {
                for (const method of values) {
                    filterMethod(method);
                }
            };
            const filterClass = (klass) => {
                if (this.#methodFilter == undefined) {
                    filterMethods(klass.methods);
                    return;
                }
                for (const method of klass.methods) {
                    if (this.#methodFilter(method)) {
                        filterMethod(method);
                    }
                }
            };
            const filterClasses = (values) => {
                for (const klass of values) {
                    filterClass(klass);
                }
            };
            const filterAssembly = (assembly) => {
                if (this.#classFilter == undefined) {
                    filterClasses(assembly.image.classes);
                    return;
                }
                for (const klass of assembly.image.classes) {
                    if (this.#classFilter(klass)) {
                        filterClass(klass);
                    }
                }
            };
            const filterAssemblies = (assemblies) => {
                for (const assembly of assemblies) {
                    filterAssembly(assembly);
                }
            };
            const filterDomain = (domain) => {
                if (this.#assemblyFilter == undefined) {
                    filterAssemblies(domain.assemblies);
                    return;
                }
                for (const assembly of domain.assemblies) {
                    if (this.#assemblyFilter(assembly)) {
                        filterAssembly(assembly);
                    }
                }
            };
            this.#methods
                ? filterMethods(this.#methods)
                : this.#classes
                    ? filterClasses(this.#classes)
                    : this.#assemblies
                        ? filterAssemblies(this.#assemblies)
                        : this.#domain
                            ? filterDomain(this.#domain)
                            : undefined;
            this.#assemblies = undefined;
            this.#classes = undefined;
            this.#methods = undefined;
            this.#assemblyFilter = undefined;
            this.#classFilter = undefined;
            this.#methodFilter = undefined;
            this.#parameterFilter = undefined;
            return this;
        }
        /** Starts tracing. */
        attach() {
            for (const target of this.#targets) {
                if (!target.virtualAddress.isNull()) {
                    try {
                        this.#applier(target, this.#state, this.#threadId);
                    }
                    catch (e) {
                        switch (e.message) {
                            case /unable to intercept function at \w+; please file a bug/.exec(e.message)?.input:
                            case "already replaced this function":
                                break;
                            default:
                                throw e;
                        }
                    }
                }
            }
        }
    }
    Il2Cpp.Tracer = Tracer;
    /** */
    function trace(parameters = false) {
        const applier = () => (method, state, threadId) => {
            const paddedVirtualAddress = method.relativeVirtualAddress.toString(16).padStart(8, "0");
            Interceptor.attach(method.virtualAddress, {
                onEnter() {
                    if (this.threadId == threadId) {
                        // prettier-ignore
                        state.buffer.push(`\x1b[2m0x${paddedVirtualAddress}\x1b[0m ${`│ `.repeat(state.depth++)}┌─\x1b[35m${method.class.type.name}::\x1b[1m${method.name}\x1b[0m\x1b[0m`);
                    }
                },
                onLeave() {
                    if (this.threadId == threadId) {
                        // prettier-ignore
                        state.buffer.push(`\x1b[2m0x${paddedVirtualAddress}\x1b[0m ${`│ `.repeat(--state.depth)}└─\x1b[33m${method.class.type.name}::\x1b[1m${method.name}\x1b[0m\x1b[0m`);
                        state.flush();
                    }
                }
            });
        };
        const applierWithParameters = () => (method, state, threadId) => {
            const paddedVirtualAddress = method.relativeVirtualAddress.toString(16).padStart(8, "0");
            const startIndex = +!method.isStatic | +Il2Cpp.unityVersionIsBelow201830;
            const callback = function (...args) {
                if (this.threadId == threadId) {
                    const thisParameter = method.isStatic ? undefined : new Il2Cpp.Parameter("this", -1, method.class.type);
                    const parameters = thisParameter ? [thisParameter].concat(method.parameters) : method.parameters;
                    // prettier-ignore
                    state.buffer.push(`\x1b[2m0x${paddedVirtualAddress}\x1b[0m ${`│ `.repeat(state.depth++)}┌─\x1b[35m${method.class.type.name}::\x1b[1m${method.name}\x1b[0m\x1b[0m(${parameters.map(e => `\x1b[32m${e.name}\x1b[0m = \x1b[31m${Il2Cpp.fromFridaValue(args[e.position + startIndex], e.type)}\x1b[0m`).join(", ")})`);
                }
                const returnValue = method.nativeFunction(...args);
                if (this.threadId == threadId) {
                    // prettier-ignore
                    state.buffer.push(`\x1b[2m0x${paddedVirtualAddress}\x1b[0m ${`│ `.repeat(--state.depth)}└─\x1b[33m${method.class.type.name}::\x1b[1m${method.name}\x1b[0m\x1b[0m${returnValue == undefined ? "" : ` = \x1b[36m${Il2Cpp.fromFridaValue(returnValue, method.returnType)}`}\x1b[0m`);
                    state.flush();
                }
                return returnValue;
            };
            method.revert();
            const nativeCallback = new NativeCallback(callback, method.returnType.fridaAlias, method.fridaSignature);
            Interceptor.replace(method.virtualAddress, nativeCallback);
        };
        return new Il2Cpp.Tracer(parameters ? applierWithParameters() : applier());
    }
    Il2Cpp.trace = trace;
    /** */
    function backtrace(mode) {
        const methods = Il2Cpp.domain.assemblies
            .flatMap(_ => _.image.classes.flatMap(_ => _.methods.filter(_ => !_.virtualAddress.isNull())))
            .sort((_, __) => _.virtualAddress.compare(__.virtualAddress));
        const searchInsert = (target) => {
            let left = 0;
            let right = methods.length - 1;
            while (left <= right) {
                const pivot = Math.floor((left + right) / 2);
                const comparison = methods[pivot].virtualAddress.compare(target);
                if (comparison == 0) {
                    return methods[pivot];
                }
                else if (comparison > 0) {
                    right = pivot - 1;
                }
                else {
                    left = pivot + 1;
                }
            }
            return methods[right];
        };
        const applier = () => (method, state, threadId) => {
            Interceptor.attach(method.virtualAddress, function () {
                if (this.threadId == threadId) {
                    const handles = globalThis.Thread.backtrace(this.context, mode);
                    handles.unshift(method.virtualAddress);
                    for (const handle of handles) {
                        if (handle.compare(Il2Cpp.module.base) > 0 && handle.compare(Il2Cpp.module.base.add(Il2Cpp.module.size)) < 0) {
                            const method = searchInsert(handle);
                            if (method) {
                                const offset = handle.sub(method.virtualAddress);
                                if (offset.compare(0xfff) < 0) {
                                    // prettier-ignore
                                    state.buffer.push(`\x1b[2m0x${method.relativeVirtualAddress.toString(16).padStart(8, "0")}\x1b[0m\x1b[2m+0x${offset.toString(16).padStart(3, `0`)}\x1b[0m ${method.class.type.name}::\x1b[1m${method.name}\x1b[0m`);
                                }
                            }
                        }
                    }
                    state.flush();
                }
            });
        };
        return new Il2Cpp.Tracer(applier());
    }
    Il2Cpp.backtrace = backtrace;
    /** https://stackoverflow.com/a/52171480/16885569 */
    function cyrb53(str) {
        let h1 = 0xdeadbeef;
        let h2 = 0x41c6ce57;
        for (let i = 0, ch; i < str.length; i++) {
            ch = str.charCodeAt(i);
            h1 = Math.imul(h1 ^ ch, 2654435761);
            h2 = Math.imul(h2 ^ ch, 1597334677);
        }
        h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507);
        h1 ^= Math.imul(h2 ^ (h2 >>> 13), 3266489909);
        h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507);
        h2 ^= Math.imul(h1 ^ (h1 >>> 13), 3266489909);
        return 4294967296 * (2097151 & h2) + (h1 >>> 0);
    }
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    class Array extends NativeStruct {
        /** Gets the Il2CppArray struct size, possibly equal to `Process.pointerSize * 4`. */
        static get headerSize() {
            return Il2Cpp.corlib.class("System.Array").instanceSize;
        }
        /** @internal Gets a pointer to the first element of the current array. */
        get elements() {
            // We previosly obtained an array whose content is known by calling
            // 'System.String::Split(NULL)' on a known string. However, that
            // method invocation somehow blows things up in Unity 2018.3.0f1.
            const array = Il2Cpp.string("v").object.method("ToCharArray", 0).invoke();
            // prettier-ignore
            const offset = array.handle.offsetOf(_ => _.readS16() == 118) ??
                raise("couldn't find the elements offset in the native array struct");
            // prettier-ignore
            getter(Il2Cpp.Array.prototype, "elements", function () {
                return new Il2Cpp.Pointer(this.handle.add(offset), this.elementType);
            }, lazy);
            return this.elements;
        }
        /** Gets the size of the object encompassed by the current array. */
        get elementSize() {
            return this.elementType.class.arrayElementSize;
        }
        /** Gets the type of the object encompassed by the current array. */
        get elementType() {
            return this.object.class.type.class.baseType;
        }
        /** Gets the total number of elements in all the dimensions of the current array. */
        get length() {
            return Il2Cpp.api.arrayGetLength(this);
        }
        /** Gets the encompassing object of the current array. */
        get object() {
            return new Il2Cpp.Object(this);
        }
        /** Gets the element at the specified index of the current array. */
        get(index) {
            if (index < 0 || index >= this.length) {
                raise(`cannot get element at index ${index} as the array length is ${this.length}`);
            }
            return this.elements.get(index);
        }
        /** Sets the element at the specified index of the current array. */
        set(index, value) {
            if (index < 0 || index >= this.length) {
                raise(`cannot set element at index ${index} as the array length is ${this.length}`);
            }
            this.elements.set(index, value);
        }
        /** */
        toString() {
            return this.isNull() ? "null" : `[${this.elements.read(this.length, 0)}]`;
        }
        /** Iterable. */
        *[Symbol.iterator]() {
            for (let i = 0; i < this.length; i++) {
                yield this.elements.get(i);
            }
        }
    }
    __decorate([
        lazy
    ], Array.prototype, "elementSize", null);
    __decorate([
        lazy
    ], Array.prototype, "elementType", null);
    __decorate([
        lazy
    ], Array.prototype, "length", null);
    __decorate([
        lazy
    ], Array.prototype, "object", null);
    __decorate([
        lazy
    ], Array, "headerSize", null);
    Il2Cpp.Array = Array;
    /** @internal */
    function array(klass, lengthOrElements) {
        const length = typeof lengthOrElements == "number" ? lengthOrElements : lengthOrElements.length;
        const array = new Il2Cpp.Array(Il2Cpp.api.arrayNew(klass, length));
        if (globalThis.Array.isArray(lengthOrElements)) {
            array.elements.write(lengthOrElements);
        }
        return array;
    }
    Il2Cpp.array = array;
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    let Assembly = class Assembly extends NativeStruct {
        /** Gets the image of this assembly. */
        get image() {
            let get = function () {
                return new Il2Cpp.Image(Il2Cpp.api.assemblyGetImage(this));
            };
            try {
                Il2Cpp.api.assemblyGetImage;
            }
            catch (_) {
                get = function () {
                    // We need to get the System.Reflection.Module of the current assembly;
                    // System.Reflection.Assembly::GetModulesInternal, for some reason,
                    // throws a NullReferenceExceptionin Unity 5.3.8f1, so we must rely on
                    // System.Type::get_Module instead.
                    // Now we need to get any System.Type of this assembly.
                    // We cannot use System.Reflection.Assembly::GetTypes because it may
                    // return an empty array; hence we use System.Reflection.Assembly::GetType
                    // to retrieve <Module>, a class/type that seems to be always present
                    // (despite being excluded from System.Reflection.Assembly::GetTypes).
                    return new Il2Cpp.Image(this.object
                        .method("GetType", 1)
                        .invoke(Il2Cpp.string("<Module>"))
                        .method("get_Module")
                        .invoke()
                        .field("_impl").value);
                };
            }
            getter(Il2Cpp.Assembly.prototype, "image", get, lazy);
            return this.image;
        }
        /** Gets the name of this assembly. */
        get name() {
            return this.image.name.replace(".dll", "");
        }
        /** Gets the encompassing object of the current assembly. */
        get object() {
            for (const _ of Il2Cpp.domain.object.method("GetAssemblies", 1).invoke(false)) {
                if (_.field("_mono_assembly").value.equals(this)) {
                    return _;
                }
            }
            raise("couldn't find the object of the native assembly struct");
        }
    };
    __decorate([
        lazy
    ], Assembly.prototype, "name", null);
    __decorate([
        lazy
    ], Assembly.prototype, "object", null);
    Assembly = __decorate([
        recycle
    ], Assembly);
    Il2Cpp.Assembly = Assembly;
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    let Class = class Class extends NativeStruct {
        /** Gets the actual size of the instance of the current class. */
        get actualInstanceSize() {
            const SystemString = Il2Cpp.corlib.class("System.String");
            // prettier-ignore
            const offset = SystemString.handle.offsetOf(_ => _.readInt() == SystemString.instanceSize - 2)
                ?? raise("couldn't find the actual instance size offset in the native class struct");
            // prettier-ignore
            getter(Il2Cpp.Class.prototype, "actualInstanceSize", function () {
                return this.handle.add(offset).readS32();
            }, lazy);
            return this.actualInstanceSize;
        }
        /** Gets the array class which encompass the current class. */
        get arrayClass() {
            return new Il2Cpp.Class(Il2Cpp.api.classGetArrayClass(this, 1));
        }
        /** Gets the size of the object encompassed by the current array class. */
        get arrayElementSize() {
            return Il2Cpp.api.classGetArrayElementSize(this);
        }
        /** Gets the name of the assembly in which the current class is defined. */
        get assemblyName() {
            return Il2Cpp.api.classGetAssemblyName(this).readUtf8String().replace(".dll", "");
        }
        /** Gets the class that declares the current nested class. */
        get declaringClass() {
            return new Il2Cpp.Class(Il2Cpp.api.classGetDeclaringType(this)).asNullable();
        }
        /** Gets the encompassed type of this array, reference, pointer or enum type. */
        get baseType() {
            return new Il2Cpp.Type(Il2Cpp.api.classGetBaseType(this)).asNullable();
        }
        /** Gets the class of the object encompassed or referred to by the current array, pointer or reference class. */
        get elementClass() {
            return new Il2Cpp.Class(Il2Cpp.api.classGetElementClass(this)).asNullable();
        }
        /** Gets the fields of the current class. */
        get fields() {
            return readNativeIterator(_ => Il2Cpp.api.classGetFields(this, _)).map(_ => new Il2Cpp.Field(_));
        }
        /** Gets the flags of the current class. */
        get flags() {
            return Il2Cpp.api.classGetFlags(this);
        }
        /** Gets the full name (namespace + name) of the current class. */
        get fullName() {
            return this.namespace ? `${this.namespace}.${this.name}` : this.name;
        }
        /** Gets the generics parameters of this generic class. */
        get generics() {
            if (!this.isGeneric && !this.isInflated) {
                return [];
            }
            const types = this.type.object.method("GetGenericArguments").invoke();
            return globalThis.Array.from(types).map(_ => new Il2Cpp.Class(Il2Cpp.api.classFromObject(_)));
        }
        /** Determines whether the GC has tracking references to the current class instances. */
        get hasReferences() {
            return !!Il2Cpp.api.classHasReferences(this);
        }
        /** Determines whether ther current class has a valid static constructor. */
        get hasStaticConstructor() {
            const staticConstructor = this.tryMethod(".cctor");
            return staticConstructor != null && !staticConstructor.virtualAddress.isNull();
        }
        /** Gets the image in which the current class is defined. */
        get image() {
            return new Il2Cpp.Image(Il2Cpp.api.classGetImage(this));
        }
        /** Gets the size of the instance of the current class. */
        get instanceSize() {
            return Il2Cpp.api.classGetInstanceSize(this);
        }
        /** Determines whether the current class is abstract. */
        get isAbstract() {
            return !!Il2Cpp.api.classIsAbstract(this);
        }
        /** Determines whether the current class is blittable. */
        get isBlittable() {
            return !!Il2Cpp.api.classIsBlittable(this);
        }
        /** Determines whether the current class is an enumeration. */
        get isEnum() {
            return !!Il2Cpp.api.classIsEnum(this);
        }
        /** Determines whether the current class is a generic one. */
        get isGeneric() {
            return !!Il2Cpp.api.classIsGeneric(this);
        }
        /** Determines whether the current class is inflated. */
        get isInflated() {
            return !!Il2Cpp.api.classIsInflated(this);
        }
        /** Determines whether the current class is an interface. */
        get isInterface() {
            return !!Il2Cpp.api.classIsInterface(this);
        }
        /** Determines whether the current class is a struct. */
        get isStruct() {
            return this.isValueType && !this.isEnum;
        }
        /** Determines whether the current class is a value type. */
        get isValueType() {
            return !!Il2Cpp.api.classIsValueType(this);
        }
        /** Gets the interfaces implemented or inherited by the current class. */
        get interfaces() {
            return readNativeIterator(_ => Il2Cpp.api.classGetInterfaces(this, _)).map(_ => new Il2Cpp.Class(_));
        }
        /** Gets the methods implemented by the current class. */
        get methods() {
            return readNativeIterator(_ => Il2Cpp.api.classGetMethods(this, _)).map(_ => new Il2Cpp.Method(_));
        }
        /** Gets the name of the current class. */
        get name() {
            return Il2Cpp.api.classGetName(this).readUtf8String();
        }
        /** Gets the namespace of the current class. */
        get namespace() {
            return Il2Cpp.api.classGetNamespace(this).readUtf8String();
        }
        /** Gets the classes nested inside the current class. */
        get nestedClasses() {
            return readNativeIterator(_ => Il2Cpp.api.classGetNestedClasses(this, _)).map(_ => new Il2Cpp.Class(_));
        }
        /** Gets the class from which the current class directly inherits. */
        get parent() {
            return new Il2Cpp.Class(Il2Cpp.api.classGetParent(this)).asNullable();
        }
        /** Gets the rank (number of dimensions) of the current array class. */
        get rank() {
            let rank = 0;
            const name = this.name;
            for (let i = this.name.length - 1; i > 0; i--) {
                const c = name[i];
                if (c == "]")
                    rank++;
                else if (c == "[" || rank == 0)
                    break;
                else if (c == ",")
                    rank++;
                else
                    break;
            }
            return rank;
        }
        /** Gets a pointer to the static fields of the current class. */
        get staticFieldsData() {
            return Il2Cpp.api.classGetStaticFieldData(this);
        }
        /** Gets the size of the instance - as a value type - of the current class. */
        get valueTypeSize() {
            return Il2Cpp.api.classGetValueTypeSize(this, NULL);
        }
        /** Gets the type of the current class. */
        get type() {
            return new Il2Cpp.Type(Il2Cpp.api.classGetType(this));
        }
        /** Allocates a new object of the current class. */
        alloc() {
            return new Il2Cpp.Object(Il2Cpp.api.objectNew(this));
        }
        /** Gets the field identified by the given name. */
        field(name) {
            return this.tryField(name) ?? raise(`couldn't find field ${name} in class ${this.type.name}`);
        }
        /** Builds a generic instance of the current generic class. */
        inflate(...classes) {
            if (!this.isGeneric) {
                raise(`cannot inflate class ${this.type.name} as it has no generic parameters`);
            }
            if (this.generics.length != classes.length) {
                raise(`cannot inflate class ${this.type.name} as it needs ${this.generics.length} generic parameter(s), not ${classes.length}`);
            }
            const types = classes.map(_ => _.type.object);
            const typeArray = Il2Cpp.array(Il2Cpp.corlib.class("System.Type"), types);
            const inflatedType = this.type.object.method("MakeGenericType", 1).invoke(typeArray);
            return new Il2Cpp.Class(Il2Cpp.api.classFromObject(inflatedType));
        }
        /** Calls the static constructor of the current class. */
        initialize() {
            Il2Cpp.api.classInitialize(this);
            return this;
        }
        /** Determines whether an instance of `other` class can be assigned to a variable of the current type. */
        isAssignableFrom(other) {
            return !!Il2Cpp.api.classIsAssignableFrom(this, other);
        }
        /** Determines whether the current class derives from `other` class. */
        isSubclassOf(other, checkInterfaces) {
            return !!Il2Cpp.api.classIsSubclassOf(this, other, +checkInterfaces);
        }
        /** Gets the method identified by the given name and parameter count. */
        method(name, parameterCount = -1) {
            return this.tryMethod(name, parameterCount) ?? raise(`couldn't find method ${name} in class ${this.type.name}`);
        }
        /** Gets the nested class with the given name. */
        nested(name) {
            return this.tryNested(name) ?? raise(`couldn't find nested class ${name} in class ${this.type.name}`);
        }
        /** Allocates a new object of the current class and calls its default constructor. */
        new() {
            const object = this.alloc();
            const exceptionArray = Memory.alloc(Process.pointerSize);
            Il2Cpp.api.objectInitialize(object, exceptionArray);
            const exception = exceptionArray.readPointer();
            if (!exception.isNull()) {
                raise(new Il2Cpp.Object(exception).toString());
            }
            return object;
        }
        /** Gets the field with the given name. */
        tryField(name) {
            return new Il2Cpp.Field(Il2Cpp.api.classGetFieldFromName(this, Memory.allocUtf8String(name))).asNullable();
        }
        /** Gets the method with the given name and parameter count. */
        tryMethod(name, parameterCount = -1) {
            return new Il2Cpp.Method(Il2Cpp.api.classGetMethodFromName(this, Memory.allocUtf8String(name), parameterCount)).asNullable();
        }
        /** Gets the nested class with the given name. */
        tryNested(name) {
            return this.nestedClasses.find(_ => _.name == name);
        }
        /** */
        toString() {
            const inherited = [this.parent].concat(this.interfaces);
            return `\
// ${this.assemblyName}
${this.isEnum ? `enum` : this.isStruct ? `struct` : this.isInterface ? `interface` : `class`} \
${this.type.name}\
${inherited ? ` : ${inherited.map(_ => _?.type.name).join(`, `)}` : ``}
{
    ${this.fields.join(`\n    `)}
    ${this.methods.join(`\n    `)}
}`;
        }
        /** Executes a callback for every defined class. */
        static enumerate(block) {
            const callback = new NativeCallback(_ => block(new Il2Cpp.Class(_)), "void", ["pointer", "pointer"]);
            return Il2Cpp.api.classForEach(callback, NULL);
        }
    };
    __decorate([
        lazy
    ], Class.prototype, "arrayClass", null);
    __decorate([
        lazy
    ], Class.prototype, "arrayElementSize", null);
    __decorate([
        lazy
    ], Class.prototype, "assemblyName", null);
    __decorate([
        lazy
    ], Class.prototype, "declaringClass", null);
    __decorate([
        lazy
    ], Class.prototype, "baseType", null);
    __decorate([
        lazy
    ], Class.prototype, "elementClass", null);
    __decorate([
        lazy
    ], Class.prototype, "fields", null);
    __decorate([
        lazy
    ], Class.prototype, "flags", null);
    __decorate([
        lazy
    ], Class.prototype, "fullName", null);
    __decorate([
        lazy
    ], Class.prototype, "generics", null);
    __decorate([
        lazy
    ], Class.prototype, "hasReferences", null);
    __decorate([
        lazy
    ], Class.prototype, "hasStaticConstructor", null);
    __decorate([
        lazy
    ], Class.prototype, "image", null);
    __decorate([
        lazy
    ], Class.prototype, "instanceSize", null);
    __decorate([
        lazy
    ], Class.prototype, "isAbstract", null);
    __decorate([
        lazy
    ], Class.prototype, "isBlittable", null);
    __decorate([
        lazy
    ], Class.prototype, "isEnum", null);
    __decorate([
        lazy
    ], Class.prototype, "isGeneric", null);
    __decorate([
        lazy
    ], Class.prototype, "isInflated", null);
    __decorate([
        lazy
    ], Class.prototype, "isInterface", null);
    __decorate([
        lazy
    ], Class.prototype, "isValueType", null);
    __decorate([
        lazy
    ], Class.prototype, "interfaces", null);
    __decorate([
        lazy
    ], Class.prototype, "methods", null);
    __decorate([
        lazy
    ], Class.prototype, "name", null);
    __decorate([
        lazy
    ], Class.prototype, "namespace", null);
    __decorate([
        lazy
    ], Class.prototype, "nestedClasses", null);
    __decorate([
        lazy
    ], Class.prototype, "parent", null);
    __decorate([
        lazy
    ], Class.prototype, "rank", null);
    __decorate([
        lazy
    ], Class.prototype, "staticFieldsData", null);
    __decorate([
        lazy
    ], Class.prototype, "valueTypeSize", null);
    __decorate([
        lazy
    ], Class.prototype, "type", null);
    Class = __decorate([
        recycle
    ], Class);
    Il2Cpp.Class = Class;
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    /** Creates a delegate object of the given delegate class. */
    function delegate(klass, block) {
        const SystemDelegate = Il2Cpp.corlib.class("System.Delegate");
        const SystemMulticastDelegate = Il2Cpp.corlib.class("System.MulticastDelegate");
        if (!SystemDelegate.isAssignableFrom(klass)) {
            raise(`cannot create a delegate for ${klass.type.name} as it's a non-delegate class`);
        }
        if (klass.equals(SystemDelegate) || klass.equals(SystemMulticastDelegate)) {
            raise(`cannot create a delegate for neither ${SystemDelegate.type.name} nor ${SystemMulticastDelegate.type.name}, use a subclass instead`);
        }
        const delegate = klass.alloc();
        const key = delegate.handle.toString();
        const Invoke = delegate.tryMethod("Invoke") ?? raise(`cannot create a delegate for ${klass.type.name}, there is no Invoke method`);
        delegate.method(".ctor").invoke(delegate, Invoke.handle);
        const callback = Invoke.wrap(block);
        delegate.field("method_ptr").value = callback;
        delegate.field("invoke_impl").value = callback;
        Il2Cpp._callbacksToKeepAlive[key] = callback;
        return delegate;
    }
    Il2Cpp.delegate = delegate;
    /** @internal Used to prevent eager garbage collection against NativeCallbacks. */
    Il2Cpp._callbacksToKeepAlive = {};
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    let Domain = class Domain extends NativeStruct {
        /** Gets the assemblies that have been loaded into the execution context of the application domain. */
        get assemblies() {
            let handles = readNativeList(_ => Il2Cpp.api.domainGetAssemblies(this, _));
            if (handles.length == 0) {
                const assemblyObjects = this.object.method("GetAssemblies").overload().invoke();
                handles = globalThis.Array.from(assemblyObjects).map(_ => _.field("_mono_assembly").value);
            }
            return handles.map(_ => new Il2Cpp.Assembly(_));
        }
        /** Gets the encompassing object of the application domain. */
        get object() {
            return Il2Cpp.corlib.class("System.AppDomain").method("get_CurrentDomain").invoke();
        }
        /** Opens and loads the assembly with the given name. */
        assembly(name) {
            return this.tryAssembly(name) ?? raise(`couldn't find assembly ${name}`);
        }
        /** Attached a new thread to the application domain. */
        attach() {
            return new Il2Cpp.Thread(Il2Cpp.api.threadAttach(this));
        }
        /** Opens and loads the assembly with the given name. */
        tryAssembly(name) {
            return new Il2Cpp.Assembly(Il2Cpp.api.domainGetAssemblyFromName(this, Memory.allocUtf8String(name))).asNullable();
        }
    };
    __decorate([
        lazy
    ], Domain.prototype, "assemblies", null);
    __decorate([
        lazy
    ], Domain.prototype, "object", null);
    Domain = __decorate([
        recycle
    ], Domain);
    Il2Cpp.Domain = Domain;
    // prettier-ignore
    getter(Il2Cpp, "domain", () => {
        return new Il2Cpp.Domain(Il2Cpp.api.domainGet());
    }, lazy);
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    class Field extends NativeStruct {
        /** Gets the class in which this field is defined. */
        get class() {
            return new Il2Cpp.Class(Il2Cpp.api.fieldGetClass(this));
        }
        /** Gets the flags of the current field. */
        get flags() {
            return Il2Cpp.api.fieldGetFlags(this);
        }
        /** Determines whether this field value is known at compile time. */
        get isLiteral() {
            return (this.flags & 64 /* Il2Cpp.Field.Attributes.Literal */) != 0;
        }
        /** Determines whether this field is static. */
        get isStatic() {
            return (this.flags & 16 /* Il2Cpp.Field.Attributes.Static */) != 0;
        }
        /** Determines whether this field is thread static. */
        get isThreadStatic() {
            const offset = Il2Cpp.corlib.class("System.AppDomain").field("type_resolve_in_progress").offset;
            // prettier-ignore
            getter(Il2Cpp.Field.prototype, "isThreadStatic", function () {
                return this.offset == offset;
            }, lazy);
            return this.isThreadStatic;
        }
        /** Gets the access modifier of this field. */
        get modifier() {
            switch (this.flags & 7 /* Il2Cpp.Field.Attributes.FieldAccessMask */) {
                case 1 /* Il2Cpp.Field.Attributes.Private */:
                    return "private";
                case 2 /* Il2Cpp.Field.Attributes.FamilyAndAssembly */:
                    return "private protected";
                case 3 /* Il2Cpp.Field.Attributes.Assembly */:
                    return "internal";
                case 4 /* Il2Cpp.Field.Attributes.Family */:
                    return "protected";
                case 5 /* Il2Cpp.Field.Attributes.FamilyOrAssembly */:
                    return "protected internal";
                case 6 /* Il2Cpp.Field.Attributes.Public */:
                    return "public";
            }
        }
        /** Gets the name of this field. */
        get name() {
            return Il2Cpp.api.fieldGetName(this).readUtf8String();
        }
        /** Gets the offset of this field, calculated as the difference with its owner virtual address. */
        get offset() {
            return Il2Cpp.api.fieldGetOffset(this);
        }
        /** Gets the type of this field. */
        get type() {
            return new Il2Cpp.Type(Il2Cpp.api.fieldGetType(this));
        }
        /** Gets the value of this field. */
        get value() {
            if (!this.isStatic) {
                raise(`cannot access instance field ${this.class.type.name}::${this.name} from a class, use an object instead`);
            }
            const handle = Memory.alloc(Process.pointerSize);
            Il2Cpp.api.fieldGetStaticValue(this.handle, handle);
            return Il2Cpp.read(handle, this.type);
        }
        /** Sets the value of this field. Thread static or literal values cannot be altered yet. */
        set value(value) {
            if (!this.isStatic) {
                raise(`cannot access instance field ${this.class.type.name}::${this.name} from a class, use an object instead`);
            }
            if (this.isThreadStatic || this.isLiteral) {
                raise(`cannot write the value of field ${this.name} as it's thread static or literal`);
            }
            const handle = 
            // pointer-like values should be passed as-is, but boxed
            // value types (primitives included) must be unboxed first
            value instanceof Il2Cpp.Object && this.type.class.isValueType
                ? value.unbox()
                : value instanceof NativeStruct
                    ? value.handle
                    : value instanceof NativePointer
                        ? value
                        : Il2Cpp.write(Memory.alloc(this.type.class.valueTypeSize), value, this.type);
            Il2Cpp.api.fieldSetStaticValue(this.handle, handle);
        }
        /** */
        toString() {
            return `\
${this.isThreadStatic ? `[ThreadStatic] ` : ``}\
${this.isStatic ? `static ` : ``}\
${this.type.name} \
${this.name}\
${this.isLiteral ? ` = ${this.type.class.isEnum ? Il2Cpp.read(this.value.handle, this.type.class.baseType) : this.value}` : ``};\
${this.isThreadStatic || this.isLiteral ? `` : ` // 0x${this.offset.toString(16)}`}`;
        }
        /** @internal */
        withHolder(instance) {
            if (this.isStatic) {
                raise(`cannot access static field ${this.class.type.name}::${this.name} from an object, use a class instead`);
            }
            const valueHandle = instance.handle.add(this.offset - (instance instanceof Il2Cpp.ValueType ? Il2Cpp.Object.headerSize : 0));
            return new Proxy(this, {
                get(target, property) {
                    if (property == "value") {
                        return Il2Cpp.read(valueHandle, target.type);
                    }
                    return Reflect.get(target, property);
                },
                set(target, property, value) {
                    if (property == "value") {
                        Il2Cpp.write(valueHandle, value, target.type);
                        return true;
                    }
                    return Reflect.set(target, property, value);
                }
            });
        }
    }
    __decorate([
        lazy
    ], Field.prototype, "class", null);
    __decorate([
        lazy
    ], Field.prototype, "flags", null);
    __decorate([
        lazy
    ], Field.prototype, "isLiteral", null);
    __decorate([
        lazy
    ], Field.prototype, "isStatic", null);
    __decorate([
        lazy
    ], Field.prototype, "isThreadStatic", null);
    __decorate([
        lazy
    ], Field.prototype, "modifier", null);
    __decorate([
        lazy
    ], Field.prototype, "name", null);
    __decorate([
        lazy
    ], Field.prototype, "offset", null);
    __decorate([
        lazy
    ], Field.prototype, "type", null);
    Il2Cpp.Field = Field;
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    class GCHandle {
        handle;
        /** @internal */
        constructor(handle) {
            this.handle = handle;
        }
        /** Gets the object associated to this handle. */
        get target() {
            return new Il2Cpp.Object(Il2Cpp.api.gcHandleGetTarget(this.handle)).asNullable();
        }
        /** Frees this handle. */
        free() {
            return Il2Cpp.api.gcHandleFree(this.handle);
        }
    }
    Il2Cpp.GCHandle = GCHandle;
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    let Image = class Image extends NativeStruct {
        /** Gets the assembly in which the current image is defined. */
        get assembly() {
            return new Il2Cpp.Assembly(Il2Cpp.api.imageGetAssembly(this));
        }
        /** Gets the amount of classes defined in this image. */
        get classCount() {
            if (Il2Cpp.unityVersionIsBelow201830) {
                return this.classes.length;
            }
            else {
                return Il2Cpp.api.imageGetClassCount(this);
            }
        }
        /** Gets the classes defined in this image. */
        get classes() {
            if (Il2Cpp.unityVersionIsBelow201830) {
                const types = this.assembly.object.method("GetTypes").invoke(false);
                // In Unity 5.3.8f1, getting System.Reflection.Emit.OpCodes type name
                // without iterating all the classes first somehow blows things up at
                // app startup, hence the `Array.from`.
                const classes = globalThis.Array.from(types, _ => new Il2Cpp.Class(Il2Cpp.api.classFromObject(_)));
                classes.unshift(this.class("<Module>"));
                return classes;
            }
            else {
                return globalThis.Array.from(globalThis.Array(this.classCount), (_, i) => new Il2Cpp.Class(Il2Cpp.api.imageGetClass(this, i)));
            }
        }
        /** Gets the name of this image. */
        get name() {
            return Il2Cpp.api.imageGetName(this).readUtf8String();
        }
        /** Gets the class with the specified name defined in this image. */
        class(name) {
            return this.tryClass(name) ?? raise(`couldn't find class ${name} in assembly ${this.name}`);
        }
        /** Gets the class with the specified name defined in this image. */
        tryClass(name) {
            const dotIndex = name.lastIndexOf(".");
            const classNamespace = Memory.allocUtf8String(dotIndex == -1 ? "" : name.slice(0, dotIndex));
            const className = Memory.allocUtf8String(name.slice(dotIndex + 1));
            return new Il2Cpp.Class(Il2Cpp.api.classFromName(this, classNamespace, className)).asNullable();
        }
    };
    __decorate([
        lazy
    ], Image.prototype, "assembly", null);
    __decorate([
        lazy
    ], Image.prototype, "classCount", null);
    __decorate([
        lazy
    ], Image.prototype, "classes", null);
    __decorate([
        lazy
    ], Image.prototype, "name", null);
    Image = __decorate([
        recycle
    ], Image);
    Il2Cpp.Image = Image;
    // prettier-ignore
    getter(Il2Cpp, "corlib", () => {
        return new Il2Cpp.Image(Il2Cpp.api.getCorlib());
    }, lazy);
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    class MemorySnapshot extends NativeStruct {
        /** Captures a memory snapshot. */
        static capture() {
            return new Il2Cpp.MemorySnapshot();
        }
        /** Creates a memory snapshot with the given handle. */
        constructor(handle = Il2Cpp.api.memorySnapshotCapture()) {
            super(handle);
        }
        /** Gets any initialized class. */
        get classes() {
            return readNativeIterator(_ => Il2Cpp.api.memorySnapshotGetClasses(this, _)).map(_ => new Il2Cpp.Class(_));
        }
        /** Gets the objects tracked by this memory snapshot. */
        get objects() {
            // prettier-ignore
            return readNativeList(_ => Il2Cpp.api.memorySnapshotGetObjects(this, _)).filter(_ => !_.isNull()).map(_ => new Il2Cpp.Object(_));
        }
        /** Frees this memory snapshot. */
        free() {
            Il2Cpp.api.memorySnapshotFree(this);
        }
    }
    __decorate([
        lazy
    ], MemorySnapshot.prototype, "classes", null);
    __decorate([
        lazy
    ], MemorySnapshot.prototype, "objects", null);
    Il2Cpp.MemorySnapshot = MemorySnapshot;
    /** */
    function memorySnapshot(block) {
        const memorySnapshot = Il2Cpp.MemorySnapshot.capture();
        const result = block(memorySnapshot);
        memorySnapshot.free();
        return result;
    }
    Il2Cpp.memorySnapshot = memorySnapshot;
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    class Method extends NativeStruct {
        /** Gets the class in which this method is defined. */
        get class() {
            return new Il2Cpp.Class(Il2Cpp.api.methodGetClass(this));
        }
        /** Gets the flags of the current method. */
        get flags() {
            return Il2Cpp.api.methodGetFlags(this, NULL);
        }
        /** Gets the implementation flags of the current method. */
        get implementationFlags() {
            const implementationFlagsPointer = Memory.alloc(Process.pointerSize);
            Il2Cpp.api.methodGetFlags(this, implementationFlagsPointer);
            return implementationFlagsPointer.readU32();
        }
        /** */
        get fridaSignature() {
            const types = [];
            for (const parameter of this.parameters) {
                types.push(parameter.type.fridaAlias);
            }
            if (!this.isStatic || Il2Cpp.unityVersionIsBelow201830) {
                types.unshift("pointer");
            }
            if (this.isInflated) {
                types.push("pointer");
            }
            return types;
        }
        /** Gets the generic parameters of this generic method. */
        get generics() {
            if (!this.isGeneric && !this.isInflated) {
                return [];
            }
            const types = this.object.method("GetGenericArguments").invoke();
            return globalThis.Array.from(types).map(_ => new Il2Cpp.Class(Il2Cpp.api.classFromObject(_)));
        }
        /** Determines whether this method is external. */
        get isExternal() {
            return (this.implementationFlags & 4096 /* Il2Cpp.Method.ImplementationAttribute.InternalCall */) != 0;
        }
        /** Determines whether this method is generic. */
        get isGeneric() {
            return !!Il2Cpp.api.methodIsGeneric(this);
        }
        /** Determines whether this method is inflated (generic with a concrete type parameter). */
        get isInflated() {
            return !!Il2Cpp.api.methodIsInflated(this);
        }
        /** Determines whether this method is static. */
        get isStatic() {
            return !Il2Cpp.api.methodIsInstance(this);
        }
        /** Determines whether this method is synchronized. */
        get isSynchronized() {
            return (this.implementationFlags & 32 /* Il2Cpp.Method.ImplementationAttribute.Synchronized */) != 0;
        }
        /** Gets the access modifier of this method. */
        get modifier() {
            switch (this.flags & 7 /* Il2Cpp.Method.Attributes.MemberAccessMask */) {
                case 1 /* Il2Cpp.Method.Attributes.Private */:
                    return "private";
                case 2 /* Il2Cpp.Method.Attributes.FamilyAndAssembly */:
                    return "private protected";
                case 3 /* Il2Cpp.Method.Attributes.Assembly */:
                    return "internal";
                case 4 /* Il2Cpp.Method.Attributes.Family */:
                    return "protected";
                case 5 /* Il2Cpp.Method.Attributes.FamilyOrAssembly */:
                    return "protected internal";
                case 6 /* Il2Cpp.Method.Attributes.Public */:
                    return "public";
            }
        }
        /** Gets the name of this method. */
        get name() {
            return Il2Cpp.api.methodGetName(this).readUtf8String();
        }
        /** @internal */
        get nativeFunction() {
            return new NativeFunction(this.virtualAddress, this.returnType.fridaAlias, this.fridaSignature);
        }
        /** Gets the encompassing object of the current method. */
        get object() {
            return new Il2Cpp.Object(Il2Cpp.api.methodGetObject(this, NULL));
        }
        /** Gets the amount of parameters of this method. */
        get parameterCount() {
            return Il2Cpp.api.methodGetParameterCount(this);
        }
        /** Gets the parameters of this method. */
        get parameters() {
            return globalThis.Array.from(globalThis.Array(this.parameterCount), (_, i) => {
                const parameterName = Il2Cpp.api.methodGetParameterName(this, i).readUtf8String();
                const parameterType = Il2Cpp.api.methodGetParameterType(this, i);
                return new Il2Cpp.Parameter(parameterName, i, new Il2Cpp.Type(parameterType));
            });
        }
        /** Gets the relative virtual address (RVA) of this method. */
        get relativeVirtualAddress() {
            return this.virtualAddress.sub(Il2Cpp.module.base);
        }
        /** Gets the return type of this method. */
        get returnType() {
            return new Il2Cpp.Type(Il2Cpp.api.methodGetReturnType(this));
        }
        /** Gets the virtual address (VA) of this method. */
        get virtualAddress() {
            const FilterTypeName = Il2Cpp.corlib.class("System.Reflection.Module").initialize().field("FilterTypeName").value;
            const FilterTypeNameMethodPointer = FilterTypeName.field("method_ptr").value;
            const FilterTypeNameMethod = FilterTypeName.field("method").value;
            // prettier-ignore
            const offset = FilterTypeNameMethod.offsetOf(_ => _.readPointer().equals(FilterTypeNameMethodPointer))
                ?? raise("couldn't find the virtual address offset in the native method struct");
            // prettier-ignore
            getter(Il2Cpp.Method.prototype, "virtualAddress", function () {
                return this.handle.add(offset).readPointer();
            }, lazy);
            // In Unity 2017.4.40f1 (don't know about others),
            // `Il2Cpp.Class::initialize` somehow triggers a nasty bug during
            // early instrumentation, so that we aren't able to obtain the
            // offset to get the virtual address of a method when the script
            // is reloaded. A workaround consists in manually re-invoking the
            // static constructor.
            Il2Cpp.corlib.class("System.Reflection.Module").method(".cctor").invoke();
            return this.virtualAddress;
        }
        /** Replaces the body of this method. */
        set implementation(block) {
            try {
                Interceptor.replace(this.virtualAddress, this.wrap(block));
            }
            catch (e) {
                switch (e.message) {
                    case "access violation accessing 0x0":
                        raise(`couldn't set implementation for method ${this.name} as it has a NULL virtual address`);
                    case /unable to intercept function at \w+; please file a bug/.exec(e.message)?.input:
                        warn(`couldn't set implementation for method ${this.name} as it may be a thunk`);
                        break;
                    case "already replaced this function":
                        warn(`couldn't set implementation for method ${this.name} as it has already been replaced by a thunk`);
                        break;
                    default:
                        throw e;
                }
            }
        }
        /** Creates a generic instance of the current generic method. */
        inflate(...classes) {
            if (!this.isGeneric) {
                raise(`cannot inflate method ${this.name} as it has no generic parameters`);
            }
            if (this.generics.length != classes.length) {
                raise(`cannot inflate method ${this.name} as it needs ${this.generics.length} generic parameter(s), not ${classes.length}`);
            }
            const types = classes.map(_ => _.type.object);
            const typeArray = Il2Cpp.array(Il2Cpp.corlib.class("System.Type"), types);
            const inflatedMethodObject = this.object.method("MakeGenericMethod", 1).invoke(typeArray);
            return new Il2Cpp.Method(inflatedMethodObject.field("mhandle").value);
        }
        /** Invokes this method. */
        invoke(...parameters) {
            if (!this.isStatic) {
                raise(`cannot invoke non-static method ${this.name} as it must be invoked throught a Il2Cpp.Object, not a Il2Cpp.Class`);
            }
            return this.invokeRaw(NULL, ...parameters);
        }
        /** @internal */
        invokeRaw(instance, ...parameters) {
            const allocatedParameters = parameters.map(Il2Cpp.toFridaValue);
            if (!this.isStatic || Il2Cpp.unityVersionIsBelow201830) {
                allocatedParameters.unshift(instance);
            }
            if (this.isInflated) {
                allocatedParameters.push(this.handle);
            }
            try {
                const returnValue = this.nativeFunction(...allocatedParameters);
                return Il2Cpp.fromFridaValue(returnValue, this.returnType);
            }
            catch (e) {
                if (e == null) {
                    raise("an unexpected native invocation exception occurred, this is due to parameter types mismatch");
                }
                switch (e.message) {
                    case "bad argument count":
                        raise(`couldn't invoke method ${this.name} as it needs ${this.parameterCount} parameter(s), not ${parameters.length}`);
                    case "expected a pointer":
                    case "expected number":
                    case "expected array with fields":
                        raise(`couldn't invoke method ${this.name} using incorrect parameter types`);
                }
                throw e;
            }
        }
        /** Gets the overloaded method with the given parameter types. */
        overload(...parameterTypes) {
            const result = this.tryOverload(...parameterTypes);
            if (result != undefined)
                return result;
            raise(`couldn't find overloaded method ${this.name}(${parameterTypes})`);
        }
        /** Gets the parameter with the given name. */
        parameter(name) {
            return this.tryParameter(name) ?? raise(`couldn't find parameter ${name} in method ${this.name}`);
        }
        /** Restore the original method implementation. */
        revert() {
            Interceptor.revert(this.virtualAddress);
            Interceptor.flush();
        }
        /** Gets the overloaded method with the given parameter types. */
        tryOverload(...parameterTypes) {
            let klass = this.class;
            while (klass) {
                const method = klass.methods.find(method => {
                    return (method.name == this.name &&
                        method.parameterCount == parameterTypes.length &&
                        method.parameters.every((e, i) => e.type.name == parameterTypes[i]));
                });
                if (method) {
                    return method;
                }
                klass = klass.parent;
            }
            return undefined;
        }
        /** Gets the parameter with the given name. */
        tryParameter(name) {
            return this.parameters.find(_ => _.name == name);
        }
        /** */
        toString() {
            return `\
${this.isStatic ? `static ` : ``}\
${this.returnType.name} \
${this.name}\
(${this.parameters.join(`, `)});\
${this.virtualAddress.isNull() ? `` : ` // 0x${this.relativeVirtualAddress.toString(16).padStart(8, `0`)}`}`;
        }
        /** @internal */
        withHolder(instance) {
            if (this.isStatic) {
                raise(`cannot access static method ${this.class.type.name}::${this.name} from an object, use a class instead`);
            }
            return new Proxy(this, {
                get(target, property) {
                    switch (property) {
                        case "invoke":
                            // In Unity 5.3.5f1 and >= 2021.2.0f1, value types
                            // methods may assume their `this` parameter is a
                            // pointer to raw data (that is how value types are
                            // layed out in memory) instead of a pointer to an
                            // object (that is object header + raw data).
                            // In any case, they also don't use whatever there
                            // is in the object header, so we can safely "skip"
                            // the object header by adding the object header
                            // size to the object (a boxed value type) handle.
                            const handle = instance instanceof Il2Cpp.ValueType
                                ? target.class.isValueType
                                    ? instance.handle.add(maybeObjectHeaderSize() - Il2Cpp.Object.headerSize)
                                    : raise(`cannot invoke method ${target.class.type.name}::${target.name} against a value type, you must box it first`)
                                : target.class.isValueType
                                    ? instance.handle.add(maybeObjectHeaderSize())
                                    : instance.handle;
                            return target.invokeRaw.bind(target, handle);
                        case "inflate":
                        case "overload":
                        case "tryOverload":
                            return function (...args) {
                                return target[property](...args)?.withHolder(instance);
                            };
                    }
                    return Reflect.get(target, property);
                }
            });
        }
        /** @internal */
        wrap(block) {
            const startIndex = +!this.isStatic | +Il2Cpp.unityVersionIsBelow201830;
            return new NativeCallback((...args) => {
                const thisObject = this.isStatic
                    ? this.class
                    : this.class.isValueType
                        ? new Il2Cpp.ValueType(args[0].add(Il2Cpp.Object.headerSize - maybeObjectHeaderSize()), this.class.type)
                        : new Il2Cpp.Object(args[0]);
                const parameters = this.parameters.map((_, i) => Il2Cpp.fromFridaValue(args[i + startIndex], _.type));
                const result = block.call(thisObject, ...parameters);
                return Il2Cpp.toFridaValue(result);
            }, this.returnType.fridaAlias, this.fridaSignature);
        }
    }
    __decorate([
        lazy
    ], Method.prototype, "class", null);
    __decorate([
        lazy
    ], Method.prototype, "flags", null);
    __decorate([
        lazy
    ], Method.prototype, "implementationFlags", null);
    __decorate([
        lazy
    ], Method.prototype, "fridaSignature", null);
    __decorate([
        lazy
    ], Method.prototype, "generics", null);
    __decorate([
        lazy
    ], Method.prototype, "isExternal", null);
    __decorate([
        lazy
    ], Method.prototype, "isGeneric", null);
    __decorate([
        lazy
    ], Method.prototype, "isInflated", null);
    __decorate([
        lazy
    ], Method.prototype, "isStatic", null);
    __decorate([
        lazy
    ], Method.prototype, "isSynchronized", null);
    __decorate([
        lazy
    ], Method.prototype, "modifier", null);
    __decorate([
        lazy
    ], Method.prototype, "name", null);
    __decorate([
        lazy
    ], Method.prototype, "nativeFunction", null);
    __decorate([
        lazy
    ], Method.prototype, "object", null);
    __decorate([
        lazy
    ], Method.prototype, "parameterCount", null);
    __decorate([
        lazy
    ], Method.prototype, "parameters", null);
    __decorate([
        lazy
    ], Method.prototype, "relativeVirtualAddress", null);
    __decorate([
        lazy
    ], Method.prototype, "returnType", null);
    Il2Cpp.Method = Method;
    let maybeObjectHeaderSize = () => {
        const struct = Il2Cpp.corlib.class("System.RuntimeTypeHandle").initialize().alloc();
        struct.method(".ctor").invokeRaw(struct, ptr(0xdeadbeef));
        // Here we check where the sentinel value is
        // if it's not where it is supposed to be, it means struct methods
        // assume they are receiving value types (that is a pointer to raw data)
        // hence, we must "skip" the object header when invoking such methods.
        const offset = struct.field("value").value.equals(ptr(0xdeadbeef)) ? 0 : Il2Cpp.Object.headerSize;
        return (maybeObjectHeaderSize = () => offset)();
    };
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    class Object extends NativeStruct {
        /** Gets the Il2CppObject struct size, possibly equal to `Process.pointerSize * 2`. */
        static get headerSize() {
            return Il2Cpp.corlib.class("System.Object").instanceSize;
        }
        /** Gets the class of this object. */
        get class() {
            return new Il2Cpp.Class(Il2Cpp.api.objectGetClass(this));
        }
        /** Returns a monitor for this object. */
        get monitor() {
            return new Il2Cpp.Object.Monitor(this);
        }
        /** Gets the size of the current object. */
        get size() {
            return Il2Cpp.api.objectGetSize(this);
        }
        /** Gets the field with the given name. */
        field(name) {
            return this.class.field(name).withHolder(this);
        }
        /** Gets the method with the given name. */
        method(name, parameterCount = -1) {
            return this.class.method(name, parameterCount).withHolder(this);
        }
        /** Creates a reference to this object. */
        ref(pin) {
            return new Il2Cpp.GCHandle(Il2Cpp.api.gcHandleNew(this, +pin));
        }
        /** Gets the correct virtual method from the given virtual method. */
        virtualMethod(method) {
            return new Il2Cpp.Method(Il2Cpp.api.objectGetVirtualMethod(this, method)).withHolder(this);
        }
        /** Gets the field with the given name. */
        tryField(name) {
            return this.class.tryField(name)?.withHolder(this);
        }
        /** Gets the field with the given name. */
        tryMethod(name, parameterCount = -1) {
            return this.class.tryMethod(name, parameterCount)?.withHolder(this);
        }
        /** */
        toString() {
            return this.isNull() ? "null" : this.method("ToString", 0).invoke().content ?? "null";
        }
        /** Unboxes the value type (either a primitive, a struct or an enum) out of this object. */
        unbox() {
            return this.class.isValueType
                ? new Il2Cpp.ValueType(Il2Cpp.api.objectUnbox(this), this.class.type)
                : raise(`couldn't unbox instances of ${this.class.type.name} as they are not value types`);
        }
        /** Creates a weak reference to this object. */
        weakRef(trackResurrection) {
            return new Il2Cpp.GCHandle(Il2Cpp.api.gcHandleNewWeakRef(this, +trackResurrection));
        }
    }
    __decorate([
        lazy
    ], Object.prototype, "class", null);
    __decorate([
        lazy
    ], Object.prototype, "size", null);
    __decorate([
        lazy
    ], Object, "headerSize", null);
    Il2Cpp.Object = Object;
    (function (Object) {
        class Monitor {
            handle;
            /** @internal */
            constructor(/** @internal */ handle) {
                this.handle = handle;
            }
            /** Acquires an exclusive lock on the current object. */
            enter() {
                return Il2Cpp.api.monitorEnter(this.handle);
            }
            /** Release an exclusive lock on the current object. */
            exit() {
                return Il2Cpp.api.monitorExit(this.handle);
            }
            /** Notifies a thread in the waiting queue of a change in the locked object's state. */
            pulse() {
                return Il2Cpp.api.monitorPulse(this.handle);
            }
            /** Notifies all waiting threads of a change in the object's state. */
            pulseAll() {
                return Il2Cpp.api.monitorPulseAll(this.handle);
            }
            /** Attempts to acquire an exclusive lock on the current object. */
            tryEnter(timeout) {
                return !!Il2Cpp.api.monitorTryEnter(this.handle, timeout);
            }
            /** Releases the lock on an object and attempts to block the current thread until it reacquires the lock. */
            tryWait(timeout) {
                return !!Il2Cpp.api.monitorTryWait(this.handle, timeout);
            }
            /** Releases the lock on an object and blocks the current thread until it reacquires the lock. */
            wait() {
                return Il2Cpp.api.monitorWait(this.handle);
            }
        }
        Object.Monitor = Monitor;
    })(Object = Il2Cpp.Object || (Il2Cpp.Object = {}));
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    class Parameter {
        /** Name of this parameter. */
        name;
        /** Position of this parameter. */
        position;
        /** Type of this parameter. */
        type;
        constructor(name, position, type) {
            this.name = name;
            this.position = position;
            this.type = type;
        }
        /** */
        toString() {
            return `${this.type.name} ${this.name}`;
        }
    }
    Il2Cpp.Parameter = Parameter;
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    class Pointer extends NativeStruct {
        type;
        constructor(handle, type) {
            super(handle);
            this.type = type;
        }
        /** Gets the element at the given index. */
        get(index) {
            return Il2Cpp.read(this.handle.add(index * this.type.class.arrayElementSize), this.type);
        }
        /** Reads the given amount of elements starting at the given offset. */
        read(length, offset = 0) {
            const values = new globalThis.Array(length);
            for (let i = 0; i < length; i++) {
                values[i] = this.get(i + offset);
            }
            return values;
        }
        /** Sets the given element at the given index */
        set(index, value) {
            Il2Cpp.write(this.handle.add(index * this.type.class.arrayElementSize), value, this.type);
        }
        /** */
        toString() {
            return this.handle.toString();
        }
        /** Writes the given elements starting at the given index. */
        write(values, offset = 0) {
            for (let i = 0; i < values.length; i++) {
                this.set(i + offset, values[i]);
            }
        }
    }
    Il2Cpp.Pointer = Pointer;
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    class Reference extends NativeStruct {
        type;
        constructor(handle, type) {
            super(handle);
            this.type = type;
        }
        /** Gets the element referenced by the current reference. */
        get value() {
            return Il2Cpp.read(this.handle, this.type);
        }
        /** Sets the element referenced by the current reference. */
        set value(value) {
            Il2Cpp.write(this.handle, value, this.type);
        }
        /** */
        toString() {
            return this.isNull() ? "null" : `->${this.value}`;
        }
    }
    Il2Cpp.Reference = Reference;
    /** Creates a reference to the specified value. */
    function reference(value, type) {
        const handle = Memory.alloc(Process.pointerSize);
        switch (typeof value) {
            case "boolean":
                return new Il2Cpp.Reference(handle.writeS8(+value), Il2Cpp.corlib.class("System.Boolean").type);
            case "number":
                switch (type?.typeEnum) {
                    case Il2Cpp.Type.enum.unsignedByte:
                        return new Il2Cpp.Reference(handle.writeU8(value), type);
                    case Il2Cpp.Type.enum.byte:
                        return new Il2Cpp.Reference(handle.writeS8(value), type);
                    case Il2Cpp.Type.enum.char:
                    case Il2Cpp.Type.enum.unsignedShort:
                        return new Il2Cpp.Reference(handle.writeU16(value), type);
                    case Il2Cpp.Type.enum.short:
                        return new Il2Cpp.Reference(handle.writeS16(value), type);
                    case Il2Cpp.Type.enum.unsignedInt:
                        return new Il2Cpp.Reference(handle.writeU32(value), type);
                    case Il2Cpp.Type.enum.int:
                        return new Il2Cpp.Reference(handle.writeS32(value), type);
                    case Il2Cpp.Type.enum.unsignedLong:
                        return new Il2Cpp.Reference(handle.writeU64(value), type);
                    case Il2Cpp.Type.enum.long:
                        return new Il2Cpp.Reference(handle.writeS64(value), type);
                    case Il2Cpp.Type.enum.float:
                        return new Il2Cpp.Reference(handle.writeFloat(value), type);
                    case Il2Cpp.Type.enum.double:
                        return new Il2Cpp.Reference(handle.writeDouble(value), type);
                }
            case "object":
                if (value instanceof Il2Cpp.ValueType || value instanceof Il2Cpp.Pointer) {
                    return new Il2Cpp.Reference(value.handle, value.type);
                }
                else if (value instanceof Il2Cpp.Object) {
                    return new Il2Cpp.Reference(handle.writePointer(value), value.class.type);
                }
                else if (value instanceof Il2Cpp.String || value instanceof Il2Cpp.Array) {
                    return new Il2Cpp.Reference(handle.writePointer(value), value.object.class.type);
                }
                else if (value instanceof NativePointer) {
                    switch (type?.typeEnum) {
                        case Il2Cpp.Type.enum.unsignedNativePointer:
                        case Il2Cpp.Type.enum.nativePointer:
                            return new Il2Cpp.Reference(handle.writePointer(value), type);
                    }
                }
                else if (value instanceof Int64) {
                    return new Il2Cpp.Reference(handle.writeS64(value), Il2Cpp.corlib.class("System.Int64").type);
                }
                else if (value instanceof UInt64) {
                    return new Il2Cpp.Reference(handle.writeU64(value), Il2Cpp.corlib.class("System.UInt64").type);
                }
            default:
                raise(`couldn't create a reference to ${value} using an unhandled type ${type?.name}`);
        }
    }
    Il2Cpp.reference = reference;
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    class String extends NativeStruct {
        /** Gets the content of this string. */
        get content() {
            return Il2Cpp.api.stringGetChars(this).readUtf16String(this.length);
        }
        /** @unsafe Sets the content of this string - it may write out of bounds! */
        set content(value) {
            // prettier-ignore
            const offset = Il2Cpp.string("vfsfitvnm").handle.offsetOf(_ => _.readInt() == 9)
                ?? raise("couldn't find the length offset in the native string struct");
            globalThis.Object.defineProperty(Il2Cpp.String.prototype, "content", {
                set(value) {
                    Il2Cpp.api.stringGetChars(this).writeUtf16String(value ?? "");
                    this.handle.add(offset).writeS32(value?.length ?? 0);
                }
            });
            this.content = value;
        }
        /** Gets the length of this string. */
        get length() {
            return Il2Cpp.api.stringGetLength(this);
        }
        /** Gets the encompassing object of the current string. */
        get object() {
            return new Il2Cpp.Object(this);
        }
        /** */
        toString() {
            return this.isNull() ? "null" : `"${this.content}"`;
        }
    }
    Il2Cpp.String = String;
    /** Creates a new string with the specified content. */
    function string(content) {
        return new Il2Cpp.String(Il2Cpp.api.stringNew(Memory.allocUtf8String(content ?? "")));
    }
    Il2Cpp.string = string;
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    class Thread extends NativeStruct {
        /** Gets the native id of the current thread. */
        get id() {
            let get = function () {
                return this.internal.field("thread_id").value.toNumber();
            };
            // https://github.com/mono/linux-packaging-mono/blob/d586f84dfea30217f34b076a616a098518aa72cd/mono/utils/mono-threads.h#L642
            if (Process.platform != "windows") {
                const currentThreadId = Process.getCurrentThreadId();
                const currentPosixThread = ptr(get.apply(Il2Cpp.currentThread));
                // prettier-ignore
                const offset = currentPosixThread.offsetOf(_ => _.readS32() == currentThreadId, 1024) ??
                    raise(`couldn't find the offset for determining the kernel id of a posix thread`);
                const _get = get;
                get = function () {
                    return ptr(_get.apply(this)).add(offset).readS32();
                };
            }
            getter(Il2Cpp.Thread.prototype, "id", get, lazy);
            return this.id;
        }
        /** Gets the encompassing internal object (System.Threding.InternalThreead) of the current thread. */
        get internal() {
            return this.object.tryField("internal_thread")?.value ?? this.object;
        }
        /** Determines whether the current thread is the garbage collector finalizer one. */
        get isFinalizer() {
            return !Il2Cpp.api.threadIsVm(this);
        }
        /** Gets the managed id of the current thread. */
        get managedId() {
            return this.object.method("get_ManagedThreadId").invoke();
        }
        /** Gets the encompassing object of the current thread. */
        get object() {
            return new Il2Cpp.Object(this);
        }
        /** @internal */
        get staticData() {
            return this.internal.field("static_data").value;
        }
        /** @internal */
        get synchronizationContext() {
            const get_ExecutionContext = this.object.tryMethod("GetMutableExecutionContext") ?? this.object.method("get_ExecutionContext");
            const executionContext = get_ExecutionContext.invoke();
            let synchronizationContext = executionContext.tryField("_syncContext")?.value ??
                executionContext.tryMethod("get_SynchronizationContext")?.invoke() ??
                this.tryLocalValue(Il2Cpp.corlib.class("System.Threading.SynchronizationContext"));
            if (synchronizationContext == null || synchronizationContext.isNull()) {
                if (this.handle.equals(Il2Cpp.mainThread.handle)) {
                    raise(`couldn't find the synchronization context of the main thread, perhaps this is early instrumentation?`);
                }
                else {
                    raise(`couldn't find the synchronization context of thread #${this.managedId}, only the main thread is expected to have one`);
                }
            }
            return synchronizationContext;
        }
        /** Detaches the thread from the application domain. */
        detach() {
            return Il2Cpp.api.threadDetach(this);
        }
        /** Schedules a callback on the current thread. */
        schedule(block) {
            const Post = this.synchronizationContext.method("Post");
            return new Promise(resolve => {
                const delegate = Il2Cpp.delegate(Il2Cpp.corlib.class("System.Threading.SendOrPostCallback"), () => {
                    const result = block();
                    setImmediate(() => resolve(result));
                });
                // This is to replace pending scheduled callbacks when the script is about to get unlaoded.
                // If we skip this cleanup, Frida's native callbacks will point to invalid memory, making
                // the application crash as soon as the IL2CPP runtime tries to execute such callbacks.
                // For instance, without the following code, this is how you can trigger a crash:
                // 1) unfocus the application;
                // 2) schedule a callback;
                // 3) reload the script;
                // 4) focus application.
                //
                // The "proper" solution consists in removing our delegates from the Unity synchroniztion
                // context, but the interface is not consisent across Unity versions - e.g. 2017.4.40f1 uses
                // a queue instead of a list, whereas newer versions do not allow null work requests.
                // The following solution, which basically redirects the invocation to a native function that
                // survives the script reloading, is much simpler, honestly.
                Script.bindWeak(globalThis, () => {
                    delegate.field("method_ptr").value = delegate.field("invoke_impl").value = Il2Cpp.api.domainGet;
                });
                Post.invoke(delegate, NULL);
            });
        }
        /** @internal */
        tryLocalValue(klass) {
            for (let i = 0; i < 16; i++) {
                const base = this.staticData.add(i * Process.pointerSize).readPointer();
                if (!base.isNull()) {
                    const object = new Il2Cpp.Object(base.readPointer()).asNullable();
                    if (object?.class?.isSubclassOf(klass, false)) {
                        return object;
                    }
                }
            }
        }
    }
    __decorate([
        lazy
    ], Thread.prototype, "internal", null);
    __decorate([
        lazy
    ], Thread.prototype, "isFinalizer", null);
    __decorate([
        lazy
    ], Thread.prototype, "managedId", null);
    __decorate([
        lazy
    ], Thread.prototype, "object", null);
    __decorate([
        lazy
    ], Thread.prototype, "staticData", null);
    __decorate([
        lazy
    ], Thread.prototype, "synchronizationContext", null);
    Il2Cpp.Thread = Thread;
    getter(Il2Cpp, "attachedThreads", () => {
        return readNativeList(Il2Cpp.api.threadGetAttachedThreads).map(_ => new Il2Cpp.Thread(_));
    });
    getter(Il2Cpp, "currentThread", () => {
        return new Il2Cpp.Thread(Il2Cpp.api.threadGetCurrent()).asNullable();
    });
    getter(Il2Cpp, "mainThread", () => {
        // I'm not sure if this is always the case. Typically, the main
        // thread managed id is 1, but this isn't always true: spawning
        // an Android application with Unity 5.3.8f1 will cause the Frida
        // thread to have the managed id equal to 1, whereas the main thread
        // managed id is 2.
        return Il2Cpp.attachedThreads[0];
    });
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    let Type = class Type extends NativeStruct {
        /** */
        static get enum() {
            const _ = (_, block = (_) => _) => block(Il2Cpp.corlib.class(_)).type.typeEnum;
            return {
                void: _("System.Void"),
                boolean: _("System.Boolean"),
                char: _("System.Char"),
                byte: _("System.SByte"),
                unsignedByte: _("System.Byte"),
                short: _("System.Int16"),
                unsignedShort: _("System.UInt16"),
                int: _("System.Int32"),
                unsignedInt: _("System.UInt32"),
                long: _("System.Int64"),
                unsignedLong: _("System.UInt64"),
                nativePointer: _("System.IntPtr"),
                unsignedNativePointer: _("System.UIntPtr"),
                float: _("System.Single"),
                double: _("System.Double"),
                pointer: _("System.IntPtr", _ => _.field("m_value")),
                valueType: _("System.Decimal"),
                object: _("System.Object"),
                string: _("System.String"),
                class: _("System.Array"),
                array: _("System.Void", _ => _.arrayClass),
                multidimensionalArray: _("System.Void", _ => new Il2Cpp.Class(Il2Cpp.api.classGetArrayClass(_, 2))),
                genericInstance: _("System.Int32", _ => _.interfaces.find(_ => _.name.endsWith("`1")))
            };
        }
        /** Gets the class of this type. */
        get class() {
            return new Il2Cpp.Class(Il2Cpp.api.typeGetClass(this));
        }
        /** */
        get fridaAlias() {
            function getValueTypeFields(type) {
                const instanceFields = type.class.fields.filter(_ => !_.isStatic);
                return instanceFields.length == 0 ? ["char"] : instanceFields.map(_ => _.type.fridaAlias);
            }
            if (this.isByReference) {
                return "pointer";
            }
            switch (this.typeEnum) {
                case Il2Cpp.Type.enum.void:
                    return "void";
                case Il2Cpp.Type.enum.boolean:
                    return "bool";
                case Il2Cpp.Type.enum.char:
                    return "uchar";
                case Il2Cpp.Type.enum.byte:
                    return "int8";
                case Il2Cpp.Type.enum.unsignedByte:
                    return "uint8";
                case Il2Cpp.Type.enum.short:
                    return "int16";
                case Il2Cpp.Type.enum.unsignedShort:
                    return "uint16";
                case Il2Cpp.Type.enum.int:
                    return "int32";
                case Il2Cpp.Type.enum.unsignedInt:
                    return "uint32";
                case Il2Cpp.Type.enum.long:
                    return "int64";
                case Il2Cpp.Type.enum.unsignedLong:
                    return "uint64";
                case Il2Cpp.Type.enum.float:
                    return "float";
                case Il2Cpp.Type.enum.double:
                    return "double";
                case Il2Cpp.Type.enum.nativePointer:
                case Il2Cpp.Type.enum.unsignedNativePointer:
                case Il2Cpp.Type.enum.pointer:
                case Il2Cpp.Type.enum.string:
                case Il2Cpp.Type.enum.array:
                case Il2Cpp.Type.enum.multidimensionalArray:
                    return "pointer";
                case Il2Cpp.Type.enum.valueType:
                    return this.class.isEnum ? this.class.baseType.fridaAlias : getValueTypeFields(this);
                case Il2Cpp.Type.enum.class:
                case Il2Cpp.Type.enum.object:
                case Il2Cpp.Type.enum.genericInstance:
                    return this.class.isStruct ? getValueTypeFields(this) : this.class.isEnum ? this.class.baseType.fridaAlias : "pointer";
                default:
                    return "pointer";
            }
        }
        /** Determines whether this type is passed by reference. */
        get isByReference() {
            return this.name.endsWith("&");
        }
        /** Determines whether this type is primitive. */
        get isPrimitive() {
            switch (this.typeEnum) {
                case Il2Cpp.Type.enum.boolean:
                case Il2Cpp.Type.enum.char:
                case Il2Cpp.Type.enum.byte:
                case Il2Cpp.Type.enum.unsignedByte:
                case Il2Cpp.Type.enum.short:
                case Il2Cpp.Type.enum.unsignedShort:
                case Il2Cpp.Type.enum.int:
                case Il2Cpp.Type.enum.unsignedInt:
                case Il2Cpp.Type.enum.long:
                case Il2Cpp.Type.enum.unsignedLong:
                case Il2Cpp.Type.enum.float:
                case Il2Cpp.Type.enum.double:
                case Il2Cpp.Type.enum.nativePointer:
                case Il2Cpp.Type.enum.unsignedNativePointer:
                    return true;
                default:
                    return false;
            }
        }
        /** Gets the name of this type. */
        get name() {
            const handle = Il2Cpp.api.typeGetName(this);
            try {
                return handle.readUtf8String();
            }
            finally {
                Il2Cpp.free(handle);
            }
        }
        /** Gets the encompassing object of the current type. */
        get object() {
            return new Il2Cpp.Object(Il2Cpp.api.typeGetObject(this));
        }
        /** Gets the type enum of the current type. */
        get typeEnum() {
            return Il2Cpp.api.typeGetTypeEnum(this);
        }
        /** */
        toString() {
            return this.name;
        }
    };
    __decorate([
        lazy
    ], Type.prototype, "class", null);
    __decorate([
        lazy
    ], Type.prototype, "fridaAlias", null);
    __decorate([
        lazy
    ], Type.prototype, "isByReference", null);
    __decorate([
        lazy
    ], Type.prototype, "isPrimitive", null);
    __decorate([
        lazy
    ], Type.prototype, "name", null);
    __decorate([
        lazy
    ], Type.prototype, "object", null);
    __decorate([
        lazy
    ], Type.prototype, "typeEnum", null);
    __decorate([
        lazy
    ], Type, "enum", null);
    Type = __decorate([
        recycle
    ], Type);
    Il2Cpp.Type = Type;
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    class ValueType extends NativeStruct {
        type;
        constructor(handle, type) {
            super(handle);
            this.type = type;
        }
        /** Boxes the current value type in a object. */
        box() {
            return new Il2Cpp.Object(Il2Cpp.api.valueTypeBox(this.type.class, this));
        }
        /** Gets the field with the given name. */
        field(name) {
            return this.type.class.field(name).withHolder(this);
        }
        /** Gets the method with the given name. */
        method(name, parameterCount = -1) {
            return this.type.class.method(name, parameterCount).withHolder(this);
        }
        /** Gets the field with the given name. */
        tryField(name) {
            return this.type.class.tryField(name)?.withHolder(this);
        }
        /** Gets the field with the given name. */
        tryMethod(name, parameterCount = -1) {
            return this.type.class.tryMethod(name, parameterCount)?.withHolder(this);
        }
        /** */
        toString() {
            const ToString = this.method("ToString", 0);
            return this.isNull()
                ? "null"
                : // If ToString is defined within a value type class, we can
                    // avoid a boxing operation.
                    ToString.class.isValueType
                        ? ToString.invoke().content ?? "null"
                        : this.box().toString() ?? "null";
        }
    }
    Il2Cpp.ValueType = ValueType;
})(Il2Cpp || (Il2Cpp = {}));
/// <reference path="./utils/android.ts">/>
/// <reference path="./utils/console.ts">/>
/// <reference path="./utils/decorate.ts">/>
/// <reference path="./utils/getter.ts">/>
/// <reference path="./utils/lazy.ts">/>
/// <reference path="./utils/native-struct.ts">/>
/// <reference path="./utils/native-wait.ts">/>
/// <reference path="./utils/offset-of.ts">/>
/// <reference path="./utils/read-native-iterator.ts">/>
/// <reference path="./utils/read-native-list.ts">/>
/// <reference path="./utils/recycle.ts">/>
/// <reference path="./utils/unity-version.ts">/>
/// <reference path="./api.ts">/>
/// <reference path="./application.ts">/>
/// <reference path="./dump.ts">/>
/// <reference path="./exception-listener.ts">/>
/// <reference path="./filters.ts">/>
/// <reference path="./gc.ts">/>
/// <reference path="./memory.ts">/>
/// <reference path="./module.ts">/>
/// <reference path="./perform.ts">/>
/// <reference path="./tracer.ts">/>
/// <reference path="./structs/array.ts">/>
/// <reference path="./structs/assembly.ts">/>
/// <reference path="./structs/class.ts">/>
/// <reference path="./structs/delegate.ts">/>
/// <reference path="./structs/domain.ts">/>
/// <reference path="./structs/field.ts">/>
/// <reference path="./structs/gc-handle.ts">/>
/// <reference path="./structs/image.ts">/>
/// <reference path="./structs/memory-snapshot.ts">/>
/// <reference path="./structs/method.ts">/>
/// <reference path="./structs/object.ts">/>
/// <reference path="./structs/parameter.ts">/>
/// <reference path="./structs/pointer.ts">/>
/// <reference path="./structs/reference.ts">/>
/// <reference path="./structs/string.ts">/>
/// <reference path="./structs/thread.ts">/>
/// <reference path="./structs/type.ts">/>
/// <reference path="./structs/value-type.ts">/>
globalThis.Il2Cpp = Il2Cpp;