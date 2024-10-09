import { ContextItem, GContext } from "./StructInfo.js"
import { logd } from "../../logger.js"

export class ContextParser {

    // saved src context
    contextInfo: Array<ContextItem> = []

    constructor(contextInfo: Array<ContextItem>) {
        this.contextInfo = contextInfo
    }

    get contextCount(): number {
        return this.contextInfo.length
    }

    get SpOffset_Arr(): NativePointer[] {
        return this.contextInfo.map(item => item.spOffset)
    }

    get Address_Arr(): NativePointer[] {
        return this.contextInfo.map(item => ptr(item.inst.address))
    }

    get Context_Arr(): GContext[] {
        return this.contextInfo.map(item => item.context)
    }

    get enterItem(): ContextItem[] {
        return this.contextInfo.filter((value: ContextItem, index: number, array: ContextItem[]) => {
            return (index != 0) && value.spOffset > array[index - 1].spOffset
        }).map((_value: ContextItem, index: number, array: ContextItem[]) => {
            return array[index - 1]
        })
    }

    get enterAddress(): NativePointer[] {
        return this.enterItem.map(item => ptr(item.inst.address))
    }

    // Indentation of function calls
    showIndentation = (indent: string = '  ') => {
        let indentationTimes: number = 0
        let indentation: string = ''
        for (let i = 0; i < this.contextCount; i++) {
            const current = this.contextInfo[i]
            const last = i > 0 ? this.contextInfo[i - 1] : null
            let showDeep: boolean
            if (current.spOffset > (last ? last.spOffset : ptr(0))) {
                indentation = getIndentation(++indentationTimes, indent)
                showDeep = true
            } else if (current.spOffset < (last ? last.spOffset : ptr(0))) {
                indentation = getIndentation(--indentationTimes, indent)
                showDeep = true
            } else {
                showDeep = false
            }
            const indentationTimesStr = showDeep ? `-> ${indentationTimes}` : ' '.repeat(`-> ${indentationTimes}`.length)
            logd(`${indentation} ${indentationTimesStr} | ${current.spOffset} | ${ptr(current.inst.address)} | ${current.inst.disassembly}`)
        }

        function getIndentation(times: number, indent: string): string {
            return indent.repeat(times)
        }
    }

    getCalledSimbolList = (): string[] => {
        return this.contextInfo
            .map(item => DebugSymbol.fromAddress(ptr(item.inst.address)).name)
            .filter(item => !item.includes('0x'))
    }

}

Reflect.set(globalThis, 'ContextParser', ContextParser)