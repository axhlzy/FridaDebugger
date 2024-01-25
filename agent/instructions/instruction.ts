import { BPStatus } from "../breakpoint/BPStatus"
import { loge, logl, logz } from "../logger"

export class InstructionParser {

    private constructor() { }

    static printCurrentInstruction = (pc: NativePointer | number = BPStatus.currentPC.get(BPStatus.currentThreadId)!, extraIns: number = 8, ret: boolean = false): Array<{ address: NativePointer, dis: string }> | void => {
        if (!ret) newLine()
        if (typeof pc === 'number') pc = ptr(pc)
        let count: number = extraIns
        // fake start
        let instruction_start = pc.sub(4 * ((extraIns / 2)))
        const arrayRet: Array<{ address: NativePointer, dis: string }> = []

        // got real start
        let offset: number = 0
        do {
            try {
                const ins = Instruction.parse(instruction_start.add(offset * 4))
                instruction_start = ins.address
                break
            } catch (error) {
                ++offset
            }
        } while (true)

        var ins: Instruction = Instruction.parse(instruction_start)
        do {
            let ins_str: string = `${DebugSymbol.fromAddress(ins.address)} | ${ins.toString()}`
            const ins_op: string = InstructionParser.InsParser(ins.address)
            if (ins_op.length != 0) ins_str += `\t| ${ins_op}`
            ins.address.equals(pc) ? loge(`-> ${ins_str}`) : logz(`   ${ins_str}`)
            if (ret) arrayRet.push({ address: ins.address, dis: ins_str })
            try {
                ins = Instruction.parse(ins.next)
            } catch (error) {
                const bt_array = ins.address.readByteArray(4)!
                const bt_array_str = Array.from(new Uint8Array(bt_array)).map((item: number) => item.toString(16).padStart(2, '0')).join(' ')
                logl(`   ${DebugSymbol.fromAddress(ins.address)} | [ ${bt_array_str} ]`)
                ins = Instruction.parse(ins.address.add(0x8))
            }
        } while (--count > 0)
        if (!ret) newLine()
        if (ret) return arrayRet
    }

    static InsParser(address: NativePointer): string {
        try {
            const ins = Instruction.parse(address)
            if (ins.mnemonic == "bl") {
                const opstr = ins.opStr
                const op = opstr.split("#")[1]
                const sym = DebugSymbol.fromAddress(ptr(op))
                return sym.toString()
            }
        } catch (error) {
            return ''
        }
        return ''
    }

}

Reflect.set(globalThis, "InstructionParser", InstructionParser)
Reflect.set(globalThis, "ins", InstructionParser)

Reflect.set(globalThis, "dism", (mPtr?: NativePointer) => { InstructionParser.printCurrentInstruction(mPtr) }) // dism