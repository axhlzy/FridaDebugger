import { formatSymbol } from "./address-info.js";
import { log } from "./logger.js";
import { toPointer } from "./pointer.js";
import type { PointerInput } from "./types.js";

export function testFindFunctionRange(input: PointerInput): void {
    try {
        const findFunctionRange = (Process as typeof Process & {
            findFunctionRange?: (address: NativePointerValue) => MemoryRange | null;
        }).findFunctionRange;

        if (typeof findFunctionRange !== "function") {
            log(`[ffr] Process.findFunctionRange is not available in Frida ${Frida.version}`, "red");
            return;
        }

        const address = toPointer(input);
        const range = findFunctionRange(address);
        if (range === null) {
            log(`[ffr] ${address} range=<null>`, "yellow");
            return;
        }

        const end = range.base.add(range.size);
        log(`[ffr] address=${address}`, "cyan");
        log(`[ffr] range=${range.base}-${end} size=${range.size}`, "green");
        log(`[ffr] symbol=${formatSymbol(address, DebugSymbol.fromAddress(address))}`, "magenta");
    } catch (error) {
        log(`[ffr] failed: ${String(error)}`, "red");
    }
}

export function testControlFlowGraph(input: PointerInput, maxBlocks = 24, maxInstructions = 6): void {
    try {
        if (typeof ControlFlowGraph === "undefined") {
            log(`[cfg] ControlFlowGraph is not available in Frida ${Frida.version}`, "red");
            return;
        }

        const address = toPointer(input);
        const graph = new ControlFlowGraph(address);
        const range = Process.findFunctionRange(address);
        const containing = graph.findBlockContaining(address);
        const blockLimit = normalizeLimit(maxBlocks, 24);
        const instructionLimit = normalizeLimit(maxInstructions, 6);
        const ids = new Map<BasicBlock, number>();

        graph.blocks.forEach((block, index) => ids.set(block, index));

        log("[cfg] ------------------------------------------------------------", "cyan");
        log(`[cfg] entrypoint=${graph.entrypoint} entryBlock=#${ids.get(graph.entryBlock) ?? "?"} blocks=${graph.blocks.length}`, "green");
        if (range !== null) {
            log(`[cfg] function=${range.base}-${range.base.add(range.size)} size=${range.size}`, "green");
        }
        if (containing !== null) {
            log(`[cfg] containing=#${ids.get(containing) ?? "?"} ${containing.start}-${containing.end}`, "yellow");
        }

        for (const block of graph.blocks.slice(0, blockLimit)) {
            logBlock(block, ids, instructionLimit);
        }

        if (graph.blocks.length > blockLimit) {
            log(`[cfg] ... ${graph.blocks.length - blockLimit} blocks omitted ...`, "yellow");
        }
    } catch (error) {
        log(`[cfg] failed: ${String(error)}`, "red");
    }
}

function logBlock(block: BasicBlock, ids: Map<BasicBlock, number>, instructionLimit: number): void {
    const id = ids.get(block) ?? -1;
    const successors = block.successors.map(successor => `#${ids.get(successor) ?? "?"}`).join(",");
    const predecessors = block.predecessors.map(predecessor => `#${ids.get(predecessor) ?? "?"}`).join(",");
    const idom = block.immediateDominator === null ? "entry" : `#${ids.get(block.immediateDominator) ?? "?"}`;

    log(`[cfg] #${String(id).padStart(2, "0")} ${block.start}-${block.end} pred=[${predecessors}] succ=[${successors}] idom=${idom}`, "gray");

    for (const instruction of block.instructions.slice(0, instructionLimit)) {
        log(`[cfg]      ${instruction.address} ${instruction}`, "gray");
    }

    if (block.instructions.length > instructionLimit) {
        log(`[cfg]      ... ${block.instructions.length - instructionLimit} instructions omitted ...`, "yellow");
    }
}

function normalizeLimit(value: number, fallback: number): number {
    if (!Number.isFinite(value) || value <= 0) {
        return fallback;
    }

    return Math.max(1, Math.floor(value));
}
