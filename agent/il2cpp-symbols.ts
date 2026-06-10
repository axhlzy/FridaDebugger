import "frida-il2cpp-bridge";
import { colorize } from "./logger.js";

interface MethodEntry {
    start: NativePointer;
    methods: Il2Cpp.Method[];
}

export interface Il2CppFunctionRange {
    start: NativePointer;
    end: NativePointer;
    name: string;
}

const MODULE_NAMES = ["libil2cpp.so", "GameAssembly.dll"];
const CLASS_BATCH_SIZE = 64;
const MAX_RANGE_LOOKUP_BATCHES = 128;
const FULL_INDEX_PROGRESS_INTERVAL = 32;

let il2cppModule: Module | null | undefined;
let attachedThreads: Il2Cpp.Thread[] = [];
let assemblies: Il2Cpp.Assembly[] | null = null;
let assemblyIndex = 0;
let currentClasses: Il2Cpp.Class[] | null = null;
let classIndex = 0;
let entries: MethodEntry[] = [];
let entriesByAddress = new Map<string, MethodEntry>();
let entriesSorted = true;
let exhausted = false;
let monotonic = true;
let lastEnumeratedStart: NativePointer | null = null;
let orderWarningPrinted = false;
const knownClassHandles = new Set<string>();

const lifecycle = {};

Script.bindWeak(lifecycle, () => {
    for (const thread of attachedThreads) {
        thread.detach();
    }
    attachedThreads = [];
});

export function resolveIl2CppAddress(address: NativePointer): string {
    const module = getIl2CppModule();
    if (module === null || !contains(module, address)) {
        return "";
    }

    if (!ensureAttached()) {
        return "";
    }

    try {
        ensureEntriesCover(address);
        const entry = findFloorEntry(address);
        if (entry === null) {
            return "";
        }

        const next = findNextEntry(entry);
        if (next !== null && address.compare(next.start) >= 0) {
            return "";
        }

        return formatEntry(address, entry);
    } catch (_error) {
        return "";
    }
}

export function findIl2CppFunctionRange(address: NativePointer): Il2CppFunctionRange | null {
    const module = getIl2CppModule();
    if (module === null || !contains(module, address) || !ensureAttached()) {
        return null;
    }

    try {
        if (!ensureAssemblies()) {
            return null;
        }

        let batches = 0;
        let entry = findFloorEntry(address);
        let next = findNextEntry(entry);
        while (!isAddressBracketed(address, entry, next) && !exhausted && batches < MAX_RANGE_LOOKUP_BATCHES) {
            loadClassBatch();
            sortEntries();
            entry = findFloorEntry(address);
            next = findNextEntry(entry);
            batches++;
        }

        if (!monotonic && !exhausted) {
            ensureFullIndex("accurate pdf range");
            entry = findFloorEntry(address);
            next = findNextEntry(entry);
        }

        if (!isAddressBracketed(address, entry, next)) {
            return null;
        }

        return {
            start: entry!.start,
            end: next!.start,
            name: formatEntry(entry!.start, entry!),
        };
    } catch (_error) {
        return null;
    }
}

export function resolveKnownIl2CppAddress(address: NativePointer): string {
    const module = getIl2CppModule();
    if (module === null || !contains(module, address)) {
        return "";
    }

    try {
        const entry = findFloorEntry(address);
        const next = findNextEntry(entry);
        if (!isAddressBracketed(address, entry, next)) {
            return "";
        }

        return formatEntry(address, entry!);
    } catch (_error) {
        return "";
    }
}

export function resolveIl2CppObject(value: NativePointer): string {
    const object = createIl2CppObject(value);
    if (object === null) {
        return "";
    }

    try {
        const className = getClassName(object.class);
        const text = sanitizeObjectText(object.toString());
        if (text.length === 0 || text === "null") {
            return colorize(`& ${className}`, "gray");
        }

        return colorize(`& ${className}: ${text}`, "gray");
    } catch (_error) {
        return "";
    }
}

export function createIl2CppObject(value: NativePointer): Il2Cpp.Object | null {
    if (!isUnityIl2CppProcess() || !isObjectCandidate(value) || !ensureAttached()) {
        return null;
    }

    try {
        const object = new Il2Cpp.Object(value);
        void object.class;
        return object;
    } catch (_error) {
        return null;
    }
}

export function rememberIl2CppClass(klass: Il2Cpp.Class): void {
    knownClassHandles.add(klass.handle.toString());
}

function getIl2CppModule(): Module | null {
    if (il2cppModule !== undefined) {
        return il2cppModule;
    }

    il2cppModule = MODULE_NAMES.map(name => Process.findModuleByName(name)).find(module => module !== null) ?? null;
    return il2cppModule;
}

function contains(module: Module, address: NativePointer): boolean {
    const start = module.base;
    const end = module.base.add(module.size);
    return address.compare(start) >= 0 && address.compare(end) < 0;
}

function ensureAttached(): boolean {
    try {
        if (Il2Cpp.currentThread === null) {
            attachedThreads.push(Il2Cpp.domain.attach());
        }
        return true;
    } catch (_error) {
        return false;
    }
}

export function isUnityIl2CppProcess(): boolean {
    return getIl2CppModule() !== null;
}

export function getClassName(klass: Il2Cpp.Class): string {
    return klass.fullName || `${klass.namespace ?? ""}.${klass.name}`.replace(/^\./, "");
}

function isObjectCandidate(value: NativePointer): boolean {
    if (value.isNull() || !isAligned(value) || !isReadableDataPointer(value)) {
        return false;
    }

    try {
        const klass = value.readPointer();
        return !klass.isNull() && isAligned(klass) && isReadableDataPointer(klass) && isKnownClassPointer(klass);
    } catch (_error) {
        return false;
    }
}

function isKnownClassPointer(klass: NativePointer): boolean {
    if (knownClassHandles.size === 0) {
        return true;
    }

    return knownClassHandles.has(klass.toString());
}

function isAligned(value: NativePointer): boolean {
    return value.and(Process.pointerSize - 1).isNull();
}

function isReadableDataPointer(value: NativePointer): boolean {
    try {
        const range = Process.findRangeByAddress(value);
        return range !== null && range.protection.includes("r") && !range.protection.includes("x");
    } catch (_error) {
        return false;
    }
}

function sanitizeObjectText(value: string | null): string {
    if (value === null) {
        return "";
    }

    const text = value.replace(/\s+/g, " ").trim();
    return text.length > 120 ? `${text.slice(0, 117)}...` : text;
}

function ensureAssemblies(): boolean {
    if (assemblies !== null) {
        return true;
    }

    try {
        assemblies = Il2Cpp.domain.assemblies;
        return true;
    } catch (_error) {
        return false;
    }
}

function ensureEntriesCover(address: NativePointer): void {
    if (!ensureAssemblies()) {
        return;
    }

    while (!exhausted && needsMoreEntries(address)) {
        loadClassBatch();
    }

    sortEntries();
}

function needsMoreEntries(address: NativePointer): boolean {
    if (entries.length === 0) {
        return true;
    }

    if (!monotonic) {
        return !exhausted;
    }

    return lastEnumeratedStart === null || lastEnumeratedStart.compare(address) <= 0;
}

function loadClassBatch(): void {
    let loaded = 0;

    while (loaded < CLASS_BATCH_SIZE && !exhausted) {
        const klass = nextClass();
        if (klass === null) {
            exhausted = true;
            break;
        }

        loaded++;
        addClassMethods(klass);
    }
}

function ensureFullIndex(reason: string): void {
    console.log(`\x1b[33m[il2cpp] building full method index for ${reason}; method order is not monotonic\x1b[0m`);

    let batches = 0;
    while (!exhausted) {
        loadClassBatch();
        batches++;
        if (batches % FULL_INDEX_PROGRESS_INTERVAL === 0) {
            console.log(`\x1b[90m[il2cpp] indexed methods=${entries.length} assemblies=${assemblyIndex}/${assemblies?.length ?? 0}\x1b[0m`);
        }
    }

    sortEntries();
    console.log(`\x1b[32m[il2cpp] full method index ready methods=${entries.length}\x1b[0m`);
}

function nextClass(): Il2Cpp.Class | null {
    if (assemblies === null) {
        return null;
    }

    while (true) {
        if (currentClasses !== null && classIndex < currentClasses.length) {
            return currentClasses[classIndex++];
        }

        if (assemblyIndex >= assemblies.length) {
            return null;
        }

        try {
            currentClasses = assemblies[assemblyIndex++].image.classes;
            classIndex = 0;
        } catch (_error) {
            currentClasses = null;
            classIndex = 0;
        }
    }
}

function addClassMethods(klass: Il2Cpp.Class): void {
    let methods: Il2Cpp.Method[];
    try {
        methods = klass.methods;
    } catch (_error) {
        return;
    }

    for (const method of methods) {
        addMethod(method);
    }
}

function addMethod(method: Il2Cpp.Method): void {
    const module = getIl2CppModule();
    if (module === null) {
        return;
    }

    let start: NativePointer;
    try {
        start = method.virtualAddress;
    } catch (_error) {
        return;
    }

    if (start.isNull() || !contains(module, start)) {
        return;
    }

    if (lastEnumeratedStart !== null && lastEnumeratedStart.compare(start) > 0) {
        monotonic = false;
        if (!orderWarningPrinted) {
            console.log("\x1b[33m[il2cpp] method address order is not monotonic; resolver will finish indexing before range matches\x1b[0m");
            orderWarningPrinted = true;
        }
    }
    lastEnumeratedStart = start;

    const id = start.toString();
    const existing = entriesByAddress.get(id);
    if (existing !== undefined) {
        existing.methods.push(method);
        return;
    }

    const entry: MethodEntry = { start, methods: [method] };
    entries.push(entry);
    entriesByAddress.set(id, entry);
    entriesSorted = false;
}

function sortEntries(): void {
    if (entriesSorted) {
        return;
    }

    entries.sort((left, right) => left.start.compare(right.start));
    entriesSorted = true;
}

function findFloorEntry(address: NativePointer): MethodEntry | null {
    sortEntries();

    let low = 0;
    let high = entries.length - 1;
    let result = -1;

    while (low <= high) {
        const middle = low + Math.floor((high - low) / 2);
        const comparison = entries[middle].start.compare(address);
        if (comparison <= 0) {
            result = middle;
            low = middle + 1;
        } else {
            high = middle - 1;
        }
    }

    return result === -1 ? null : entries[result];
}

function findNextEntry(entry: MethodEntry | null): MethodEntry | null {
    sortEntries();

    if (entry === null) {
        return null;
    }

    const index = entries.indexOf(entry);
    if (index === -1 || index + 1 >= entries.length) {
        return null;
    }

    return entries[index + 1];
}

function isAddressBracketed(address: NativePointer, entry: MethodEntry | null, next: MethodEntry | null): boolean {
    return entry !== null && next !== null && address.compare(entry.start) >= 0 && address.compare(next.start) < 0;
}

function formatEntry(address: NativePointer, entry: MethodEntry): string {
    const offset = address.sub(entry.start).toUInt32();
    const methodText = formatMethod(entry.methods[0]);
    const aliasText = entry.methods.length > 1 ? ` (+${entry.methods.length - 1} aliases)` : "";
    return offset === 0 ? `${methodText}${aliasText}` : `${methodText}+0x${offset.toString(16)}${aliasText}`;
}

function formatMethod(method: Il2Cpp.Method): string {
    try {
        const klass = method.class;
        const className = klass.fullName || `${klass.namespace ?? ""}.${klass.name}`.replace(/^\./, "");
        const parameters = method.parameters.map(parameter => parameter.type.name).join(", ");
        return `${className}::${method.name}(${parameters})`;
    } catch (_error) {
        try {
            return method.name;
        } catch (__error) {
            return "<unknown il2cpp method>";
        }
    }
}
