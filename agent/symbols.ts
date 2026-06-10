import "frida-il2cpp-bridge";
import { createCallableFunction } from "./function-call.js";
import { rememberIl2CppClass } from "./il2cpp-symbols.js";
import { log } from "./logger.js";

type SymbolNode = Record<string, unknown>;

interface MethodNameCounts {
    [name: string]: number;
}

export class NativeSymbolResolver {
    readonly root: SymbolNode = Object.create(null);

    private attachedThread: Il2Cpp.Thread | null = null;

    constructor() {
        this.reload();
        Object.defineProperty(this.root, "reload", {
            value: () => this.reload(),
            enumerable: false,
        });
        Script.bindWeak(this, () => {
            if (this.attachedThread !== null) {
                this.attachedThread.detach();
                this.attachedThread = null;
            }
        });
    }

    reload(): void {
        clearEnumerableProperties(this.root);
        this.addModules();
        this.addUnityMetadata();
    }

    private addModules(): void {
        const modules = Process.enumerateModules();
        for (const module of modules) {
            const symbols = createExportNode(module);
            for (const alias of getModuleAliases(module.name)) {
                defineUniqueValue(this.root, alias, symbols);
            }
        }

        defineList(this.root);
        log(`[sym] modules=${modules.length}`, "gray");
    }

    private addUnityMetadata(): void {
        const il2cpp = Process.findModuleByName("libil2cpp.so");
        if (il2cpp === null || !this.ensureIl2CppAttached()) {
            return;
        }

        const il2cppNode = this.root.il2cpp as SymbolNode | undefined;
        if (il2cppNode === undefined) {
            return;
        }

        const classes = createUnityClassTree(il2cppNode);
        defineValue(il2cppNode, "classes", classes);
    }

    private ensureIl2CppAttached(): boolean {
        try {
            if (Il2Cpp.currentThread === null && this.attachedThread === null) {
                this.attachedThread = Il2Cpp.domain.attach();
            }
            return true;
        } catch (_error) {
            return false;
        }
    }
}

function createExportNode(module: Module): SymbolNode {
    const node: SymbolNode = Object.create(null);
    for (const exp of module.enumerateExports()) {
        if (exp.type !== "function") {
            continue;
        }

        defineUniqueValue(node, sanitizeIdentifier(exp.name), createCallableFunction(exp.address));
    }

    defineList(node);
    return node;
}

function createUnityClassTree(directClassRoot: SymbolNode): SymbolNode {
    const root: SymbolNode = Object.create(null);
    let classCount = 0;
    let methodCount = 0;

    try {
        for (const assembly of Il2Cpp.domain.assemblies) {
            for (const klass of assembly.image.classes) {
                rememberIl2CppClass(klass);
                classCount++;
                const classNode = getOrCreateClassNode(root, klass);
                methodCount += addMethods(classNode, klass);
                defineUniqueValue(directClassRoot, sanitizeIdentifier(klass.name), classNode);
            }
        }
    } catch (error) {
        log(`[sym] failed to build Unity metadata symbols: ${String(error)}`, "red");
    }

    defineList(root);
    log(`[sym] unity classes=${classCount} methods=${methodCount}`, "gray");
    return root;
}

function getOrCreateClassNode(root: SymbolNode, klass: Il2Cpp.Class): SymbolNode {
    const namespace = klass.namespace ?? "";
    const namespaceParts = namespace.length === 0 ? [] : namespace.split(".");
    const className = sanitizeIdentifier(klass.name);
    let node = root;

    for (const part of namespaceParts.map(sanitizeIdentifier)) {
        node = getOrCreateNode(node, part);
    }

    const classNode = getOrCreateNode(node, className);
    Object.defineProperty(classNode, "$class", {
        value: klass,
        enumerable: false,
        configurable: true,
    });
    defineList(classNode);
    return classNode;
}

function addMethods(classNode: SymbolNode, klass: Il2Cpp.Class): number {
    const counts: MethodNameCounts = Object.create(null);
    let count = 0;

    try {
        for (const method of klass.methods) {
            let address: NativePointer;
            try {
                address = method.virtualAddress;
            } catch (_error) {
                continue;
            }

            if (address.isNull()) {
                continue;
            }

            const baseName = sanitizeIdentifier(method.name);
            const seen = counts[baseName] ?? 0;
            counts[baseName] = seen + 1;
            const propertyName = seen === 0 && !(baseName in classNode) ? baseName : `${baseName}_${seen}`;
            defineValue(classNode, propertyName, createCallableFunction(address));
            count++;
        }
    } catch (_error) {
        return count;
    }

    return count;
}

function getOrCreateNode(parent: SymbolNode, name: string): SymbolNode {
    const existing = parent[name];
    if (isSymbolNode(existing)) {
        return existing;
    }

    const node: SymbolNode = Object.create(null);
    defineValue(parent, name, node);
    defineList(node);
    return node;
}

function getModuleAliases(moduleName: string): string[] {
    let alias = moduleName.replace(/\.(so|dll|dylib)$/i, "");
    if (alias.startsWith("lib") && alias.length > 3) {
        alias = alias.slice(3);
    }

    return [sanitizeIdentifier(alias)].filter(name => name.length > 0);
}

function sanitizeIdentifier(name: string): string {
    const sanitized = name.replace(/[^0-9A-Za-z_$]/g, "_");
    if (sanitized.length === 0) {
        return "_";
    }

    return /^[A-Za-z_$]/.test(sanitized) ? sanitized : `_${sanitized}`;
}

function defineUniqueValue(node: SymbolNode, baseName: string, value: unknown): void {
    let name = baseName;
    let index = 1;
    while (name in node) {
        name = `${baseName}_${index++}`;
    }

    defineValue(node, name, value);
}

function defineValue(node: SymbolNode, name: string, value: unknown): void {
    Object.defineProperty(node, name, {
        value,
        enumerable: true,
        configurable: true,
    });
}

function defineList(node: SymbolNode): void {
    Object.defineProperty(node, "list", {
        value: (filter = "") => Object.keys(node).filter(name => name.includes(filter)),
        enumerable: false,
        configurable: true,
    });
}

function clearEnumerableProperties(node: SymbolNode): void {
    for (const key of Object.keys(node)) {
        delete node[key];
    }
}

function isSymbolNode(value: unknown): value is SymbolNode {
    return typeof value === "object" && value !== null && !(value instanceof NativePointer);
}
