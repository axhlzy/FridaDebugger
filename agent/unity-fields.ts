import { resolveAddress } from "./address-info.js";
import { padLeft, padRight } from "./format.js";
import { createIl2CppObject, getClassName, isUnityIl2CppProcess } from "./il2cpp-symbols.js";
import { colorize, log } from "./logger.js";

type BindableField = Il2Cpp.Field & {
    bind(instance: Il2Cpp.Object | Il2Cpp.ValueType): Il2Cpp.BoundField;
};

type ArrayWithElements = Il2Cpp.Array & {
    elements: {
        handle: NativePointer;
    };
};

const MAX_ARRAY_ELEMENTS = 64;
const ARRAY_HEAD_ELEMENTS = 48;
const ARRAY_TAIL_ELEMENTS = 8;

export function logIl2CppFields(address: NativePointer): void {
    if (!isUnityIl2CppProcess()) {
        log("[lfs] Unity IL2CPP is not available", "yellow");
        return;
    }

    const object = createIl2CppObject(address);
    if (object === null) {
        log(`[lfs] ${address} is not a valid Il2Cpp.Object`, "red");
        return;
    }

    try {
        log("[lfs] ------------------------------------------------------------", "cyan");
        log(`[lfs] object ${address} ${formatObjectSummary(object)}`, "green");

        const array = tryAsArray(object);
        if (array !== null) {
            logArray(array);
            return;
        }

        const hierarchy = Array.from(object.class.hierarchy({ includeCurrent: true }));
        logInheritance(hierarchy);

        const groups: FieldGroup[] = [];
        for (const [depth, klass] of hierarchy.entries()) {
            const fields = klass.fields.filter(field => !field.isStatic);
            if (fields.length === 0) {
                continue;
            }

            groups.push({
                depth,
                className: getClassName(klass),
                rows: fields.map(field => readFieldRow(object, field)),
            });
        }

        const count = groups.reduce((total, group) => total + group.rows.length, 0);
        if (count === 0) {
            log("[lfs] no instance fields", "gray");
            return;
        }

        const widths = getColumnWidths(groups);
        for (const group of groups) {
            logFieldGroupHeader(group);
            for (const row of group.rows) {
                logFieldRow(row, widths);
            }
        }
    } catch (error) {
        log(`[lfs] failed: ${String(error)}`, "red");
    }
}

interface FieldGroup {
    depth: number;
    className: string;
    rows: FieldRow[];
}

interface FieldRow {
    offset: string;
    pointer: NativePointer;
    typeName: string;
    name: string;
    value: string;
    failed: boolean;
}

interface ColumnWidths {
    typeName: number;
    name: number;
}

function logInheritance(hierarchy: Il2Cpp.Class[]): void {
    const names = hierarchy.map(klass => getClassName(klass));
    if (names.length === 0) {
        return;
    }

    log(`[lfs] inheritance ${names.join(" -> ")}`, "magenta");
}

function logFieldGroupHeader(group: FieldGroup): void {
    const relation = group.depth === 0 ? "self" : `base+${group.depth}`;
    const color = group.depth === 0 ? "yellow" : "cyan";
    log(`[lfs] [${group.depth}] ${padRight(relation, 6)} ${group.className}`, color);
}

function readFieldRow(object: Il2Cpp.Object, field: Il2Cpp.Field): FieldRow {
    const offset = `+0x${field.offset.toString(16).padStart(4, "0")}`;
    const pointer = object.handle.add(field.offset);
    const typeName = safeFieldType(field);
    const name = safeFieldName(field);

    try {
        const value = (field as BindableField).bind(object).value;
        return { offset, pointer, typeName, name, value: formatFieldValue(value), failed: false };
    } catch (error) {
        const errorText = String(error);
        if (errorText.includes("access violation accessing 0x0")) {
            return { offset, pointer, typeName, name, value: colorize("null", "gray"), failed: false };
        }

        return { offset, pointer, typeName, name, value: `<read failed: ${errorText}>`, failed: true };
    }
}

function logFieldRow(row: FieldRow, widths: ColumnWidths): void {
    const line = [
        colorize("[lfs]", "gray"),
        colorize(padLeft(row.offset, 7), "yellow"),
        colorize(padRight(row.pointer, 20), "blue"),
        colorize(padRight(fit(row.typeName, widths.typeName), widths.typeName), "cyan"),
        colorize(padRight(fit(row.name, widths.name), widths.name), "gray"),
        "=",
        row.value,
    ].join(" ");

    log(row.failed ? colorize(line, "red") : line);
}

function getColumnWidths(groups: FieldGroup[]): ColumnWidths {
    const rows = groups.flatMap(group => group.rows);
    return {
        typeName: clamp(maxLength(rows.map(row => row.typeName)), 18, 44),
        name: clamp(maxLength(rows.map(row => row.name)), 18, 42),
    };
}

function maxLength(values: string[]): number {
    return values.reduce((max, value) => Math.max(max, value.length), 0);
}

function clamp(value: number, min: number, max: number): number {
    return Math.max(min, Math.min(max, value));
}

function fit(value: string, width: number): string {
    if (value.length <= width) {
        return value;
    }

    return `${value.slice(0, Math.max(0, width - 3))}...`;
}

function formatFieldValue(value: Il2Cpp.Field.Type): string {
    if (value instanceof NativePointer) {
        const resolved = resolveAddress(value);
        const pointerText = colorize(padRight(value, 20), resolved.length > 0 ? "green" : "gray");
        return resolved.length > 0 ? `${pointerText} ${colorize(resolved, "magenta")}` : pointerText;
    }

    if (value instanceof Il2Cpp.String) {
        return colorize(JSON.stringify(value.content), "gray");
    }

    if (value instanceof Il2Cpp.Object) {
        return `${colorize(padRight(value.handle, 20), "green")} ${formatObjectSummary(value)}`;
    }

    if (value instanceof Il2Cpp.Array) {
        return `${colorize(padRight(value.handle, 20), "green")} ${formatArraySummary(value)}`;
    }

    if (value instanceof Il2Cpp.ValueType) {
        return colorize(sanitizeText(value.toString()), "green");
    }

    return colorize(String(value), "green");
}

function formatObjectSummary(object: Il2Cpp.Object): string {
    const className = getClassName(object.class);
    const text = sanitizeText(object.toString());
    if (text.length === 0 || text === "null") {
        return colorize(`& ${className}`, "gray");
    }

    return colorize(`& ${className}: ${text}`, "gray");
}

function tryAsArray(object: Il2Cpp.Object): Il2Cpp.Array | null {
    try {
        const klass = object.class;
        const className = getClassName(klass);
        if (!className.endsWith("[]") && klass.rank <= 0) {
            return null;
        }

        const array = new Il2Cpp.Array(object.handle);
        void array.length;
        void array.elementType;
        return array;
    } catch (_error) {
        return null;
    }
}

function logArray(array: Il2Cpp.Array): void {
    const length = array.length;
    const elementType = safeArrayElementType(array);
    const elementSize = safeArrayElementSize(array);
    log(`[lfs] array length=${length} elementType=${elementType} elementSize=${elementSize}`, "yellow");

    if (length === 0) {
        return;
    }

    const indices = getArrayDisplayIndices(length);
    let omitted = false;
    const indexWidth = Math.max(3, String(length - 1).length);
    const typeWidth = clamp(elementType.length, 12, 44);

    for (const index of indices) {
        if (index === -1) {
            if (!omitted) {
                log(`[lfs] ... ${length - ARRAY_HEAD_ELEMENTS - ARRAY_TAIL_ELEMENTS} elements omitted ...`, "yellow");
                omitted = true;
            }
            continue;
        }

        logArrayElement(array, index, indexWidth, typeWidth);
    }
}

function logArrayElement(array: Il2Cpp.Array, index: number, indexWidth: number, typeWidth: number): void {
    const pointer = getArrayElementPointer(array, index);
    try {
        const value = array.get(index);
        log([
            colorize("[lfs]", "gray"),
            colorize(`[${padLeft(index, indexWidth)}]`, "yellow"),
            colorize(padRight(pointer, 20), "blue"),
            colorize(padRight(fit(safeArrayElementType(array), typeWidth), typeWidth), "cyan"),
            "=",
            formatFieldValue(value),
        ].join(" "));
    } catch (error) {
        log(`[lfs] [${padLeft(index, indexWidth)}] ${pointer} = <read failed: ${String(error)}>`, "red");
    }
}

function getArrayElementPointer(array: Il2Cpp.Array, index: number): NativePointer {
    try {
        return (array as ArrayWithElements).elements.handle.add(index * array.elementSize);
    } catch (_error) {
        return array.handle.add(Il2Cpp.Array.headerSize).add(index * Process.pointerSize);
    }
}

function getArrayDisplayIndices(length: number): number[] {
    if (length <= MAX_ARRAY_ELEMENTS) {
        return Array.from({ length }, (_value, index) => index);
    }

    const head = Array.from({ length: ARRAY_HEAD_ELEMENTS }, (_value, index) => index);
    const tailStart = length - ARRAY_TAIL_ELEMENTS;
    const tail = Array.from({ length: ARRAY_TAIL_ELEMENTS }, (_value, index) => tailStart + index);
    return [...head, -1, ...tail];
}

function formatArraySummary(array: Il2Cpp.Array): string {
    try {
        return colorize(`& ${safeArrayElementType(array)}[] length=${array.length}`, "gray");
    } catch (_error) {
        return colorize("& array", "gray");
    }
}

function safeArrayElementType(array: Il2Cpp.Array): string {
    try {
        return array.elementType.name;
    } catch (_error) {
        return "<unknown>";
    }
}

function safeArrayElementSize(array: Il2Cpp.Array): string {
    try {
        return String(array.elementSize);
    } catch (_error) {
        return "?";
    }
}

function safeFieldType(field: Il2Cpp.Field): string {
    try {
        return field.type.name;
    } catch (_error) {
        return "<unknown>";
    }
}

function safeFieldName(field: Il2Cpp.Field): string {
    try {
        return field.name;
    } catch (_error) {
        return "<unknown>";
    }
}

function sanitizeText(value: string | null): string {
    if (value === null) {
        return "";
    }

    const text = value.replace(/\s+/g, " ").trim();
    return text.length > 96 ? `${text.slice(0, 93)}...` : text;
}
