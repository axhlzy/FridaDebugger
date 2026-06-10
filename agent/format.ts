export function padRight(value: unknown, width: number): string {
    const text = String(value);
    return text.length >= width ? text : text + " ".repeat(width - text.length);
}

export function padLeft(value: unknown, width: number): string {
    const text = String(value);
    return text.length >= width ? text : " ".repeat(width - text.length) + text;
}

export function formatReg(name: string, value: unknown): string {
    return `${padRight(name, 4)} ${padRight(value, 20)}`;
}
