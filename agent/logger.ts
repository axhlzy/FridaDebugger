export type LogColor = "red" | "green" | "yellow" | "blue" | "magenta" | "cyan" | "gray";

const colors: Record<LogColor, string> = {
    red: "\x1b[31m",
    green: "\x1b[32m",
    yellow: "\x1b[33m",
    blue: "\x1b[34m",
    magenta: "\x1b[35m",
    cyan: "\x1b[36m",
    gray: "\x1b[90m",
};

const reset = "\x1b[0m";

export function log(message: string, color?: LogColor): void {
    if (color === undefined) {
        console.log(message);
        return;
    }

    console.log(colorize(message, color));
}

export function colorize(message: string, color: LogColor): string {
    return `${colors[color]}${message}${reset}`;
}
