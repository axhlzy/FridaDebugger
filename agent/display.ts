import { log } from "./logger.js";

export type DisplaySection = "asm" | "reg" | "sym" | "stack" | "bt";

const sections: Record<DisplaySection, boolean> = {
    asm: true,
    reg: true,
    sym: true,
    stack: true,
    bt: true,
};

export function isShown(section: DisplaySection): boolean {
    return sections[section];
}

export function setShown(section: DisplaySection | "all", enabled?: boolean): void {
    if (section === "all") {
        const value = enabled ?? !Object.values(sections).every(Boolean);
        for (const key of Object.keys(sections) as DisplaySection[]) {
            sections[key] = value;
        }
        printShown();
        return;
    }

    if (!(section in sections)) {
        log(`[show] unknown section ${section}`, "red");
        return;
    }

    sections[section] = enabled ?? !sections[section];
    printShown();
}

export function printShown(): void {
    const state = Object.entries(sections).map(([key, value]) => `${key}=${value ? "on" : "off"}`).join(" ");
    log(`[show] ${state}`, "cyan");
}
