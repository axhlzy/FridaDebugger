const semInitPtr = Module.findGlobalExportByName("sem_init");
const semWaitPtr = Module.findGlobalExportByName("sem_wait");
const semPostPtr = Module.findGlobalExportByName("sem_post");
const semDestroyPtr = Module.findGlobalExportByName("sem_destroy");

if (semInitPtr === null || semWaitPtr === null || semPostPtr === null || semDestroyPtr === null) {
    throw new Error("failed to resolve libc semaphore exports");
}

const semInit = new NativeFunction(semInitPtr, "int", ["pointer", "int", "uint"]);
const semWait = new NativeFunction(semWaitPtr, "int", ["pointer"]);
const semPost = new NativeFunction(semPostPtr, "int", ["pointer"]);
const semDestroy = new NativeFunction(semDestroyPtr, "int", ["pointer"]);

export class Semaphore {
    private readonly handle = Memory.alloc(0x10);
    private destroyed = false;

    constructor() {
        semInit(this.handle, 0, 0);
    }

    wait(): void {
        if (this.destroyed) {
            return;
        }
        semWait(this.handle);
    }

    post(): void {
        if (this.destroyed) {
            return;
        }
        semPost(this.handle);
    }

    release(): void {
        this.post();
    }

    destroy(): void {
        if (this.destroyed) {
            return;
        }
        semDestroy(this.handle);
        this.destroyed = true;
    }
}
