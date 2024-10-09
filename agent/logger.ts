export enum LogRedirect {
    LOGCAT,
    CMD,
    BOTH,
    TOAST,
    NOP
}

export enum android_LogPriority {
    /** For internal use only.  */
    ANDROID_LOG_UNKNOWN = 0,
    /** The default priority, for internal use only.  */
    ANDROID_LOG_DEFAULT = 1, /* only for SetMinPriority() */
    /** Verbose logging. Should typically be disabled for a release apk. */
    ANDROID_LOG_VERBOSE = 2,
    /** Debug logging. Should typically be disabled for a release apk. */
    ANDROID_LOG_DEBUG = 3,
    /** Informational logging. Should typically be disabled for a release apk. */
    ANDROID_LOG_INFO = 4,
    /** Warning logging. For use with recoverable failures. */
    ANDROID_LOG_WARN = 5,
    /** Error logging. For use with unrecoverable failures. */
    ANDROID_LOG_ERROR = 6,
    /** Fatal logging. For use when aborting. */
    ANDROID_LOG_FATAL = 7,
    /** For internal use only.  */
    ANDROID_LOG_SILENT = 8 /* only for SetMinPriority(); must be last */
}

export enum LogColor {
    TRACE, MARK, FATAL,
    WHITE = 0, RED = 1, YELLOW = 3,
    C31 = 31, C32 = 32, C33 = 33, C34 = 34, C35 = 35, C36 = 36,
    C41 = 41, C42 = 42, C43 = 43, C44 = 44, C45 = 45, C46 = 46,
    C90 = 90, C91 = 91, C92 = 92, C93 = 93, C94 = 94, C95 = 95, C96 = 96, C97 = 97,
    C100 = 100, C101 = 101, C102 = 102, C103 = 103, C104 = 104, C105 = 105, C106 = 106, C107 = 107
}

export const logw = (message: string) => log(message, LogColor.YELLOW)

export const logt = (message: string) => log(message, LogColor.TRACE)

export const logm = (message: string) => log(message, LogColor.MARK)

export const logf = (message: string) => log(message, LogColor.FATAL)

export const loge = (message: string) => log(message, LogColor.RED)

export const logg = (message: string) => log(message, LogColor.C32)

export const logo = (message: string) => log(message, LogColor.C33)

export const logl = (message: string) => log(message, LogColor.C34)

export const logn = (message: string) => log(message, LogColor.C35)

export const logd = (message: string) => log(message, LogColor.C36)

export const logh = (message: string) => log(message, LogColor.C96)

export const logz = (message: string) => log(message, LogColor.C90)

const LOG_TO: LogRedirect = LogRedirect.CMD

const LOG_COUNT_MAX: number = 20

export function log(message: string, type: LogColor = LogColor.WHITE, filter: boolean = false): void {
    if (LOG_TO == LogRedirect.NOP) return
    if (filter && !filterDuplicateOBJ(message, LOG_COUNT_MAX)) return
    switch (LOG_TO) {
        case LogRedirect.CMD:
            switch (type) {
                case LogColor.WHITE:
                    console.debug(message)
                    break
                case LogColor.RED:
                    console.error(message)
                    break
                case LogColor.YELLOW:
                    console.warn(message)
                    break
                case LogColor.TRACE:
                    console.trace(message)
                    break
                case LogColor.MARK:
                    console.debug(message)
                    break
                case LogColor.FATAL:
                    console.error(message)
                    break
                default:
                    console.log(`\x1b[${type}m${message}\x1b[0m`)
                    break
            }
            break
        case LogRedirect.LOGCAT:
            logcat(message)
            break
        case LogRedirect.TOAST:
            showToast(message)
            break
        default:
            console.log(`\x1b[${type}m${message}\x1b[0m`)
            break
    }
}

export const logcat = (msg: string) => {
    Java.perform(() => {
        const jstr = Java.use("java.lang.String")
        Java.use("android.util.Log").d(jstr.$new("ZZZ"), jstr.$new(msg))
    })
}

const showToast = (message: string) => {
    Java.perform(() => {
        let Toast = Java.use("android.widget.Toast")
        let context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext()
        // .overload('android.content.Context', 'java.lang.CharSequence', 'int')
        Java.scheduleOnMainThread(() => Toast.makeText(context, Java.use("java.lang.String").$new(message), 1).show())
    })
}

var nameCountMap: Map<string, number> = new Map()
globalThis.filterDuplicateOBJ = (objstr: string, maxCount: number = 10) => {
    let count: number | undefined = nameCountMap.get(objstr.toString())
    if (count == undefined) count = 0
    if (count < maxCount) {
        nameCountMap.set(objstr.toString(), count + 1)
        return true
    }
    return false
}

declare global {
    var filterDuplicateOBJ: (objstr: string, maxCount?: number) => boolean

    var logd: (message: string) => void
    var loge: (message: string) => void
    var logw: (message: string) => void
    var logi: (message: string) => void
}

globalThis.logd = logd
globalThis.loge = console.error
globalThis.logw = console.warn
globalThis.logi = console.info