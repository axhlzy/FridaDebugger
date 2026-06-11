// ===========================================================================
// thread-stalker.js — Stalker-trace selected threads from birth to exit.
//
// Pairs with thread-monitor.js: that script prints a thread tree like
//     ├─ 12007:Thread-4#12051 [exited, lived 1287ms] libfk.so+0x950bb8
// Take the entry-routine token at the end (e.g. "libfk.so+0x950bb8") and drop
// it straight into CONFIG.targets below to stalk that thread when it next spawns.
//
// On each matching thread, Stalker.follow() begins in the thread's OWN context
// (attachThreadObserver.onAdded runs there), records the requested event types
// (call / block / ret / exec / compile), and Stalker.unfollow() on exit.
//
// WARNING: Stalker is heavy. Tracing too broadly floods events and can stall the
// process. Keep targets tight and scope limited. exec:true (every instruction)
// is the most expensive — leave it off unless you really need it.
// ===========================================================================


//    ├─ 17070:Injector#17113 [exited, lived 129ms] libfk.so+0x942d18
//    └─ 17070:Thread-4#17114 [exited, lived 670ms] libfk.so+0x950bb8

const CONFIG = {
  // ---- which threads to stalk: matched against the thread ENTRY routine ----
  // Each entry accepts (copy the token from thread-monitor's output):
  //   "libfk.so"             any thread whose entry is in libfk.so
  //   "libfk.so+0x950bb8"    exact module + offset
  //   "0x950bb8@libfk.so"    same, alternate syntax
  //   "name:Thread-4"        match by thread name instead of routine
  targets: [
    "libfk.so+0x942d18",
  ],

  // ---- which Stalker events to record ----
  trace: {
    call: false,     // CALL instructions  (function calls)        — "指令调用"
    block: false,    // basic-block execution                      — "基本块调用"
    ret: false,     // RET instructions
    compile: false, // basic-block compilation (first time seen)
    exec: true,    // EVERY instruction — EXTREMELY heavy, careful!
  },

  // ---- scope: keep the firehose down ----
  // When true, Stalker.exclude() EVERY module except the target module(s) from
  // CONFIG.targets. Excluded code runs natively (not rewritten, no code slab),
  // so instrumentation — and slab allocation — is confined to the target lib.
  // This is what prevents "Unable to allocate code slab" on big/hot modules.
  excludeAllButTargets: true,
  // Extra functions to Stalker.exclude even when they live INSIDE a target
  // module. The Injector thread crashes because, inside libfk, it installs
  // inline hooks (Dobby) and does JNI attach — those rewrite code / flush
  // i-cache and fight Stalker. Excluding them lets Stalker run them natively.
  // Names are resolved via Module.findGlobalExportByName (any module).
  excludeFunctions: [
    "mprotect",
    "__clear_cache",
    "cacheflush",
    "pthread_setname_np",
    // JNI attach lives in libart; libart is already excluded as a non-target
    // module, but listing keeps intent explicit if you ever instrument libart.
  ],
  // Only LOG events whose address lands in these modules. [] => restrict to the
  // matched thread's own entry module. Add names to widen, e.g. ["libfk.so"].
  onlyLogScopeModules: [],

  // ---- output / safety ----
  symbolicate: true,        // resolve addresses via dladdr (cached)
  maxThreads: 6,            // never stalk more than this many threads at once
  maxEventsPerThread: 50000,// auto-unfollow a thread after this many logged events
  flushBatch: 200,          // print at most this many lines per drain (rest counted+dropped)
  color: true,
};

// ===========================================================================
// Below is machinery; tweak CONFIG above, not this.
// ===========================================================================

const _c = {
  reset: "\x1b[0m", green: "\x1b[32m", red: "\x1b[31m",
  yellow: "\x1b[33m", cyan: "\x1b[36m", dim: "\x1b[2m",
};
const C = new Proxy(_c, { get: (t, k) => (CONFIG.color ? (t[k] || "") : "") });

const PID = Process.id;
const START = Date.now();
function tms() { return Date.now() - START; }

// --- dladdr resolver (light, cached) ---------------------------------------
const symCache = new Map();
let dladdr = null, dlInfo = null;
(function initDladdr() {
  try {
    const p = Module.findGlobalExportByName("dladdr");
    if (!p) return;
    dladdr = new NativeFunction(p, "int", ["pointer", "pointer"]);
    dlInfo = Memory.alloc(32);
  } catch (e) {}
})();

// resolve(addr) -> { lib, text }  (lib may be null if unknown)
function resolve(addr) {
  if (!addr || addr.isNull()) return { lib: null, text: "(null)" };
  const key = addr.toString();
  const hit = symCache.get(key);
  if (hit) return hit;

  let out = { lib: null, text: key };
  if (dladdr) {
    try {
      if (dladdr(addr, dlInfo) !== 0) {
        const fname = dlInfo.readPointer();
        const fbase = dlInfo.add(8).readPointer();
        const sname = dlInfo.add(16).readPointer();
        const saddr = dlInfo.add(24).readPointer();
        const lib = fname.isNull() ? null : (fname.readCString() || "").split("/").pop();
        let text;
        if (!sname.isNull()) {
          const nm = sname.readCString();
          const off = addr.sub(saddr);
          text = off.compare(0) === 0 ? `${nm} @ ${lib}` : `${nm}+0x${off.toString(16)} @ ${lib}`;
        } else if (lib) {
          text = `${lib}+0x${addr.sub(fbase).toString(16)}`;
        } else {
          text = key;
        }
        out = { lib, text };
      }
    } catch (e) {}
  }
  symCache.set(key, out);
  return out;
}

// routineModuleOffset(addr) -> { module, offset } using the module table.
function routineModuleOffset(addr) {
  if (!addr || addr.isNull()) return null;
  let m = null;
  try { m = Process.findModuleByAddress(addr); } catch (e) {}
  if (!m) return null;
  // NativePointer has no toNumber(); go via hex string.
  return { module: m.name, offset: parseInt(addr.sub(m.base).toString(), 16) };
}

// --- target parsing & matching ---------------------------------------------
// parseTarget("libfk.so+0x950bb8") -> {module:"libfk.so", offset:0x950bb8}
// parseTarget("0x950bb8@libfk.so") -> {module:"libfk.so", offset:0x950bb8}
// parseTarget("libfk.so")          -> {module:"libfk.so"}
// parseTarget("name:Thread-4")     -> {name:"Thread-4"}
function parseTarget(s) {
  s = String(s).trim();
  if (s.toLowerCase().startsWith("name:")) return { name: s.slice(5) };
  if (s.includes("@")) {
    const [off, mod] = s.split("@");
    return { module: mod.trim(), offset: parseInt(off, 16) };
  }
  if (s.includes("+")) {
    const [mod, off] = s.split("+");
    return { module: mod.trim(), offset: parseInt(off, 16) };
  }
  return { module: s };
}
const TARGETS = CONFIG.targets.map(parseTarget);

// returns the matched module name to use as default scope, or null if no match
function matchThread(thread) {
  const routine =
    thread.entrypoint && thread.entrypoint.routine ? thread.entrypoint.routine : null;
  const mo = routine ? routineModuleOffset(routine) : null;
  const name = thread.name || "";

  for (const t of TARGETS) {
    if (t.name != null) {
      if (name.includes(t.name)) return mo ? mo.module : null;
      continue;
    }
    if (!mo) continue;
    if (!mo.module.includes(t.module)) continue;
    if (t.offset != null && mo.offset !== t.offset) continue;
    return mo.module; // matched; module is the default logging scope
  }
  return null;
}

// --- Stalker.exclude: keep instrumentation INSIDE target modules only -------
// Exclude every loaded module whose name is NOT one of the target modules.
// Excluded ranges run natively (no rewrite, no code slab) -> confines Stalker
// to the target lib and avoids slab exhaustion on huge/hot foreign modules.
const TARGET_MODULE_NAMES = new Set(
  TARGETS.map((t) => t.module).filter(Boolean)
);

let excludedOnce = false;
function excludeAllButTargetsOnce() {
  if (excludedOnce || !CONFIG.excludeAllButTargets) return;
  excludedOnce = true;
  let kept = [], n = 0;
  try {
    for (const m of Process.enumerateModules()) {
      const isTarget = [...TARGET_MODULE_NAMES].some((name) => m.name.includes(name));
      if (isTarget) { kept.push(m.name); continue; }
      try { Stalker.exclude(m); n++; } catch (e) {}
    }
  } catch (e) {}
  console.log(`${C.dim}[stalk] excluded ${n} modules; instrumenting only: ${kept.join(", ") || "(target not loaded yet!)"}${C.reset}`);
  excludeFunctionsOnce();
}

// Exclude individual functions (by name) even if they sit inside a target
// module. Stalker.exclude needs a {base,size} range; function size isn't
// exposed, so we exclude a fixed span from the entry — enough to cover the
// prologue/body of small leaf functions like mprotect/cacheflush. Functions in
// libc/libart are already covered by the module-level exclude above; this is
// mainly for code-rewriting helpers that live inside the target lib itself.
const FUNC_EXCLUDE_SPAN = 0x400;
let funcsExcludedOnce = false;
function excludeFunctionsOnce() {
  if (funcsExcludedOnce) return;
  funcsExcludedOnce = true;
  const names = CONFIG.excludeFunctions || [];
  for (const name of names) {
    let addr = null;
    try { addr = Module.findGlobalExportByName(name); } catch (e) {}
    if (!addr) { console.log(`${C.dim}[stalk]   fn-exclude: ${name} not found${C.reset}`); continue; }
    try {
      Stalker.exclude({ base: addr, size: FUNC_EXCLUDE_SPAN });
      const r = resolve(addr);
      console.log(`${C.dim}[stalk]   fn-exclude: ${name} @ ${r.text} (+0x${FUNC_EXCLUDE_SPAN.toString(16)})${C.reset}`);
    } catch (e) {
      console.log(`${C.dim}[stalk]   fn-exclude: ${name} failed: ${e}${C.reset}`);
    }
  }
}

// --- coerce parsed Stalker values to NativePointer --------------------------
function np(x) {
  if (x == null) return null;
  if (typeof x === "string") return ptr(x);
  return x; // already a NativePointer
}

// --- per-thread stalk state -------------------------------------------------
const stalked = new Map(); // tid -> { name, scope:Set<string>|null, count, dropped, startedAt }
let stalkedCount = 0;

function scopeSetFor(defaultModule) {
  if (CONFIG.onlyLogScopeModules && CONFIG.onlyLogScopeModules.length) {
    return new Set(CONFIG.onlyLogScopeModules);
  }
  return defaultModule ? new Set([defaultModule]) : null; // null => no scope filter
}

function inScope(state, lib) {
  if (!state.scope) return true;     // no scope => allow all
  if (!lib) return false;            // unknown module, scope active => drop
  for (const s of state.scope) if (lib.includes(s)) return true;
  return false;
}

function eventsConfig() {
  const t = CONFIG.trace;
  return {
    call: !!t.call, ret: !!t.ret, exec: !!t.exec,
    block: !!t.block, compile: !!t.compile,
  };
}

function startStalk(thread, scopeModule) {
  const tid = thread.id;
  if (stalked.has(tid)) return;
  if (stalkedCount >= CONFIG.maxThreads) {
    console.log(`${C.yellow}[stalk] skip ${tid} (maxThreads ${CONFIG.maxThreads} reached)${C.reset}`);
    return;
  }

  const state = {
    name: thread.name || `(tid ${tid})`,
    scope: scopeSetFor(scopeModule),
    count: 0, dropped: 0, startedAt: tms(),
  };
  stalked.set(tid, state);
  stalkedCount++;
  const scopeDesc = state.scope ? [...state.scope].join(",") : "ALL";
  console.log(`${C.green}[stalk+]${C.reset} ${PID}:${state.name}#${tid} ${C.dim}scope=${scopeDesc} @+${state.startedAt}ms${C.reset}`);

  // Exclude all non-target modules now — the target lib is guaranteed loaded
  // here (this thread's entry lives in it), unlike at script load time.
  excludeAllButTargetsOnce();

  try {
    Stalker.follow(tid, {
      events: eventsConfig(),
      onReceive(events) {
        drainEvents(tid, state, events);
      },
    });
  } catch (e) {
    console.log(`${C.red}[stalk] follow ${tid} failed: ${e}${C.reset}`);
    stalked.delete(tid);
    stalkedCount--;
  }
}

function drainEvents(tid, state, events) {
  let parsed;
  try {
    parsed = Stalker.parse(events, { annotate: true, stringify: false });
  } catch (e) { return; }

  const lines = [];
  for (const ev of parsed) {
    if (state.count >= CONFIG.maxEventsPerThread) {
      stopStalk(tid, `event cap ${CONFIG.maxEventsPerThread} reached`);
      break;
    }
    const line = formatEvent(state, ev);
    if (line == null) continue; // filtered out by scope
    state.count++;
    if (lines.length < CONFIG.flushBatch) lines.push(line);
    else state.dropped++;
  }
  if (lines.length) {
    const tag = `${C.dim}#${tid}${C.reset}`;
    console.log(lines.map((l) => `${tag} ${l}`).join("\n"));
  }
}

function sym(addr) {
  if (!CONFIG.symbolicate) return addr.toString();
  return resolve(addr).text;
}

// returns formatted string, or null if it should be dropped by scope
function formatEvent(state, ev) {
  const type = ev[0];
  switch (type) {
    case "call": {
      const from = np(ev[1]), to = np(ev[2]), depth = ev[3];
      const r = resolve(to);
      if (!inScope(state, r.lib)) return null;
      return `${C.cyan}CALL${C.reset} ${sym(from)} -> ${r.text} ${C.dim}depth=${depth}${C.reset}`;
    }
    case "ret": {
      const from = np(ev[1]), to = np(ev[2]);
      const r = resolve(from);
      if (!inScope(state, r.lib)) return null;
      return `${C.dim}RET ${C.reset} ${r.text} -> ${sym(to)}`;
    }
    case "block": {
      const start = np(ev[1]), end = np(ev[2]);
      const r = resolve(start);
      if (!inScope(state, r.lib)) return null;
      const size = end && start ? parseInt(end.sub(start).toString(), 16) : 0;
      return `${C.yellow}BLOCK${C.reset} ${r.text} ${C.dim}(${size}B)${C.reset}`;
    }
    case "compile": {
      const start = np(ev[1]);
      const r = resolve(start);
      if (!inScope(state, r.lib)) return null;
      return `${C.dim}COMPILE${C.reset} ${r.text}`;
    }
    case "exec": {
      const pc = np(ev[1]);
      const r = resolve(pc);
      if (!inScope(state, r.lib)) return null;
      return `EXEC ${r.text}`;
    }
    default:
      return null;
  }
}

function stopStalk(tid, reason) {
  const state = stalked.get(tid);
  if (!state) return;
  try { Stalker.unfollow(tid); } catch (e) {}
  try { Stalker.flush(); } catch (e) {}
  stalked.delete(tid);
  stalkedCount--;
  console.log(`${C.red}[stalk-]${C.reset} ${PID}:${state.name}#${tid} ${C.dim}events=${state.count}${state.dropped ? ` dropped=${state.dropped}` : ""} reason=${reason || "thread exit"} @+${tms()}ms${C.reset}`);
}

// --- the observer -----------------------------------------------------------
const threadObs = Process.attachThreadObserver({
  onAdded(thread) {
    // runs in the NEW thread's context -> ideal place for Stalker.follow()
    const scopeModule = matchThread(thread);   // module name if matched, else null
    if (scopeModule !== null || isNameOnlyMatch(thread)) {
      startStalk(thread, scopeModule);
    }
  },
  onRemoved(thread) {
    stopStalk(thread.id);
  },
});

// name-only targets can match with a null scope; detect that case explicitly
function isNameOnlyMatch(thread) {
  const name = thread.name || "";
  return TARGETS.some((t) => t.name != null && name.includes(t.name));
}

// --- REPL helpers -----------------------------------------------------------
function stalking() {
  console.log(`${C.green}=== currently stalking (${stalked.size}) ===${C.reset}`);
  for (const [tid, s] of stalked) {
    const scope = s.scope ? [...s.scope].join(",") : "ALL";
    console.log(`  ${PID}:${s.name}#${tid} ${C.dim}events=${s.count} scope=${scope} since +${s.startedAt}ms${C.reset}`);
  }
  console.log("");
}

function stopAll() {
  const ids = [...stalked.keys()];
  ids.forEach((tid) => stopStalk(tid, "manual stopAll()"));
  try { Stalker.flush(); } catch (e) {}
  console.log(`${C.dim}[*] stopped ${ids.length} thread(s)${C.reset}`);
}

function clear() { console.log("\x1b[3J\x1b[H\x1b[2J"); }

function help() {
  const b = (s) => `${C.green}${s}${C.reset}`, d = (s) => `${C.dim}${s}${C.reset}`;
  console.log(`
${C.yellow}=== thread-stalker commands ===${C.reset}
  ${b("stalking()")}   ${d("list threads currently being stalked")}
  ${b("stopAll()")}    ${d("unfollow every stalked thread")}
  ${b("clear()")}      ${d("clear the screen")}
  ${b("help()")}       ${d("show this help")}

${d("Config is at the TOP of the script (CONFIG). Set targets to the entry-routine")}
${d('token from thread-monitor, e.g. "libfk.so", "libfk.so+0x950bb8", "0x950bb8@libfk.so".')}
${d("Log tags: [stalk+] begin  [stalk-] end  CALL/BLOCK/RET/EXEC/COMPILE per event")}
`);
}

globalThis.stalking = stalking;
globalThis.stopAll = stopAll;
globalThis.clear = clear;
globalThis.help = help;

console.log(`${C.dim}[*] thread-stalker ready. targets=[${CONFIG.targets.join(", ")}] events={${Object.keys(CONFIG.trace).filter((k) => CONFIG.trace[k]).join(",")}}. type ${C.reset}${C.green}help()${C.reset}`);
