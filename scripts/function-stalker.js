// ===========================================================================
// function-stalker.js — Stalker-trace a function's execution, scoped to each
// CALL into it. Interceptor.attach the target; on ENTER, Stalker.follow the
// current thread; on LEAVE, Stalker.unfollow. Unlike thread-stalker (which
// follows a whole thread for its entire life), this only instruments the
// dynamic extent of the target function — far lighter and avoids whole-thread
// crashes (e.g. an injector thread that installs hooks / does JNI attach).
//
// targets here are FUNCTIONS to hook (entry addresses), taken from a tool like
// thread-monitor or your own offsets, e.g. "libil2cpp.so+0x1218300".
//
// WARNING: Stalker is heavy. If the target function is a hot/long loop, scope
// it tight and prefer call/block over exec.
// ===========================================================================

const CONFIG = {
  // ---- functions to hook & trace (matched/resolved to an address) ----
  //   "libil2cpp.so+0x1218300"   module + offset
  //   "0x1218300@libil2cpp.so"   same, alternate syntax
  //   "0x7xxxxxxxxx"             absolute address
  //   "open"                     exported symbol name (any module)
  targets: [
    "libil2cpp.so+0x1218300",
  ],

  // ---- which Stalker events to record during the call ----
  trace: {
    call: true,     // CALL instructions                          — "指令调用"
    block: false,   // basic-block execution                      — "基本块调用"
    ret: false,     // RET instructions
    compile: false, // basic-block compilation (first time seen)
    exec: false,    // EVERY instruction — EXTREMELY heavy, careful!
  },

  // ---- scope: confine instrumentation ----
  // Exclude every module except the target function's own module, so Stalker
  // runs foreign code (libc/libart/libunity/...) natively — no code-slab blowup.
  excludeAllButTargets: true,
  // Functions to Stalker.exclude even inside the target module (code-rewriting
  // / cache-flushing helpers that fight Stalker). Resolved in any module.
  excludeFunctions: [
    "mprotect", "__clear_cache", "cacheflush",
  ],
  // Only LOG events landing in these modules. [] => the target's own module.
  onlyLogScopeModules: [],

  // ---- args / return logging for the hooked function itself ----
  logArgs: 4,        // print this many integer args on enter (0 to disable)
  logRet: true,      // print return value on leave

  // ---- output / safety ----
  symbolicate: true,
  maxDepthFollow: true,      // handle recursion: follow only at outermost enter
  maxEventsPerCall: 20000,   // stop recording within a call after this many events
  flushBatch: 200,
  maxCalls: 0,               // 0 = unlimited; else auto-detach after N calls
  color: true,
};

// ===========================================================================
// Machinery below; tweak CONFIG above.
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
        } else { text = key; }
        out = { lib, text };
      }
    } catch (e) {}
  }
  symCache.set(key, out);
  return out;
}

// --- resolve a target string to an absolute address -------------------------
// "mod+0xoff" | "0xoff@mod" | "0xabs" | "symbolName"
function resolveTarget(s) {
  s = String(s).trim();
  try {
    if (s.includes("@")) {
      const [off, mod] = s.split("@");
      const m = Process.findModuleByName(mod.trim());
      return m ? m.base.add(parseInt(off, 16)) : null;
    }
    if (s.includes("+")) {
      const [mod, off] = s.split("+");
      const m = Process.findModuleByName(mod.trim());
      return m ? m.base.add(parseInt(off, 16)) : null;
    }
    if (/^0x[0-9a-f]+$/i.test(s)) return ptr(s);
    return Module.findGlobalExportByName(s); // symbol name
  } catch (e) { return null; }
}

// module name of a target string, for the exclude step
function targetModuleName(s) {
  s = String(s).trim();
  if (s.includes("@")) return s.split("@")[1].trim();
  if (s.includes("+")) return s.split("+")[0].trim();
  // absolute / symbol: resolve then look up
  const a = resolveTarget(s);
  if (!a) return null;
  let m = null; try { m = Process.findModuleByAddress(a); } catch (e) {}
  return m ? m.name : null;
}

// --- Stalker.exclude: confine instrumentation -------------------------------
let excludedOnce = false;
function excludeAllButTargetsOnce(targetMods) {
  if (excludedOnce || !CONFIG.excludeAllButTargets) return;
  excludedOnce = true;
  const keepNames = new Set(targetMods.filter(Boolean));
  let kept = [], n = 0;
  try {
    for (const m of Process.enumerateModules()) {
      const isTarget = [...keepNames].some((name) => m.name.includes(name));
      if (isTarget) { kept.push(m.name); continue; }
      try { Stalker.exclude(m); n++; } catch (e) {}
    }
  } catch (e) {}
  console.log(`${C.dim}[fstalk] excluded ${n} modules; instrumenting only: ${kept.join(", ") || "(none?)"}${C.reset}`);

  const FUNC_SPAN = 0x400;
  for (const name of (CONFIG.excludeFunctions || [])) {
    let a = null; try { a = Module.findGlobalExportByName(name); } catch (e) {}
    if (!a) { console.log(`${C.dim}[fstalk]   fn-exclude: ${name} not found${C.reset}`); continue; }
    try {
      Stalker.exclude({ base: a, size: FUNC_SPAN });
      console.log(`${C.dim}[fstalk]   fn-exclude: ${name} @ ${resolve(a).text}${C.reset}`);
    } catch (e) {}
  }
}

// --- scope filter -----------------------------------------------------------
function scopeSetFor(defaultModule) {
  if (CONFIG.onlyLogScopeModules && CONFIG.onlyLogScopeModules.length) {
    return new Set(CONFIG.onlyLogScopeModules);
  }
  return defaultModule ? new Set([defaultModule]) : null;
}
function inScope(scope, lib) {
  if (!scope) return true;
  if (!lib) return false;
  for (const s of scope) if (lib.includes(s)) return true;
  return false;
}

function eventsConfig() {
  const t = CONFIG.trace;
  return { call: !!t.call, ret: !!t.ret, exec: !!t.exec, block: !!t.block, compile: !!t.compile };
}

function np(x) {
  if (x == null) return null;
  if (typeof x === "string") return ptr(x);
  return x;
}

// --- per-thread follow state (handle recursion: follow at outermost only) ---
const depthByTid = new Map();   // tid -> reentry depth
const stateByTid = new Map();   // tid -> { scope, count, dropped }
let callsSeen = 0;

function beginFollow(tid, scope) {
  const d = (depthByTid.get(tid) || 0) + 1;
  depthByTid.set(tid, d);
  if (d > 1 && CONFIG.maxDepthFollow) return; // already following at outer frame

  const state = { scope, count: 0, dropped: 0 };
  stateByTid.set(tid, state);
  try {
    Stalker.follow(tid, {
      events: eventsConfig(),
      onReceive(events) { drainEvents(tid, state, events); },
    });
  } catch (e) {
    console.log(`${C.red}[fstalk] follow ${tid} failed: ${e}${C.reset}`);
  }
}

function endFollow(tid) {
  const d = (depthByTid.get(tid) || 0) - 1;
  depthByTid.set(tid, Math.max(0, d));
  if (d > 0 && CONFIG.maxDepthFollow) return; // still inside outer frame
  try { Stalker.unfollow(tid); } catch (e) {}
  try { Stalker.flush(); } catch (e) {}
  const st = stateByTid.get(tid);
  stateByTid.delete(tid);
  return st;
}

function drainEvents(tid, state, events) {
  let parsed;
  try { parsed = Stalker.parse(events, { annotate: true, stringify: false }); }
  catch (e) { return; }
  const lines = [];
  for (const ev of parsed) {
    if (state.count >= CONFIG.maxEventsPerCall) break;
    const line = formatEvent(state, ev);
    if (line == null) continue;
    state.count++;
    if (lines.length < CONFIG.flushBatch) lines.push(line);
    else state.dropped++;
  }
  if (lines.length) {
    const tag = `${C.dim}#${tid}${C.reset}`;
    console.log(lines.map((l) => `${tag} ${l}`).join("\n"));
  }
}

function sym(addr) { return CONFIG.symbolicate ? resolve(addr).text : addr.toString(); }

function formatEvent(state, ev) {
  const type = ev[0];
  switch (type) {
    case "call": {
      const from = np(ev[1]), to = np(ev[2]), depth = ev[3];
      const r = resolve(to);
      if (!inScope(state.scope, r.lib)) return null;
      return `${C.cyan}CALL${C.reset} ${sym(from)} -> ${r.text} ${C.dim}depth=${depth}${C.reset}`;
    }
    case "ret": {
      const from = np(ev[1]), to = np(ev[2]);
      const r = resolve(from);
      if (!inScope(state.scope, r.lib)) return null;
      return `${C.dim}RET ${C.reset} ${r.text} -> ${sym(to)}`;
    }
    case "block": {
      const start = np(ev[1]), end = np(ev[2]);
      const r = resolve(start);
      if (!inScope(state.scope, r.lib)) return null;
      const size = end && start ? parseInt(end.sub(start).toString(), 16) : 0;
      return `${C.yellow}BLOCK${C.reset} ${r.text} ${C.dim}(${size}B)${C.reset}`;
    }
    case "compile": {
      const r = resolve(np(ev[1]));
      if (!inScope(state.scope, r.lib)) return null;
      return `${C.dim}COMPILE${C.reset} ${r.text}`;
    }
    case "exec": {
      const r = resolve(np(ev[1]));
      if (!inScope(state.scope, r.lib)) return null;
      return `EXEC ${r.text}`;
    }
    default: return null;
  }
}

// --- install hooks ----------------------------------------------------------
const hooks = [];
function install() {
  const targetMods = [];
  let installed = 0;

  for (const spec of CONFIG.targets) {
    const addr = resolveTarget(spec);
    if (!addr) { console.log(`${C.red}[fstalk] cannot resolve target: ${spec}${C.reset}`); continue; }
    const modName = targetModuleName(spec);
    if (modName) targetMods.push(modName);
    const scope = scopeSetFor(modName);
    const label = resolve(addr).text;

    try {
      const h = Interceptor.attach(addr, {
        onEnter(args) {
          if (CONFIG.maxCalls && callsSeen >= CONFIG.maxCalls) return;
          callsSeen++;
          const tid = Process.getCurrentThreadId();
          let argStr = "";
          if (CONFIG.logArgs > 0) {
            const parts = [];
            for (let i = 0; i < CONFIG.logArgs; i++) {
              try { parts.push(`a${i}=${args[i]}`); } catch (e) {}
            }
            argStr = " " + parts.join(" ");
          }
          console.log(`${C.green}[call+]${C.reset} ${label} ${C.dim}#${tid} @+${tms()}ms${C.reset}${C.dim}${argStr}${C.reset}`);
          beginFollow(tid, scope);
        },
        onLeave(retval) {
          const tid = Process.getCurrentThreadId();
          const st = endFollow(tid);
          const cnt = st ? ` events=${st.count}${st.dropped ? ` dropped=${st.dropped}` : ""}` : "";
          const ret = CONFIG.logRet ? ` ret=${retval}` : "";
          console.log(`${C.red}[call-]${C.reset} ${label} ${C.dim}#${tid}${ret}${cnt}${C.reset}`);
        },
      });
      hooks.push(h);
      installed++;
      console.log(`${C.green}[fstalk] hooked${C.reset} ${label} ${C.dim}(${spec})${C.reset}`);
    } catch (e) {
      console.log(`${C.red}[fstalk] attach failed for ${spec}: ${e}${C.reset}`);
    }
  }

  if (installed) excludeAllButTargetsOnce(targetMods);
  console.log(`${C.dim}[*] function-stalker ready. hooked ${installed}/${CONFIG.targets.length}, events={${Object.keys(CONFIG.trace).filter((k) => CONFIG.trace[k]).join(",")}}. type ${C.reset}${C.green}help()${C.reset}`);
}

// --- REPL helpers -----------------------------------------------------------
function detachAll() {
  hooks.forEach((h) => { try { h.detach(); } catch (e) {} });
  hooks.length = 0;
  for (const tid of [...stateByTid.keys()]) { try { Stalker.unfollow(tid); } catch (e) {} }
  try { Stalker.flush(); } catch (e) {}
  depthByTid.clear(); stateByTid.clear();
  console.log(`${C.dim}[*] detached all hooks & unfollowed${C.reset}`);
}
function clear() { console.log("\x1b[3J\x1b[H\x1b[2J"); }
function help() {
  const b = (s) => `${C.green}${s}${C.reset}`, d = (s) => `${C.dim}${s}${C.reset}`;
  console.log(`
${C.yellow}=== function-stalker ===${C.reset}
  ${b("detachAll()")}  ${d("remove all hooks and stop following")}
  ${b("clear()")}      ${d("clear the screen")}
  ${b("help()")}       ${d("show this help")}

${d("Edit CONFIG at top: targets=functions to hook+trace, e.g. \"libil2cpp.so+0x1218300\".")}
${d("Per call: [call+] enter (args) -> Stalker events -> [call-] leave (ret, count).")}
`);
}

globalThis.detachAll = detachAll;
globalThis.clear = clear;
globalThis.help = help;

install();
