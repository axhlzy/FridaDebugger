// Thread + Module observers with grouped REPL views. See bottom for commands.

// ANSI colors: green=created red=stopped yellow=renamed
const C = {
  reset: "\x1b[0m",
  green: "\x1b[32m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  dim: "\x1b[2m",
};

const PID = Process.id;
const START = Date.now();  // script start time; log timestamps are relative to this (ms)
const names = new Map();   // tid -> thread name (used to show creator name)
const pending = [];        // creators captured by pthread_create {parentTid, routineKey}

// Thread registry: `threads` keeps full history (incl. exited, to handle tid reuse),
// `liveByTid` points only to currently-alive records for fast rename/remove lookup.
const threads = [];
const liveByTid = new Map();

// Module registry: name -> { name, path, base, size, loadedAt, unloadedAt, loaded }
const modules = new Map();

// elapsed-ms prefix since script start
function ts() {
  return `${C.dim}[+${Date.now() - START}ms]${C.reset}`;
}

// --- live-log gating: pause streaming while running list()/tree()/inspect() so
// their output isn't interrupted by a sudden [thread+] line. Buffered logs are
// flushed on resume. Can also be called manually: pause() / resume().
let paused = false;
const logBuffer = [];
const LOG_BUFFER_MAX = 5000;

// --- live-log history: every emitted line is kept (with its elapsed-ms) so it
// can be replayed later. filter() re-prints matching past lines on demand.
const history = [];
const HISTORY_MAX = 20000;

function stripAnsi(s) {
  return s.replace(/\x1b\[[0-9;]*m/g, "");
}

function emit(line) {
  if (history.length >= HISTORY_MAX) history.shift();
  history.push(line);
  if (paused) {
    if (logBuffer.length < LOG_BUFFER_MAX) logBuffer.push(line);
    return;
  }
  console.log(line);
}

// ===========================================================================
// filter(keyword): replay PAST scrolling logs that match, from history.
// This does not affect future live logs — it re-prints what already scrolled by.
//   filter("fk")            replay past lines containing "fk"
//   filter("fk binder")     match ANY of the words (OR)
//   filter("fk", true)      invert: replay lines NOT containing "fk"
//   filter()                replay everything in history
// Runs with live logs paused so the replay isn't interrupted.
// ===========================================================================
function filter(keyword, invert) {
 withPaused(() => {
  const words = String(keyword || "").toLowerCase().split(/\s+/).filter(Boolean);
  const match = (line) => {
    if (words.length === 0) return true;
    const text = stripAnsi(line).toLowerCase();
    const hit = words.some((w) => text.includes(w));
    return invert ? !hit : hit;
  };

  const sel = history.filter(match);
  const desc = words.length
    ? `${invert ? "NOT matching" : "matching"} ${words.join(" | ")}`
    : "all";
  console.log(`\n${C.dim}[filter] replaying ${sel.length} / ${history.length} past lines (${desc})${C.reset}`);
  sel.forEach((l) => console.log(l));
  console.log(`${C.dim}[filter] end of replay${C.reset}\n`);
 });
}

function pause() {
  paused = true;
}

function resume() {
  paused = false;
  if (logBuffer.length) {
    const n = logBuffer.length;
    const dropped = n >= LOG_BUFFER_MAX;
    logBuffer.forEach((l) => console.log(l));
    logBuffer.length = 0;
    console.log(`${C.dim}[*] resumed, flushed ${n} buffered line(s)${dropped ? " (buffer was full, some dropped)" : ""}${C.reset}`);
  }
}

// Run fn with live logs paused, then auto-resume (used by list/tree/inspect).
function withPaused(fn) {
  const wasPaused = paused;
  paused = true;
  try {
    fn();
  } finally {
    if (!wasPaused) resume(); // only auto-resume if we were the one who paused
  }
}

// Format a thread identity as PID:name#TID, tagging the process main thread
// (where tid == pid) with a "(main)" note.
function tag(name, tid) {
  return `${PID}:${name}#${tid}${tid === PID ? " (main)" : ""}`;
}

// --- dladdr: resolve an address to its owner (so + nearest symbol) -----------
// Much lighter than DebugSymbol (only reads loaded-module symbol tables), and
// cached: each entry address is resolved once, so during an ART thread-pool
// storm almost everything hits the cache and we rarely call native code in a
// new-thread context.
const symCache = new Map();
let dladdr = null;
let dlInfo = null; // Dl_info buffer (32B): fname/fbase/sname/saddr, 8B each
(function initDladdr() {
  try {
    const p = Module.findGlobalExportByName("dladdr");
    if (!p) return;
    dladdr = new NativeFunction(p, "int", ["pointer", "pointer"]);
    dlInfo = Memory.alloc(32);
  } catch (e) {}
})();

function resolve(addr) {
  if (!addr || addr.isNull()) return "(null)";
  const key = addr.toString();
  const hit = symCache.get(key);
  if (hit !== undefined) return hit;

  let out = key;
  if (dladdr) {
    try {
      if (dladdr(addr, dlInfo) !== 0) {
        const fname = dlInfo.readPointer();         // dli_fname  owner file path
        const fbase = dlInfo.add(8).readPointer();  // dli_fbase  module base
        const sname = dlInfo.add(16).readPointer(); // dli_sname  nearest symbol name
        const saddr = dlInfo.add(24).readPointer(); // dli_saddr  symbol address
        const lib = fname.isNull() ? "?" : (fname.readCString() || "?").split("/").pop();
        if (!sname.isNull()) {
          const name = sname.readCString();
          const off = addr.sub(saddr);
          out = off.compare(0) === 0
            ? `${name} @ ${lib}`
            : `${name}+0x${off.toString(16)} @ ${lib}`;
        } else {
          out = `${lib}+0x${addr.sub(fbase).toString(16)}`; // no symbol: module offset
        }
      }
    } catch (e) {}
  }
  symCache.set(key, out);
  return out;
}

// --- hook thread-creation funcs to record "who creates whom". onEnter is light/safe.
(function installCreationHooks() {
  const fns = Process.platform === "windows"
    ? ["_beginthreadex", "CreateThread"]
    : ["pthread_create"];
  for (const fn of fns) {
    const addr = Module.findGlobalExportByName(fn);
    if (!addr) continue;
    Interceptor.attach(addr, {
      onEnter(args) {
        pending.push({
          parentTid: Process.getCurrentThreadId(),
          routineKey: args[2].toString(),
        });
      },
    });
    break;
  }
})();

function takeCreator(routineKey) {
  if (pending.length === 0) return null;
  if (routineKey) {
    const idx = pending.findIndex((p) => p.routineKey === routineKey);
    if (idx !== -1) return pending.splice(idx, 1)[0];
  }
  return pending.shift(); // FIFO fallback
}

const threadObs = Process.attachThreadObserver({
    onAdded(thread) {
      const tid = thread.id;
      const rawName = thread.name ?? null;
      if (rawName) names.set(tid, rawName);

      const routine =
        thread.entrypoint && thread.entrypoint.routine ? thread.entrypoint.routine : null;
      const creator = takeCreator(routine ? routine.toString() : null);

      // creator: if not captured, it's a system/startup thread (created before our hook)
      const creatorName = creator ? (names.get(creator.parentTid) ?? null) : null;
      const from = creator
        ? tag(creatorName ?? "?", creator.parentTid)
        : "[system]";

      // New thread name often inherits the parent's comm; the real name arrives
      // shortly after via [thread~]. If empty or same as creator, mark "(unnamed-yet)"
      // so it isn't mistaken for the same thread.
      let toName = rawName;
      if (!rawName || (creatorName && rawName === creatorName)) toName = "(unnamed-yet)";
      const to = tag(toName, tid);

      const r = routine ? resolve(routine) : "(none)";
      const param = thread.entrypoint ? (thread.entrypoint.parameter ?? null) : null;

      // register (pure JS, light/safe)
      const rec = {
        tid,
        initialName: toName,          // name at creation (often inherited/unnamed-yet)
        currentName: rawName,         // latest name, updated on rename
        renames: [],                  // rename history [{from,to,at}]
        creator: creator
          ? { tid: creator.parentTid, name: creatorName }
          : null,
        routine: r,                   // resolved entry owner (string)
        routinePtr: routine,          // raw entry pointer (for inspect)
        param: param ? param.toString() : null,
        paramPtr: param,              // raw arg pointer (for inspect)
        createdAt: Date.now() - START,
        exitedAt: null,
        alive: true,
      };
      threads.push(rec);
      liveByTid.set(tid, rec);

      emit(
        `${ts()} ${C.green}[thread+]${C.reset} ${from} -> ${to} ${C.dim}routine=${r} param=${param}${C.reset}`
      );
    },
    onRemoved(thread) {
      const rec = liveByTid.get(thread.id);
      if (rec) {
        rec.alive = false;
        rec.exitedAt = Date.now() - START;
        if (thread.name) rec.currentName = thread.name;
        liveByTid.delete(thread.id);
      }
      names.delete(thread.id);
      emit(`${ts()} ${C.red}[thread-]${C.reset} ${tag(thread.name ?? `(tid ${thread.id})`, thread.id)}`);
    },
    onRenamed(thread, previousName) {
      if (thread.name) names.set(thread.id, thread.name);
      const rec = liveByTid.get(thread.id);
      if (rec) {
        rec.renames.push({
          from: previousName ?? "(unnamed)",
          to: thread.name ?? "(unnamed)",
          at: Date.now() - START,
        });
        rec.currentName = thread.name ?? rec.currentName;
      }
      emit(`${ts()} ${C.yellow}[thread~]${C.reset} ${tag(thread.name ?? "(unnamed)", thread.id)} ${previousName ?? "(unnamed)"} -> ${thread.name ?? "(unnamed)"}`);
    },
  });

// Module observer: log + register so loads/unloads. Callback is light (Map write
// + emit), safe to run inline. Color: cyan-ish via yellow for load, red unload.
const moduleObs = Process.attachModuleObserver({
  onAdded(m) {
    const rec = modules.get(m.name);
    if (rec) {
      rec.loaded = true;
      rec.unloadedAt = null;
    } else {
      modules.set(m.name, {
        name: m.name,
        path: m.path,
        base: m.base,
        size: m.size,
        loadedAt: Date.now() - START,
        unloadedAt: null,
        loaded: true,
      });
    }
    emit(`${ts()} ${C.green}[module+]${C.reset} ${m.name} ${C.dim}${m.path} base=${m.base} size=0x${m.size.toString(16)}${C.reset}`);
  },
  onRemoved(m) {
    const rec = modules.get(m.name);
    if (rec) {
      rec.loaded = false;
      rec.unloadedAt = Date.now() - START;
    }
    emit(`${ts()} ${C.red}[module-]${C.reset} ${m.name} ${C.dim}${m.path}${C.reset}`);
  },
});

// ===========================================================================
// list command: grouped view of all recorded threads (running / exited) with detail.
// Runs in the REPL (safe JS thread), reads the registry only, no native calls.
//   list()            default: hide system-lib threads, show app logic only
//   list("binder")    filter by keyword (matches name / routine, case-insensitive)
//   list("", true)    show all (incl. system-lib threads)
//   listAll()         alias for list("", true)
// ===========================================================================

// System libraries: threads whose entry routine lives in these are hidden by default.
const SYS_LIBS = [
  "libart.so", "libc.so", "libc++.so", "libutils.so", "libbinder.so",
  "libandroid_runtime.so", "libjavacore.so", "libopenjdkjvm.so",
  "libadbconnection.so", "libnativehelper.so", "libcutils.so",
  "libgui.so", "libhwui.so", "libsqlite.so", "libRS.so", "libbase.so",
];

function isSystemThread(t) {
  const r = t.routine || "";
  // routine looks like "name @ libxxx.so" or "libxxx.so+0x..."
  return SYS_LIBS.some((lib) => r.includes(lib));
}

function list(keyword, showSystem) {
 withPaused(() => {
  const kw = (keyword || "").toLowerCase();
  const match = (t) => {
    if (!showSystem && isSystemThread(t)) return false;
    if (!kw) return true;
    const name = (t.currentName ?? t.initialName ?? "").toLowerCase();
    return name.includes(kw) || (t.routine || "").toLowerCase().includes(kw);
  };

  const sel = threads.filter(match);
  const running = sel.filter((t) => t.alive);
  const exited = sel.filter((t) => !t.alive);

  const fmt = (t) => {
    const name = t.currentName ?? t.initialName ?? "(unnamed)";
    const from = t.creator
      ? tag(t.creator.name ?? "?", t.creator.tid)
      : "[system]";
    const lines = [];
    lines.push(`  ${tag(name, t.tid)}  ${C.dim}<= creator ${from}${C.reset}`);
    lines.push(`      entry  : routine=${t.routine}  param=${t.param}`);
    if (t.renames.length) {
      const chain = [t.initialName, ...t.renames.map((r) => `${r.to}(+${r.at}ms)`)].join(" -> ");
      lines.push(`      renamed: ${chain}`);
    }
    if (t.alive) {
      lines.push(`      ${C.dim}created +${t.createdAt}ms, alive ${Date.now() - START - t.createdAt}ms${C.reset}`);
    } else {
      lines.push(`      ${C.dim}created +${t.createdAt}ms, exited +${t.exitedAt}ms, lived ${t.exitedAt - t.createdAt}ms${C.reset}`);
    }
    return lines.join("\n");
  };

  const hint = [];
  if (kw) hint.push(`keyword="${keyword}"`);
  hint.push(showSystem ? "system libs included" : "system libs hidden");
  console.log(`\n${C.dim}[filter] ${hint.join(", ")}${C.reset}`);

  console.log(`${C.green}=== RUNNING (${running.length}) ===${C.reset}`);
  running.forEach((t) => console.log(fmt(t)));
  console.log(`\n${C.red}=== EXITED (${exited.length}) ===${C.reset}`);
  exited.forEach((t) => console.log(fmt(t)));

  const hidden = threads.length - sel.length;
  console.log(`\n${C.dim}shown ${sel.length} / total ${threads.length} (running ${running.length} / exited ${exited.length}, filtered ${hidden})${C.reset}\n`);
 });
}

function listAll(keyword) { list(keyword, true); }

// ===========================================================================
// tree command: parent -> child relationship tree, same filtering as list.
//   tree()            default: hide system-lib threads
//   tree("binder")    filter by keyword (name / routine)
//   tree("", true)    show all (incl. system libs)
//   treeAll()         alias for tree("", true)
// A node is kept if it matches the filter OR any descendant matches, so paths
// to matched threads stay visible. Kept-only-for-path nodes are dimmed "(filtered)".
// ===========================================================================
function tree(keyword, showSystem) {
 withPaused(() => {
  const kw = (keyword || "").toLowerCase();
  const selfVisible = (t) => {
    if (!showSystem && isSystemThread(t)) return false;
    if (!kw) return true;
    const name = (t.currentName ?? t.initialName ?? "").toLowerCase();
    return name.includes(kw) || (t.routine || "").toLowerCase().includes(kw);
  };

  // build parentTid -> [child records]; roots = no creator or creator not recorded
  const known = new Set(threads.map((t) => t.tid));
  const childrenOf = new Map();
  const roots = [];
  for (const t of threads) {
    const ptid = t.creator ? t.creator.tid : null;
    if (ptid != null && known.has(ptid) && ptid !== t.tid) {
      if (!childrenOf.has(ptid)) childrenOf.set(ptid, []);
      childrenOf.get(ptid).push(t);
    } else {
      roots.push(t);
    }
  }

  // a node is shown if it is self-visible or has any shown descendant
  const isShown = (t, guard) => {
    guard = guard || new Set();
    if (guard.has(t)) return false;
    guard.add(t);
    if (selfVisible(t)) return true;
    return (childrenOf.get(t.tid) || []).some((c) => isShown(c, guard));
  };

  const printed = new Set();
  let count = 0;
  const label = (t) => {
    const name = t.currentName ?? t.initialName ?? "(unnamed)";
    const id = tag(name, t.tid);
    const life = t.alive
      ? `${C.green}alive ${Date.now() - START - t.createdAt}ms${C.reset}`
      : `${C.red}exited, lived ${t.exitedAt - t.createdAt}ms${C.reset}`;
    const pass = selfVisible(t) ? "" : `${C.dim}(filtered) ${C.reset}`;
    const route = t.routine && t.routine !== "(none)" ? ` ${C.dim}${t.routine}${C.reset}` : "";
    return `${pass}${id} [${life}]${route}`;
  };
  const walk = (t, prefix, isLast) => {
    if (printed.has(t)) return;
    printed.add(t);
    count++;
    console.log(`${prefix}${isLast ? "└─ " : "├─ "}${label(t)}`);
    const kids = (childrenOf.get(t.tid) || []).filter((c) => isShown(c) && !printed.has(c));
    const childPrefix = prefix + (isLast ? "   " : "│  ");
    kids.forEach((c, i) => walk(c, childPrefix, i === kids.length - 1));
  };

  const shownRoots = roots.filter((r) => isShown(r));

  const hint = [];
  if (kw) hint.push(`keyword="${keyword}"`);
  hint.push(showSystem ? "system libs included" : "system libs hidden");
  console.log(`\n${C.dim}[filter] ${hint.join(", ")}${C.reset}`);
  shownRoots.forEach((r, i) => walk(r, "", i === shownRoots.length - 1));
  console.log(`\n${C.dim}shown ${count} / total ${threads.length}${C.reset}\n`);
 });
}

function treeAll(keyword) { tree(keyword, true); }

// ===========================================================================
// inspect(tid): deep-look at one thread's entry param (the void* arg passed to
// start_routine). Runs in the REPL (safe), never in a new-thread context.
//
// IMPORTANT: this must NOT call Process.enumerateThreads() — that suspends every
// thread to read register contexts and deadlocks/hangs on busy multi-threaded
// apps (e.g. Unity) when triggered from the REPL. We classify using only
// Process.findRangeByAddress (reads /proc maps, no thread suspension).
//
// Reports for the param pointer:
//   - region: module(.so) / rw-anon (heap-ish) / r-x / unmapped
//   - access validity: mapped & readable? (stale/dangling risk)
//   - symbol info: dladdr resolution if it points into a module
//   - small hex dump + first pointer-word resolved (likely vtable/callback)
// Note: exact heap-vs-stack cannot be told from maps alone without suspending
// threads, so anonymous rw memory is reported as "anon-rw (heap or stack)".
// ===========================================================================

function classify(addr) {
  if (!addr || addr.isNull()) return { kind: "null", readable: false };

  let range = null;
  try { range = Process.findRangeByAddress(addr); } catch (e) {}
  if (!range) {
    return { kind: "unmapped", readable: false };
  }

  const prot = range.protection;
  const readable = prot.indexOf("r") !== -1;
  const writable = prot.indexOf("w") !== -1;
  const exec = prot.indexOf("x") !== -1;

  let kind, detail = "";
  if (range.file && range.file.path) {
    kind = "module";
    detail = `${range.file.path.split("/").pop()}+0x${addr.sub(range.base).toString(16)}`;
  } else if (exec) {
    kind = "anon-rx (jit/code)";
  } else if (writable) {
    kind = "anon-rw (heap or stack)";
  } else {
    kind = "anon";
  }

  return { kind, detail, readable, protection: prot, base: range.base, size: range.size };
}

function inspect(tid) {
 withPaused(() => {
  const rec = [...threads].reverse().find((t) => t.tid === tid);
  if (!rec) { console.log(`no record for tid ${tid}`); return; }

  const name = rec.currentName ?? rec.initialName ?? "(unnamed)";
  console.log(`\n${C.green}inspect ${tag(name, tid)}${C.reset} ${rec.alive ? "" : C.red + "[EXITED]" + C.reset}`);
  console.log(`  entry  routine=${rec.routine}`);

  const p = rec.paramPtr;
  if (!p || p.isNull()) { console.log(`  param  (null)\n`); return; }
  console.log(`  param  ${p}`);

  // 1) region classification (maps-only, no thread suspension)
  const c = classify(p);
  console.log(`  region ${c.kind}${c.detail ? " " + c.detail : ""}` +
    (c.protection ? ` ${C.dim}[${c.protection}] base=${c.base} size=0x${c.size.toString(16)}${C.reset}` : ""));

  // 2) access validity / stale risk
  if (c.kind === "unmapped") {
    console.log(`  access ${C.red}UNMAPPED - reading would fault (dangling/freed/invalid)${C.reset}\n`);
    return;
  }
  if (!c.readable) {
    console.log(`  access ${C.red}not readable [${c.protection}] - skip dump${C.reset}\n`);
    return;
  }
  if (!rec.alive) {
    console.log(`  access ${C.yellow}thread exited; param may be freed - dump is best-effort${C.reset}`);
  } else {
    console.log(`  access ${C.green}mapped & readable${C.reset}`);
  }

  // 3) symbol info (if param points into a module)
  if (c.kind === "module") {
    console.log(`  symbol ${resolve(p)}`);
  }

  // 4) hex dump + first word resolved (likely vtable / callback)
  try {
    const dump = hexdump(p, { length: 64, ansi: true, header: false });
    console.log(dump.split("\n").map((l) => "         " + l).join("\n"));
  } catch (e) {
    console.log(`  ${C.red}dump failed: ${e}${C.reset}`);
  }
  try {
    const first = p.readPointer();
    const fc = classify(first);
    const fsym = fc.kind === "module" ? resolve(first) : `(${fc.kind})`;
    console.log(`  word0  ${first} -> ${fsym}  ${C.dim}(if module/.so, likely vtable or callback)${C.reset}`);
  } catch (e) {}
  console.log("");
 });
}

// ===========================================================================
// libs command: list loaded shared objects. Default shows only APK-bundled libs
// (the app's own native code), hiding system libraries.
//   libs()            APK libs only (loaded)
//   libs("unity")     filter by name/path keyword
//   libs("", true)    show all loaded modules (incl. system)
//   libsAll()         alias for libs("", true)
// Records come from the module observer; also seeds from a one-time enumerate so
// modules loaded before the observer attached are included.
// ===========================================================================

// An APK-bundled lib lives under the app's data dir or is mapped from the APK.
function isApkLib(path) {
  if (!path) return false;
  return /\/data\/(app|data)\//.test(path) || /\.apk!/.test(path) || /\/data\/app-lib\//.test(path);
}

// Seed the registry once with already-loaded modules (observer only sees future
// load/unload events). Safe: enumerateModules() reads maps, no thread suspension.
function seedModules() {
  try {
    for (const m of Process.enumerateModules()) {
      if (modules.has(m.name)) continue;
      modules.set(m.name, {
        name: m.name, path: m.path, base: m.base, size: m.size,
        loadedAt: null, unloadedAt: null, loaded: true,
      });
    }
  } catch (e) {}
}

function libs(keyword, showSystem) {
 withPaused(() => {
  seedModules();
  const kw = (keyword || "").toLowerCase();
  const sel = [...modules.values()].filter((m) => {
    if (!m.loaded) return false;
    if (!showSystem && !isApkLib(m.path)) return false;
    if (!kw) return true;
    return m.name.toLowerCase().includes(kw) || (m.path || "").toLowerCase().includes(kw);
  });
  sel.sort((a, b) => a.name.localeCompare(b.name));

  const hint = [];
  if (kw) hint.push(`keyword="${keyword}"`);
  hint.push(showSystem ? "all modules" : "APK libs only");
  console.log(`\n${C.dim}[filter] ${hint.join(", ")}${C.reset}`);
  console.log(`${C.green}=== LOADED LIBS (${sel.length}) ===${C.reset}`);
  for (const m of sel) {
    const when = m.loadedAt != null ? ` ${C.dim}loaded +${m.loadedAt}ms${C.reset}` : ` ${C.dim}(pre-existing)${C.reset}`;
    console.log(`  ${m.name}  ${C.dim}base=${m.base} size=0x${m.size.toString(16)}${C.reset}${when}`);
    console.log(`      ${C.dim}${m.path}${C.reset}`);
  }
  const total = [...modules.values()].filter((m) => m.loaded).length;
  console.log(`\n${C.dim}shown ${sel.length} / ${total} loaded modules${C.reset}\n`);
 });
}

function libsAll(keyword) { libs(keyword, true); }

// Clear the terminal (ANSI: cursor home + clear screen + clear scrollback).
function clear() {
  console.log("\x1b[3J\x1b[H\x1b[2J");
}

// Show usage for all commands.
function help() {
  const b = (s) => `${C.green}${s}${C.reset}`;
  const d = (s) => `${C.dim}${s}${C.reset}`;
  console.log(`
${C.yellow}=== FridaDebugger commands ===${C.reset}

${C.green}Threads${C.reset}
  ${b("list()")}              ${d("running/exited threads with detail (APK only)")}
  ${b('list("kw")')}          ${d("filter by name/routine keyword")}
  ${b('list("", true)')} ${b("/ listAll()")}  ${d("include system-lib threads")}
  ${b("tree()")}              ${d("parent -> child thread tree (APK only)")}
  ${b('tree("kw")')} ${b("/ treeAll()")}      ${d("filter / include system")}
  ${b("inspect(tid)")}        ${d("deep-look a thread's entry param (region/access/symbol/dump)")}

${C.green}Modules${C.reset}
  ${b("libs()")}              ${d("loaded APK .so libraries")}
  ${b('libs("kw")')}          ${d("filter by name/path keyword")}
  ${b('libs("", true)')} ${b("/ libsAll()")}  ${d("include system libraries")}

${C.green}Live log${C.reset}
  ${b("pause()")} ${b("/ resume()")}    ${d("stop / resume the scrolling log")}
  ${b('filter("kw")')}        ${d("replay PAST log lines matching keyword(s)")}
  ${b('filter("a b")')}       ${d("OR-match multiple words")}
  ${b('filter("kw", true)')}  ${d("invert: replay lines NOT matching")}
  ${b("filter()")}            ${d("replay full history")}

${C.green}Misc${C.reset}
  ${b("clear()")}             ${d("clear the screen")}
  ${b("help()")}              ${d("show this help")}

${d("Log tags: [thread+] created  [thread-] exited  [thread~] renamed  [module+/-] so load/unload")}
`);
}

globalThis.list = list;
globalThis.listAll = listAll;
globalThis.tree = tree;
globalThis.treeAll = treeAll;
globalThis.inspect = inspect;
globalThis.libs = libs;
globalThis.libsAll = libsAll;
globalThis.pause = pause;
globalThis.resume = resume;
globalThis.filter = filter;
globalThis.clear = clear;
globalThis.help = help;
console.log(`${C.dim}[*] ready. type ${C.reset}${C.green}help()${C.reset}${C.dim} for all commands${C.reset}`);
