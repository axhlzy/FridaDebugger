# Frida Stalker Breakpoint

`b(address)` installs an `Interceptor.attach()` listener. When the address is
hit, the listener starts Stalker on the current thread. Stalker callouts print
registers and pause the thread through a libc semaphore.

## Build

```powershell
npm install
npm run build
```

## Use

```powershell
frida -U -f <package> -l _agent.js
```

In the Frida REPL:

```js
help()                 // print the startup help page again
b("0x12345678")        // attach breakpoint and start Stalker when hit
b("0x12345678", { snapshot: false }) // skip pre-attach disassembly
s(3)                   // step 3 instructions; s() defaults to 1
si()                   // step in: run until LR changes
so()                   // step out: run until PC reaches the current LR
ni()                   // next: step over call-like instruction
until("0x12345678")    // run silently until address
c()                    // continue and stop the current Stalker session
d()                    // continue current session and detach all breakpoints
bt()                   // print backtrace for the paused context
regs()                 // print current registers
dis()                  // disassemble from current position; default count is 8
dis("0x12345678", 16)  // disassemble 16 instructions from an address
stack()                // print SP..FP stack window
stack(48)              // print at most 48 stack entries
ia("0x12345678")       // resolve address with DebugSymbol and lazy IL2CPP names
ia("x0")               // resolve a register value from the paused context
sr("x0", "0x1")        // set a register while paused
wm("sp+0x20", 0, "u32") // write memory; useful for stack slots
callFunction(sym.il2cpp.il2cpp_string_new, Memory.allocUtf8String("123"))
sym.il2cpp.il2cpp_string_new(Memory.allocUtf8String("123")) // direct symbol call
sym.il2cpp.il2cpp_string_new.address // exported libil2cpp function pointer
sym.il2cpp.Application.functionName // Unity class simple-name shortcut
sym.il2cpp.classes.GameController.Start // Unity class method pointer when available
sym.reload()            // refresh native symbol namespaces
lfs("x0")              // Unity IL2CPP only: list fields of an object register
lfs("0x12345678")      // Unity IL2CPP only: list fields of an object address
pdf("0x12345678")      // Unity IL2CPP only: disassemble a full function
ffr("0x12345678")      // experiment: Process.findFunctionRange(address)
cfg("0x12345678")      // experiment: ControlFlowGraph(address)
cfg("0x12345678", 16, 4) // limit blocks and instructions per block
show("stack", false)   // toggle asm/reg/sym/stack/bt output
status()               // show active Stalker sessions
bl()                   // list attached breakpoints and hit counts
bc("0x12345678")       // detach the Interceptor listener
bd("0x12345678")       // disable a breakpoint without detaching
be("0x12345678")       // enable a disabled breakpoint
dispose()              // detach listeners and release paused threads
```

`b()` converts the input to a `NativePointer`, snapshots a small instruction
window around the hook address, then calls `Interceptor.attach(address,
{ onEnter })`. There is no range check or symbol lookup before attaching.

Before attaching, the agent snapshots a small disassembly window around the hook
address. This preserves the user's original breakpoint context before
`Interceptor.attach()` patches the first instructions.

On hit:

1. `onEnter` logs the hit and starts `Stalker.follow()` on the current thread.
2. Stalker filters instructions to the module containing the breakpoint address.
3. Stalker inserts a callout before each followed instruction in that module.
4. The callout logs an assembly window, registers, and waits on a semaphore.
5. `s(count)` posts the semaphore and keeps Stalker active until `count`
   instructions have executed.
6. `si()` silently runs until LR changes. If the current instruction is not
   call-like (`bl`/`blr`), it falls back to `s(1)`.
7. `so()` silently runs until PC reaches the LR captured at the paused context.
8. `ni()` steps over call-like instructions by running until the next PC.
9. `until(addr)` silently runs until the requested address.
10. `c()` unfollows the thread, posts the semaphore, and lets the program run.

`si()` and `so()` do not print intermediate steps. They stop and print only when
their condition is reached. A safety budget prevents them from running forever if
the condition is never observed.

If `so()`, `ni()`, or `until()` targets an address outside the current module
filter, the filter is temporarily relaxed and restored after stopping.

The current instruction is the original instruction captured in Stalker's
transform callback. It is marked with `=>` in the `[asm]` output.

The first pause is mapped back to the hook address supplied to `b()`. Its log
uses `pc=<hook address> actual=<stalker address>` so the breakpoint context stays
anchored to the user's address while still exposing Stalker's real execution PC.

Log colors:

- yellow: breakpoint hits and current instruction
- cyan: section separators and trace filters
- green: successful actions and key registers
- gray: context lines
- red: errors

Changed registers are also highlighted in red after stepping.
Resolvable register values are printed as `[sym]` lines using
`DebugSymbol.fromAddress()`. If a value belongs to `libil2cpp.so`, the resolver
also asks `frida-il2cpp-bridge` for the IL2CPP method name.
In Unity IL2CPP processes, register values that look like readable managed
objects are also parsed with `new Il2Cpp.Object(value).toString()`.
When `DebugSymbol.fromAddress()` returns a string starting with the same address,
the repeated address is replaced with `@`.

`lfs(value)` is a Unity IL2CPP helper. It accepts an address or a paused-register
name such as `x0`, validates that the value can be parsed as an `Il2Cpp.Object`,
then prints all non-static fields from the object's class hierarchy. Field values
that are pointers are resolved through the same symbol, IL2CPP method, and object
resolver used by registers and stack slots. The startup banner only shows this
command when the script detects a Unity IL2CPP module.

`sr(register, value)` mutates the current paused `CpuContext`, so the new
register value takes effect when the Stalker callout returns after `s()` or
`c()`. `wm(address, value, type)` writes memory directly. The address can be an
absolute pointer or a paused register expression such as `sp+0x20`; supported
types include `pointer`, `u8`, `u16`, `u32`, `u64`, `s8`, `s16`, `s32`, `s64`,
`float`, `double`, and `utf8`.

`bd(address)` and `be(address)` toggle a breakpoint's enabled state while
keeping its `Interceptor` listener attached. `regs()` prints the current paused
register state. `callFunction(address, ...args)` manually invokes a native
function using pointer return and pointer argument types, then prints the return
value with normal address resolution.

`sym` is a native export and Unity metadata namespace used for REPL completion
and quick lookup. Module names are normalized by removing a leading `lib` and a
trailing `.so`, so `libil2cpp.so` becomes `sym.il2cpp`. Each module namespace
exposes exported functions as callable symbol objects. Use `.address` to get the
raw native pointer. In Unity IL2CPP, `sym.il2cpp.classes`
contains a namespace/class/method tree where method values are callable native
symbols.
Simple class-name shortcuts are also added directly under `sym.il2cpp`, so a
class named `Application` can be accessed as `sym.il2cpp.Application`. Use
`sym.il2cpp.list("string")` to filter names, and `sym.reload()` after new
modules are loaded.

`ffr(address)` and `cfg(address)` are experimental helpers that require
`frida-server >= 17.12.0`. They exercise Frida's `Process.findFunctionRange()`
and `ControlFlowGraph`. `ffr()` prints the best function range Frida can infer
for an address. `cfg()` builds a control-flow graph for the containing function
and prints basic blocks, edges, immediate dominators, and a small instruction
preview.

`pdf(address)` is available only when Unity IL2CPP is detected. It resolves the
IL2CPP method containing `address`, advances the lazy method index until the next
method start is known, and disassembles the full `[start, nextStart)` range.
Direct call instructions are annotated with the resolved target symbol or
IL2CPP method name. Indirect calls are marked as such because the target is held
in a register at runtime.

IL2CPP method names are loaded lazily. The agent does not enumerate all methods
at startup. It advances through classes in small batches only when an address in
`libil2cpp.so` needs resolving, keeps discovered method starts sorted, and uses
binary search to map an address to the nearest method start.

Each pause also prints a stack window based on `sp` and `fp`. Long stack ranges
are truncated by showing the head and tail, with omitted entries summarized.
Pointer values on the stack are resolved with `DebugSymbol.fromAddress()` and,
for IL2CPP code addresses, the same lazy method resolver. Stack values that look
like Unity managed objects are parsed with the same `Il2Cpp.Object` best-effort
logic used for registers.
Changed stack slots are highlighted in red.
The stack is displayed from high address to low address, i.e. `fp -> sp`, while
offsets remain relative to `sp`.

The startup banner prints grouped usage for breakpoints, execution, inspection,
and cleanup commands.

`bt()` first walks the frame-pointer chain using the paused context. If that does
not produce caller frames, it falls back to Frida's fuzzy backtracer. Results are
merged and de-duplicated.

When the script is unloaded, it disposes debugger state through `Script.bindWeak`.
This detaches all breakpoint listeners, unfollows active Stalker sessions, and
posts semaphores so paused target threads can continue. `dispose()` runs the same
cleanup manually.

## Known Issues

Unity object instance parsing is best-effort. Some register, stack, field, or
array values may look like valid `Il2Cpp.Object` pointers but actually point to
stale or invalid Unity objects. Calling bridge helpers such as
`new Il2Cpp.Object(ptr).toString()` or reading fields from those objects can hang
or become very slow inside the target process. If this happens, avoid expanding
that value with `lfs()` and prefer raw pointer/symbol inspection.

```js
b("0x7e3e726bb8")
// trigger the code path
s()
s()
c()
```

Use string addresses or `ptr("0x...")` for 64-bit addresses. Large numeric
literals may lose precision in JavaScript.
