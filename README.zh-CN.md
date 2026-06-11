# Frida Stalker 断点调试器

- [English README](README.md)
- [Wiki（中文）](https://github.com/axhlzy/FridaDebugger/wiki/Home_CN)
- [Wiki（English）](https://github.com/axhlzy/FridaDebugger/wiki/Home_EN)

`b(address)` 会在目标地址安装 `Interceptor.attach()` 监听器。命中断点后，监听器会在当前线程上启动 Stalker。Stalker 的 callout 会打印寄存器，并通过 libc 信号量暂停线程，便于在 Frida REPL 中单步调试。

## 构建

```powershell
npm install
npm run build
```

## 使用

```powershell
frida -U -f <package> -l _agent.js
```

在 Frida REPL 中：

```js
help()                 // 再次打印启动帮助页
b("0x12345678")        // 附加断点，命中后启动 Stalker
b("0x12345678", { snapshot: false }) // 跳过附加前的反汇编快照
s(3)                   // 单步执行 3 条指令；s() 默认为 1
si()                   // 步入：运行直到 LR 发生变化
so()                   // 步出：运行直到 PC 到达当前 LR
ni()                   // 下一步：跨过 call 类指令
until("0x12345678")    // 静默运行直到指定地址
c()                    // 继续执行并结束当前 Stalker 会话
d()                    // 继续当前会话并 detach 所有断点
bt()                   // 打印暂停上下文的回溯
regs()                 // 打印当前寄存器
dis()                  // 从当前位置反汇编；默认 8 条指令
dis("0x12345678", 16)  // 从指定地址反汇编 16 条指令
stack()                // 打印 SP..FP 栈窗口
stack(48)              // 最多打印 48 个栈项
ia("0x12345678")       // 用 DebugSymbol 与惰性 IL2CPP 名称解析地址
ia("x0")               // 解析暂停上下文中的寄存器值
sr("x0", "0x1")        // 在暂停状态下修改寄存器
wm("sp+0x20", 0, "u32") // 写内存；可用于栈槽
callFunction(sym.il2cpp.il2cpp_string_new, Memory.allocUtf8String("123"))
sym.il2cpp.il2cpp_string_new(Memory.allocUtf8String("123")) // 直接调用符号
sym.il2cpp.il2cpp_string_new.address // 导出的 libil2cpp 函数指针
sym.il2cpp.Application.functionName // Unity 类简名快捷方式
sym.il2cpp.classes.GameController.Start // Unity 类方法指针（若可用）
sym.reload()            // 刷新 native 符号命名空间
lfs("x0")              // 仅 Unity IL2CPP：列出对象寄存器的字段
lfs("0x12345678")      // 仅 Unity IL2CPP：列出对象地址的字段
pdf("0x12345678")      // 仅 Unity IL2CPP：反汇编完整函数
ffr("0x12345678")      // 实验性：Process.findFunctionRange(address)
cfg("0x12345678")      // 实验性：ControlFlowGraph(address)
cfg("0x12345678", 16, 4) // 限制基本块数量及每块指令数
show("stack", false)   // 切换 asm/reg/sym/stack/bt 输出
status()               // 显示活跃的 Stalker 会话
bl()                   // 列出已附加断点及命中次数
bc("0x12345678")       // detach 指定 Interceptor 监听器
bd("0x12345678")       // 禁用断点但不 detach
be("0x12345678")       // 重新启用已禁用的断点
dispose()              // detach 监听器并释放被暂停的线程
```

## 工作原理

`b()` 将输入转换为 `NativePointer`，在 hook 地址附近快照一小段指令窗口，然后调用 `Interceptor.attach(address, { onEnter })`。附加前不会做范围检查或符号查找。

附加前，agent 会在 hook 地址附近快照一小段反汇编窗口。这样可以保留用户原始的断点上下文，避免 `Interceptor.attach()` 改写首条指令后丢失现场。

命中断点后：

1. `onEnter` 记录命中，并在当前线程上启动 `Stalker.follow()`。
2. Stalker 将指令过滤限制在包含断点地址的模块内。
3. Stalker 在该模块内每条被跟踪指令之前插入 callout。
4. callout 打印汇编窗口、寄存器，并在信号量上等待。
5. `s(count)` 释放信号量，保持 Stalker 活跃，直到执行完 `count` 条指令。
6. `si()` 静默运行直到 LR 变化。若当前指令不是 call 类（`bl`/`blr`），则回退为 `s(1)`。
7. `so()` 静默运行直到 PC 到达暂停上下文时捕获的 LR。
8. `ni()` 跨过 call 类指令，运行直到下一条 PC。
9. `until(addr)` 静默运行直到请求地址。
10. `c()` 取消跟踪线程、释放信号量，让程序继续运行。

`si()` 和 `so()` 不会打印中间步骤，仅在条件满足时停止并输出。内置安全预算可防止条件永远不满足时无限运行。

若 `so()`、`ni()` 或 `until()` 的目标地址不在当前模块过滤范围内，会临时放宽过滤，停止后恢复。

当前指令是 Stalker transform 回调中捕获的原始指令，在 `[asm]` 输出中用 `=>` 标记。

暂停输出会将 Stalker 的实际执行 PC 与展示给用户的目标代码 PC 分开。若 Stalker 到达断点模块中的真实代码，则直接显示该地址；若先到达 Frida 生成的重定位入口代码，agent 会映射回附加前的反汇编快照，并同时记录 `pc=<展示地址>` 与 `actual=<stalker 地址>`。

## 日志颜色

- 黄色：断点命中与当前指令
- 青色：分隔线与跟踪过滤信息
- 绿色：成功操作与关键寄存器
- 灰色：上下文行
- 红色：错误

单步后，发生变化的寄存器也会以红色高亮。可解析的寄存器值会以 `[sym]` 行输出，使用 `DebugSymbol.fromAddress()`。若值属于 `libil2cpp.so`，解析器还会向 `frida-il2cpp-bridge` 查询 IL2CPP 方法名。在 Unity IL2CPP 进程中，看起来像可读托管对象的寄存器值也会用 `new Il2Cpp.Object(value).toString()` 解析。当 `DebugSymbol.fromAddress()` 返回以相同地址开头的字符串时，重复的地址会被替换为 `@`。

## Unity IL2CPP 辅助命令

`lfs(value)` 是 Unity IL2CPP 辅助命令。可接受地址或暂停寄存器名（如 `x0`），验证该值能否解析为 `Il2Cpp.Object`，然后打印对象类层次结构中所有非静态字段。指针类型的字段值会通过与寄存器、栈槽相同的符号、IL2CPP 方法与对象解析器进行解析。仅当脚本检测到 Unity IL2CPP 模块时，启动横幅才会显示此命令。

`pdf(address)` 同样仅在检测到 Unity IL2CPP 时可用。它会解析包含 `address` 的 IL2CPP 方法，惰性推进方法索引直到已知下一个方法起始地址，并反汇编完整的 `[start, nextStart)` 范围。直接 call 指令会标注解析后的目标符号或 IL2CPP 方法名；间接 call 会标记为间接，因为运行时目标在寄存器中。

IL2CPP 方法名采用惰性加载。agent 不会在启动时枚举全部方法，仅在需要解析 `libil2cpp.so` 内地址时以小批量推进类遍历，将已发现的方法起始地址排序保存，并通过二分查找将地址映射到最近的方法起始点。

## 寄存器、内存与符号

`sr(register, value)` 修改当前暂停的 `CpuContext`，因此在 `s()` 或 `c()` 后 Stalker callout 返回时新寄存器值会生效。`wm(address, value, type)` 直接写内存。地址可以是绝对指针或暂停寄存器表达式（如 `sp+0x20`）；支持的类型包括 `pointer`、`u8`、`u16`、`u32`、`u64`、`s8`、`s16`、`s32`、`s64`、`float`、`double`、`utf8`。

`bd(address)` 与 `be(address)` 可在保持 `Interceptor` 监听器附加的情况下切换断点启用状态。`regs()` 打印当前暂停寄存器状态。`callFunction(address, ...args)` 使用指针返回类型与指针参数类型手动调用 native 函数，并用常规地址解析打印返回值。

`sym` 是用于 REPL 补全与快速查找的 native 导出与 Unity 元数据命名空间。模块名会规范化：去掉前缀 `lib` 与后缀 `.so`，因此 `libil2cpp.so` 变为 `sym.il2cpp`。每个模块命名空间将导出函数暴露为可调用符号对象，使用 `.address` 获取原始 native 指针。在 Unity IL2CPP 中，`sym.il2cpp.classes` 包含命名空间/类/方法树，方法值为可调用 native 符号。类简名快捷方式也会直接挂在 `sym.il2cpp` 下，例如名为 `Application` 的类可通过 `sym.il2cpp.Application` 访问。使用 `sym.il2cpp.list("string")` 过滤名称，在新模块加载后调用 `sym.reload()`。

## 栈与回溯

每次暂停还会基于 `sp` 与 `fp` 打印栈窗口。较长的栈范围会被截断，只显示头尾，中间省略项会汇总说明。栈上的指针值通过 `DebugSymbol.fromAddress()` 解析；对 IL2CPP 代码地址还会使用相同的惰性方法解析器。看起来像 Unity 托管对象的栈值会用与寄存器相同的 `Il2Cpp.Object` 尽力解析逻辑处理。发生变化的栈槽以红色高亮。栈从高地址向低地址展示，即 `fp -> sp`，偏移量仍相对于 `sp`。

`bt()` 首先用暂停上下文遍历帧指针链；若无法得到调用帧，则回退到 Frida 的模糊回溯器。结果会合并并去重。

## 实验性功能

`ffr(address)` 与 `cfg(address)` 是实验性辅助命令，需要 `frida-server >= 17.12.0`。它们分别调用 Frida 的 `Process.findFunctionRange()` 与 `ControlFlowGraph`。`ffr()` 打印 Frida 能为某地址推断的最佳函数范围。`cfg()` 为包含该地址的函数构建控制流图，并打印基本块、边、直接支配者及少量指令预览。

## 清理

脚本卸载时，会通过 `Script.bindWeak` 释放调试器状态：detach 所有断点监听器、取消活跃 Stalker 会话、释放信号量，使被暂停的目标线程可以继续运行。`dispose()` 可手动执行相同清理。

启动横幅会分组展示断点、执行、检查与清理相关命令。

## 快速示例

```js
b("0x7e3e726bb8")
// 触发对应代码路径
s()
s()
c()
```

请使用字符串地址或 `ptr("0x...")` 表示 64 位地址。JavaScript 中的大整数字面量可能丢失精度。

## 后续计划

- 增加调试录制。未来的 `record()` 流程应捕获每次暂停时的展示 PC、实际 Stalker PC、指令、寄存器差异、栈差异与解析符号，以便导出并回顾调试会话。
- 抽象断点后端。当前实现以 `Interceptor.attach()` 作为断点后端。未来应支持 `interceptor`、`hardware` 与 `software-brk`，让调试器为精确指令断点选择最安全的可用机制。
- 增强 `callFunction()`。计划支持显式返回类型、显式参数类型、通过 `Memory.allocUtf8String()` 自动转换 JavaScript 字符串，以及 Unity IL2CPP 返回值格式化，使 `Il2Cpp.String` 结果以可读字符串打印。

## 已知问题

Unity 对象实例解析是尽力而为的。部分寄存器、栈、字段或数组值可能看起来像有效的 `Il2Cpp.Object` 指针，但实际指向已失效或无效的 Unity 对象。对这些值调用 bridge 辅助函数（如 `new Il2Cpp.Object(ptr).toString()`）或读取字段，可能在目标进程内挂起或变得非常慢。若出现此情况，请避免用 `lfs()` 展开该值，优先使用原始指针/符号检查。
