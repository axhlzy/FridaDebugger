# Frida Stalker Breakpoint

- [中文文档（仓库内）](README.zh-CN.md)
- [Wiki（English）](https://github.com/axhlzy/FridaDebugger/wiki/Home_EN)
- [Wiki（中文）](https://github.com/axhlzy/FridaDebugger/wiki/Home_CN)

`b(address)` installs an `Interceptor.attach()` listener. When the address is
hit, the listener starts Stalker on the current thread. Stalker callouts print
registers and pause the thread through a libc semaphore.
