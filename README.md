Easy Use： 
frida --codeshare axhlzy/fridadebugger -U -f ${PackageName}

- 在arm64实现了基本的单个断点的步过和继续

1. b(functionaddress)

2. si() step ins 步进

3. ni() next ins 步过 ( todo ... )

4. n(mPtr) nop

5. c() continue 继续

6. dism(mPtr) 给定位置反汇编

---

todo: 
 平栈解析
 ...

每一步的执行都将被记录
这些记录可以用来后续进行时间无关回溯，回退到任何状态
或者是筛选过滤，分析出函数调用栈以及执行流程

后续会继续完善功能，有什么好的想法或者是建议可以去提出issue,或者pr,欢迎大伙儿一起来完善项目

--- 

![bt](https://github.com/axhlzy/FridaDebugger/blob/main/images/bt.png)

![si](https://github.com/axhlzy/FridaDebugger/blob/main/images/si.png)
