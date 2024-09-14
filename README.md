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

idea:
 现在已知的问题是stalker trace出来的汇编未必和原来的汇编完全对的上 ( 所以很多时候看起来还是有点问题的 )
 所以新的思路考虑 使用qbdi frida signal 的组合，借用qbdi的单步指令trace，然后把信号下在每次指令执行的位置以达到单步执行的效果
 ... todo ...
 考虑到frida脚本就脚本吧，每次都要附带一个so的push多麻烦的，所以暂时是这么考虑优化：
 将编译出来的so文件base64编码在js脚本中，运行时解出来再使用frida的load将动态库加载进去

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

![debug](https://github.com/axhlzy/FridaDebugger/blob/main/images/debug.png)
