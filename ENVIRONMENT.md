# 项目环境与工作记录（ENVIRONMENT.md）

> 用途：记录本项目的机器环境、安装内容、仓库布局、清理策略与里程碑/待办，供任何接手者（或重装系统后的自己）一键复原。
> 维护约定：每次安装新东西/清理文件/完成里程碑，先改本文档再改代码。
> 更新：2026-09-15（r6.4 小里程碑收口）

---

## 1. 机器环境（已安装，含来源）

| 组件 | 版本 | 位置 | 来源/安装方式 |
| --- | --- | --- | --- |
| Git | 2.55.0.windows.3 | `C:\Program Files\Git` | 华为云镜像（见 project_memory：winget 境外源失败史）；SSH ed25519 免密，GitHub 走 22 端口 |
| Python（系统） | 3.12.10 + pip 25.0.1 | `C:\Program Files\Python312` | npmmirror 安装包；已 `pip install zstandard`（清华 pypi 镜像） |
| Python（嵌入式，项目自带） | 3.12 + capstone + pefile | `9-4#2\tools\python\python.exe` | 免安装，随仓库本地保留（gitignore 排除）；**分析脚本一律用它**（`import pefile/capstone` 只有它有） |
| MinGW-w64 (gcc) | 16.2.0（MSYS2 构建） | `C:\workspace\tools\mingw64\mingw64` | 清华 MSYS2 镜像 15 个 `.pkg.tar.zst` 手装（zstd 用系统 python 的 zstandard 解压 + tar 解包）；含 gcc/binutils/crt/headers/pthread/gmp/mpfr/mpc/isl/zstd/libiconv/manifest/gettext-runtime/zlib/winpthreads；**编译 implant 前须把其 bin 加 PATH** |
| .NET csc | 4.0.30319 | `C:\Windows\Microsoft.NET\Framework64\...` | 系统自带（RvaPatcher 等 C# 工具用它，已归档） |

**复装脚本**：`tools/install_mingw.ps1`（本次安装全流程，可重放）。
**约定**：安装包统一下载到 `C:\workspace\downloads\`，装完即删（本次已清，17 个 mingw 包 67MB 已删）。

### 编译 implant 速查

```powershell
$env:PATH = 'C:\workspace\tools\mingw64\mingw64\bin;' + $env:PATH
gcc -shared -O2 -s -o implant\implant.dll implant\implant.c          # 注入模块（-s strip 符号=反指纹要求）
gcc -O2 -municode -o implant\inject.exe implant\inject.c -ladvapi32  # 注入器
# 或直接: powershell -File implant\build.ps1
```

**implant 运行控制（环境变量，注入前在启动器 shell 里 set）**：
- `IMPLANT_OUT=<目录>`：日志输出目录（默认 %TEMP%；日志文件名 implant_<pid>.log）
- `IMPLANT_DUMP=1`：开启全量 methods.tsv 落盘（默认关=无磁盘痕迹；做全表解析时才开）
- `IMPLANT_HOOKTEST=1`：开启活体 detour 自测（默认关——会改写游戏活代码，仅隔离环境用）

---

## 2. 仓库布局（两个 git 仓库 + 依赖）

| 仓库 | 本地路径 | 远程 | 内容 | 分支现状 |
| --- | --- | --- | --- | --- |
| **xxx_reverse** | `9-4#2\xxx\` | `git@github.com:Purties/xxx_reverse.git` | 交接文档（UNPACKING_REPORT r6.4 / STRATEGY_PIVOT / PHASE0_REPORT）+ analysis 产物（含 13.8 万行新版方法表） | main，已同步 |
| **xxx_implant** | `9-4#2\` | `git@github.com:Purties/xxx_implant.git` | tools（分析/签名/验证脚本 26 个）+ implant（自研模块源码） | master，已同步 |

- 外层 `.gitignore` 关键策略：二进制（exe/dll/bin/dat/zip）、内嵌 python、mingw 工具链、运行日志、`xxx/`（独立仓库）均不入库
- **不入库的大资产**（本地保留，路径固定）：
  - `tools\GameAssembly.dll`（新版 ba7b80fc，117MB）＋ `tools\GameAssembly_old_0902.dll`（老版 09fbcb26，116MB）＋ `tools\global-metadata_new.dat`（新版元数据 17MB）——跨构建验证三件套
  - `xxx\ControlProc*.exe`（原始+两份解包映像，~187MB）
  - `xxx\analysis\memscan\region_0_0x269C000.bin`（8.9MB 注入 DLL 转储）
- 现场/游戏目录（不在仓库）：老客户端 `C:\冒险岛online\mxdclassic`（0902 版）；新客户端 `D:\冒险岛online\mxdclassic`（ba7b80fc 版）；原版 ControlProc 运行目录 `9-4\xxx\`
- `9-4#2\xxx\config.json` 为现场运行配置，**永不入库**（untracked 属预期）

## 3. 本次清理记录（2026-09-15）

已删：`C:\workspace\downloads\*.pkg.tar.zst`（67MB）、`tools\patcher_run_*.log`×14 + `phase0_smoke.log`（RvaPatcher 线已废止）、`implant\out\*`（运行产物，poc 日志要点已摘录进文档）、`implant\sig_*.txt`（中间产物，掩码已内嵌 implant.c）。
保留决策：`observe\20260913_232703\events.jsonl`（160MB，含注入链关键观测原始数据，虽大但是 §4 章节的证据源——暂留，若 GitHub 推送无压力不动它）。

---

## 4. 里程碑时间线（阶段式）

| 里程碑 | 日期 | 内容 | 证据/产物 |
| --- | --- | --- | --- |
| **M-0 战略转向定稿** | 09-14 | 原版被官方特征化识别 → 废止"修原版"全线（RvaPatcher/RVA 全量迁移/devirt），转自研反检测注入模块 | UNPACKING_REPORT 文首 + STRATEGY_PIVOT.md（r6.0） |
| **M-1 阶段 0 侦察** | 09-14 | 功能基线（P0/P1/P2/丢弃分级）；11 维特征枚举→6 条反检测硬要求；IPC 契约 18 对象+句柄实锤；il2cpp 241 导出实锤 | PHASE0_REPORT.md + feature_baseline.txt + fingerprint_recon.txt |
| **M-2 阶段 1 POC 全绿** | 09-14 | 老客户端活体：枚举 62ms/13.8 万方法、RVA 反查 5/5、身份键 5/5；创建时注入绕开句柄剥离实锤；dispatch join 47/126 | §5.9 + poc_result.log（要点已摘录）+ dispatch_identity.tsv |
| **M-3 跨构建判别** | 09-14 | 哈希逐构建轮换（0/7，控制组有效）→ 身份键仅构建内有效 | §5.9.5 + xbuild_identity_check.py |
| **M-4 特征签名架构定案** | 09-14 | 掩码签名（老/新自动 diff）+ 结构约束（C=同类+call I）；离线两版唯一 + 老客户端活体 5/5；detour 引擎离线单测 PASS；纯离线字节法上限 ~24/126 实锤 | §5.9.5b + sig_design.py + hooktest.c |
| **M-5 新版现场闭环** | 09-15 | 登录器启动新版游戏 + `--race` 竞速注入成功；SIG-VERDICT 5/5 全中新版 RVA；新版 13.8 万方法表入库 | §5.9.5c + methods_new_0915.tsv |
| **M-6 第三构建终验+重构** | 09-15 | 游戏再次更新（0c06cc8c）：4/5→修复 C 函数尾钳制→**5/5 全 RESOLVED-NEW 零人工**；代码评审重构（去开发机路径/strip/VEH 用完即卸/落盘默认关/hooktest 目标修复） | §5.9.5d + poc_build3_refactor.log + poc_build3_run.log |
| **M-7 签名法推广 126（当前）** | 09-15 | 28 个已配对目标跑双版 diff+第三版校验→**21 条三构建唯一签名**编入 `implant/sigs126.inc`（静态映像扫描通道）；--spawn 活体 **SIG126-VERDICT 21/21**；启发式单版掩码/hash-join 配对两路被已知答案实验否决 | §5.9.5e + sig126_paired.py + poc_sig126_run.log |

**M-5/M-6/M-7 含义**：钩子定位问题彻底解决且不依赖人工每构建维护——连续两次真实游戏更新（ba7b80fc→0c06cc8c）零干预全解析；dispatch 目标覆盖 5→23 个（21 静态+5 钩）。阶段 1 收官。

---

## 5. 后续计划（待办全量，含负责人）

### P0 —— 阶段 2 功能复刻（当前主线）

1. **新客户端全钩子解析**（用户配合：启动新版游戏到任意界面即可）
   - 现状：5 钩已 5/5；其余 ~121 个 dispatch 目标需把 implant 的 `g_sigs[]` 扩成全表——但**其余 121 个没有第二构建样本可自动 diff 掩码**，做法：先按 `sig_design.py` 框架对老版 126 RVA 生成"老版唯一"签名（含通配启发式：掩码所有 RIP disp32/imm8/imm32 大常数），再在新版现场跑一次 implant 收集候选 → 用同类/call 图/参数数约束消歧 → 产出新版全表
   - 判据：新版上 dispatch 全表命中 + 与已知 5 钩交叉一致
2. **端到端功能验证（M1 无 UI 最小可用）**（用户配合：新版进游戏世界，小号）
   - SetVelocity 族 detour 真实对象生效（速度可感变化）→ 无敌（SetDamaged 拦截）→ 战斗步进
   - 开关：配置文件 + 热键（无 UI）；detour 引擎已离线 PASS，活体首测在隔离窗口做，崩了有 VEH 留痕
3. **旧版行为观察**（用户方便时，与 1/2 并行）：按 UNPACKING_REPORT §5.10.4 协议在旧客户端逐项开/关功能并回报现象 + 页签截图 → 补全行为规格（M3 输入）

### P1 —— 反检测工程化（阶段 2 后半）

4. 注入手法：POC 的 LoadLibrary（模块可见）→ 手动映射复刻（去模块列表痕迹）；内存画像正常化（避免大块 RWX、代码/数据分段）
5. 静态去特征：字符串/常量运行时解密、配置键名表加密、无作者路径/构建号/日志落盘（对照 fingerprint_recon.txt 11 维逐项自检，用 ScoutScan 思路自扫）
6. 行为去特征：Present hook 自写（不用 kiero）、ImGui 自编译去 assert 串、钩子安装时机随机化
7. 自检门禁：每次发版前跑"特征扫描器找不到自己"回归

### P2 —— 脱离 ControlProc（阶段 3 慢线，卡密 9/26 到期前必须评估）

8. 授权 MITM 基础设施（winhttp 系统代理 + mitmproxy）：观察 lease 通道版本表下发（§5.3 闭环）+ 为卡密到期后自建控制器铺路
9. 自建注入控制器（替代 ControlProc 启动/多开/状态回显），去壳线（§6）仅作该目标的支撑慢推
10. 若 9/26 卡密失效：原版宿主自然退役，自研路线无损失（功能钩走我们自己的 implant）

### P3 —— 收尾杂项

11. 76 个"函数体内" dispatch 目标改由"签名+函数内偏移"表达（不再需要独立 RVA）
12. 交接文档每里程碑更新（当前 r6.4）；本文档随环境变化更新
13. （可选）老客户端目录 `C:\冒险岛online` 整目录备份——它是唯一"原版功能可跑"的参考环境，游戏若被自动更新会失去观察窗口

---

## 6. 风险登记

| 风险 | 缓解 |
| --- | --- |
| 老/新客户端被自动更新毁掉参考环境 | 老目录暂不启动更新；观察任务尽早做 |
| 活体功能钩崩游戏 | VEH 留痕 + detour 仅 14B 最小改写 + 小号测试；崩了不重试先分析日志 |
| 卡密 9/26 到期 | 自研路线不依赖它；P2-8 提前铺 MITM |
| 单机构建环境漂移 | 本文档 §1 + install_mingw.ps1 可重放 |
