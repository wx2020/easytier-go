# EasyTier-Go v2.6.4 Release Notes

## 📝 更新日志（v2.6.3 → v2.6.4）

### 🚀 核心架构与新特性

* **Clean-Room 纯 Go 高性能核心重写** — 核心网络引擎与命令行工具采用纯 Go 全新实现（`CGO_ENABLED=0` 静态编译，零外部动态库依赖）。与 EasyTier 2.6.4 官方协议保持 100% 双向互联互通，可无缝接入任意现有网络与公共共享服务器。

* **全新纯 Go Wails 桌面客户端** — 彻底剥离原版 Tauri + Rust 胶水层（移除 4300+ 行 Rust 冗余代码），采用 Wails v2 纯 Go 桌面宿主。客户端安装包压缩体积由原先的 30~40MB 暴降至 **~2.5MB**，极速秒级编译，完美保留全部 Vue 3 现代化界面与网络控制能力。

* **全面全生命周期上下文与安全治理** — 所有网络 Socket、TUN 设备、系统路由表及映射租约均与 Go `context.Context` 严格绑定，退出或重启时具备确定的资源清理与状态回滚路径，彻底解决长时间运行内存与文件句柄泄漏问题。

### ⚡ 架构优化与平台精简

* **生产级平台架构聚焦** — 精简剔除维护代价高、缺乏现代生态支持的 32 位老旧 ARM (ARMv6/v7)、MIPS、RISC-V 64、LoongArch 64 及 Windows ARM64 矩阵。全面保障并优化 **Linux (x86_64 / arm64)**、**Windows (x86_64 / i686)**、**Android (arm64-v8a)** 与 **FreeBSD (x86_64)** 主流生产环境。

* **自动化互通性矩阵保障** — CI 流水线集成 60 余个跨语言协议测试矩阵单元（TCP/UDP/WebSocket/WireGuard、Noise_xx 握手、中继转发与数据压缩），持续确保 Go 重写版与 Rust 官方预言机（Oracle）的协议一致性。

### 🐞 问题修复

* **修复 jemalloc 在多架构下的交叉编译冲突** — 彻底根除了老旧 ARM 软浮点目标在 Zig Clang 下由于 `-mcpu` 指令集参数冲突引发的 Exit 101 编译崩溃。

* **加固 Magisk 移动端打包链路** — 优化上游构建产物依赖检测，确保 Android 64 位核心与 Magisk 模块稳定串接打包。

* **修复 Go GUI 代码风格与静态分析检查** — 统一对齐 `gofmt` 代码规范与带竞态检测（`-race`）的完整单元测试。

---

## 📝 Release Notes (v2.6.3 → v2.6.4)

### 🚀 Major Architecture & Features

* **Clean-Room Pure Go Core Rewrite** — Network engine and CLI reimplemented in clean-room pure Go (`CGO_ENABLED=0` static binary, zero dynamic dependencies). Achieves 100% bidirectional protocol compatibility with the official EasyTier 2.6.4 specification, seamlessly interoperating with existing networks and shared public nodes.

* **Brand-New Pure Go Wails Desktop Client** — Completely decoupled from Tauri and Rust (removed 4,300+ lines of Rust glue code). Replaced with a pure Go Wails v2 host. Archive package size slashed from 30~40 MB down to **~2.5 MB** with sub-3-second builds while retaining 100% of the sleek Vue 3 interface.

* **Context-Bound Lifecycle & Resource Governance** — Every socket, TUN interface, routing table entry, and mapping lease is bound to Go's `context.Context` supervisor, ensuring deterministic teardown and rollback to prevent resource leaks during extended operations.

### ⚡ Optimizations & Platform Pruning

* **Streamlined Mainstream Platform Matrix** — Pruned legacy high-maintenance targets (32-bit ARMv6/v7, MIPS, RISC-V 64, LoongArch 64, and Windows ARM64). Deeply optimized production platforms: **Linux (x86_64 / arm64)**, **Windows (x86_64 / i686)**, **Android (arm64-v8a)**, and **FreeBSD (x86_64)**.

* **Continuous Automated Interoperability Matrix** — Validated by over 60 CI interop test cells (`interop.yml`) covering TCP, UDP, WebSocket, WireGuard, Noise_xx handshakes, relaying, and real-time packet compression against the official Rust 2.6.4 oracle.

### 🐞 Bug Fixes

* **Fixed jemalloc cross-compilation errors** — Eliminated Zig Clang `-mcpu` argument conflicts in legacy ARM targets that previously caused Exit 101 build failures.

* **Hardened Magisk packaging pipeline** — Resolved artifact dependency timing in the downstream Magisk Android module packaging workflow.

* **Standardized code formatting and static analysis** — Enforced strict `gofmt` style compliance and passing race-detector (`-race`) unit test suites.

