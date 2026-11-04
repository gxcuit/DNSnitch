# Journal - gao (Part 1)

> AI development session journal
> Started: 2026-11-02

---



## Session 1: dnsleak P1：mihomo 配置 DNS 泄露静态检查
<!-- trellis-session: v=2 fp=a9801b6aed6edc82 -->

**Date**: 2026-11-03
**Task**: dnsleak P1：mihomo 配置 DNS 泄露静态检查
**Branch**: `main`

### Summary

梳理三篇文档并对照 mihomo 源码（3f27ef39）核实规则解析与 DNS 解析语义；完成 Go CLI dnsleak 的 check/trace（RULE/DNS/CFG 检查、风险矩阵、离线读取 yaml/text/mrs 与 GeoSite.dat、中文与 JSON 输出，GPL-3.0）；填写 backend spec（CLI 约定、mihomo 行为约定、错误处理、质量规范）。下一步：用 Wails 做 GUI（选择/拖入配置并检查）。

### Git Commits

| Hash | Message |
|------|---------|
| `a2ce979` | feat: 新增 dnsleak，静态检查 mihomo 配置中的 DNS 泄露 |
| `f065d37` | docs(trellis): 记录 dnsleak 任务规划与 backend spec |

### Status

[OK] **Completed**


## Session 2: dnsleak 桌面 GUI（Wails v2 + Vue 3）
<!-- trellis-session: v=2 fp=577203694906aae0 -->

**Date**: 2026-11-04
**Task**: dnsleak 桌面 GUI（Wails v2 + Vue 3）
**Branch**: `main`

### Summary

新增嵌套模块 gui/（Wails v2.17.1 + Vue 3 + TS）：选择或拖入配置即检查，结果与 dnsleak check 一致，可跳转高亮原文；抽出 internal/app 供 CLI 与 GUI 共用，CLI 输出逐字节不变；ReadSource 白名单修复 NTFS 备用数据流绕过；.gitattributes 统一 LF；补全 backend gui-bindings spec 与全部 frontend spec，归档 GUI 与 bootstrap 任务。8 条验收全部通过（AC2/AC8 由用户在真实窗口确认）。

### Git Commits

| Hash | Message |
|------|---------|
| `82fc6c9` | chore: 统一文本文件换行符为 LF |
| `1c5ccdb` | refactor: 抽出 internal/app，CLI 与 GUI 共用检查流程 |
| `22455f5` | feat(gui): 新增 Wails 桌面窗口 dnsleak-gui |
| `076e8c6` | docs(trellis): GUI 任务规划与前后端 spec |
| `0f45d1f` | docs(trellis): 记录 GUI 人工验收结果（AC2、AC8） |
| `8904d6d` | Merge branch 'feat/wails-gui'：dnsleak 桌面 GUI |

### Status

[OK] **Completed**


## Session 3: 系统状态检测：TUN 与智能多宿主名称解析
<!-- trellis-session: v=2 fp=b9438262ec854c9d -->

**Date**: 2026-11-04
**Task**: 系统状态检测：TUN 与智能多宿主名称解析
**Branch**: `main`

### Summary

基于《Windows 系统下 Clash 系代理软件 TUN 模式的 DNS 泄露》文章，新增 internal/platform 只读检测：TUN 按 wintun 网卡（驱动 ComponentId=Wintun，备用规则 IfType 53 + 描述以 Tunnel 结尾）且为公网出口判断，智能多宿主名称解析读 DisableSmartNameResolution；AST 测试强制只读。新增 dnsleak status 与 GUI 顶部状态栏，TUN 开/关两种真实状态均在本机核对，7 条验收全部通过；更新前后端 spec。

### Git Commits

| Hash | Message |
|------|---------|
| `c3f04ba` | feat: 新增只读系统状态检测与 dnsleak status 子命令 |
| `c86117c` | feat(gui): 窗口顶部显示 TUN 与智能多宿主名称解析状态 |
| `8212116` | docs: 新增 TUN 模式 DNS 泄露参考文章 |
| `d6152c0` | docs(trellis): 系统状态任务规划与前后端 spec |
| `ec44ae9` | Merge branch 'feat/system-status'：系统状态检测（TUN 与智能多宿主名称解析） |

### Status

[OK] **Completed**
