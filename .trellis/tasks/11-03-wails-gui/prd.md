# dnsleak 桌面 GUI（Wails）

## Goal

给 dnsleak 加一个桌面窗口：用户选择或拖入一份 mihomo 配置文件，就能看到和 `dnsleak check` 相同的检查结果，并能对照配置原文查看问题所在。目标用户是不习惯命令行的 mihomo 使用者。

## Background

- 检查逻辑已在 `internal/` 中实现并验证（已归档任务 `archive/2026-11/11-02-config-dns-leak-check`）；约定见 `.trellis/spec/backend/`。
- 环境与 Wails 版本调研：`research/environment-and-wails.md`。

## Key Decisions（已与用户确认）

| # | 决定 |
|---|---|
| G1 | 使用 Wails 做独立桌面窗口（不是浏览器里的本地网页） |
| G2 | 第一版功能只有「选择 / 拖入配置并检查」；trace、自动查找客户端配置、Smart 内核键名兼容都不在本期 |
| G3 | 命令行版 `dnsleak` 保留且行为不变 |
| G4 | 使用 Wails v2（当前 v2.17.1），不用刚发布的 v3 |
| G5 | 前端使用 Vue 3 + TypeScript（Wails v2 官方 vue-ts 模板） |

## Requirements

### R1 打开配置
- R1.1 窗口内提供「选择配置文件」按钮，弹出系统原生文件对话框（筛选 `.yaml` / `.yml`，也允许所有文件）。
- R1.2 支持把文件从资源管理器拖入窗口；拖入多个文件时只取第一个并提示。
- R1.3 打开后立即执行检查；提供「重新检查」按钮，用于用户修改配置后刷新。

### R2 展示结果
- R2.1 顶部汇总：配置文件路径、各等级数量（错误 / 高 / 中 / 低 / 提示），无「错误 / 高 / 中」时显示明确的「未发现泄露风险」状态。
- R2.2 问题列表按等级排序（与 CLI 相同），每项显示等级、ID、说明、修复建议、假设说明。
- R2.3 每项的位置列表显示角色（触发规则 / 受影响 / 解析器…）、文件行号、原文，受影响位置显示各自的解析器分级。
- R2.4 点击位置，在配置原文视图中跳转并高亮对应行；位置在规则集文件中时显示该文件。
- R2.5 文字为中文，与 CLI 共用 `internal/report/messages_zh.go`，不在前端重复写提示文字。

### R3 异常
- R3.1 文件无法读取、YAML 无法解析、age 加密：界面显示对应说明，不崩溃、不卡死。
- R3.2 检查在后台执行，期间界面显示加载状态；大配置（数千行）检查时界面不冻结。

### R4 构建与跨平台
- R4.1 Windows 上可一条命令构建出单个 `.exe`。
- R4.2 不改变 `internal/` 的跨平台约束；GUI 专属代码与 CLI 隔离，CLI 仍可在 Windows 上交叉编译到 Linux / macOS。
- R4.3 macOS / Linux 的 GUI 构建步骤写入文档（需在对应系统上执行），本期不要求实际产出。

## Acceptance Criteria

- [x] AC1：选择 `testdata/ac1-geoip-without-no-resolve.yaml`，界面显示 RULE-01（高）与 DNS-02（中），汇总为「高 1、中 1」。
- [ ] AC2：拖入同一文件得到相同结果（需在真实窗口中人工确认）。
- [x] AC3：点击 RULE-01 的第一个「受影响」位置（`GEOSITE,youtube,…`），原文视图滚动到第 44 行并高亮。
- [x] AC4：打开 `testdata/ac3-recommended.yaml`，显示「未发现泄露风险」。
- [x] AC5：打开 `testdata/ac12-encrypted.yaml` 和一个非 YAML 文件，分别显示加密 / 解析失败说明，窗口可继续使用。
- [x] AC6：GUI 展示的 Finding（ID、等级、文字、位置）与 `dnsleak check --format json` 对同一文件的输出一致。
- [x] AC7：`go test ./...` 通过；`GOOS=linux` / `GOOS=darwin` 交叉编译 CLI 仍然成功。
- [ ] AC8：Windows 上按文档命令构建出 GUI `.exe` 并能启动（启动需人工确认）。

## Out of Scope

- 域名模拟（trace）界面、自动查找客户端配置、Smart 内核键名兼容。
- 修改或保存配置文件。
- 安装包、自动更新、代码签名。
- 实际产出 macOS / Linux 的 GUI 构建。
