# 系统状态检测：TUN 与智能多宿主名称解析

## Goal

在 GUI 和命令行里展示本机此刻的两项状态：**TUN 模式是否实际开启**，以及 **Windows 智能多宿主名称解析是否已禁用**。两者组合起来能直接告诉用户是否处在文章描述的必然泄露场景（TUN 开启 + 未禁用）。工具**只读检测，不修改任何系统设置或配置**。

## Background

- 依据文章：`docs/Windows系统下Clash系代理软件虚拟网卡（TUN）模式的 DNS 泄露问题及解决方案 – 野生网管.md`。
- 检测方法与源码依据：`research/tun-and-smart-resolution.md`。
- 这是 `.trellis/spec/backend/directory-structure.md` 中预留的 `internal/platform` 扩展点的首次落地。

## Key Decisions（已与用户确认）

| # | 决定 |
|---|---|
| S1 | TUN 状态按**系统实际状态**判断（网卡与路由），与客户端种类、所选配置无关 |
| S2 | 在 GUI 和命令行（新子命令 `dnsleak status`）都展示 |
| S3 | 只读：不写注册表、不改网络设置、不改任何配置文件 |

## Requirements

### R1 智能多宿主名称解析
- R1.1 读取 `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient` 的 `DisableSmartNameResolution`，按 research 中的表判定为「已禁用 / 未禁用 / 未知」。
- R1.2 未禁用时给出文章中的处理方法（专业版：组策略路径；家庭版：`reg add` 命令 + 需重启），**只展示文字，不提供执行按钮**。
- R1.3 非 Windows 系统显示「仅适用于 Windows」。

### R2 TUN 状态
- R2.1 判定为「已开启 / 未开启 / 未知」。已开启的依据：存在已启用的 wintun 虚拟网卡，且访问公网的出口网卡就是它。
- R2.2 展示依据：网卡名称、描述、IPv4 地址、公网出口网卡。
- R2.3 存在 wintun 网卡但公网出口不走它时，判定「未开启」并注明「检测到虚拟网卡但流量未经过它（可能未开启 auto-route）」。
- R2.4 本期 Linux / macOS 显示「暂不支持」，但接口按跨平台设计（见 design）。

### R3 组合结论
- R3.1 TUN 已开启 + 智能多宿主名称解析未禁用 → 显示高风险提示：「必然发生 DNS 泄露」，并附文章的处理方法。
- R3.2 其余组合给出对应的说明（例如 TUN 未开启时，该策略与本工具的配置检查无关）。

### R4 命令行 `dnsleak status`
- R4.1 `dnsleak status [--format text|json]`，不需要配置文件参数。
- R4.2 退出码：0 = 无风险；1 = TUN 已开启且未禁用智能多宿主名称解析；2 = 参数错误。检测「未知」不算风险（退出码 0，并在输出中说明）。
- R4.3 现有 `check` / `trace` 行为与输出不变。

### R5 GUI
- R5.1 窗口顶部新增「系统状态」区：两项状态 + 组合结论；启动时自动检测，提供「刷新」按钮。不依赖是否已打开配置文件。
- R5.2 状态用文字 + 颜色表示，深色 / 浅色主题都清晰可读。

### R6 安全与跨平台
- R6.1 注册表只用只读权限打开；代码中不得出现注册表写入、网络配置修改或执行外部命令的调用（有测试强制）。
- R6.2 根模块仍可从 Windows 交叉编译到 Linux / macOS。
- R6.3 检测失败（权限、API 错误）显示「未知」及原因，不崩溃。

## Acceptance Criteria

- [x] AC1：本机（`DisableSmartNameResolution = 1`）运行 `dnsleak status`，显示「智能多宿主名称解析：已禁用」。
- [x] AC2：客户端 TUN 关闭时显示「TUN：未开启」；在 mihomo-party 中打开 TUN 后刷新，显示「TUN：已开启」，并列出网卡名称与地址（需用户切换 TUN，人工确认）。
- [x] AC3：单元测试覆盖判定逻辑的全部组合：注册表值 1 / 0 / 缺失 / 类型错误；wintun 网卡存在且为出口 / 存在但非出口 / 不存在；组合结论与退出码。
- [x] AC4：`dnsleak status --format json` 输出可解析的 JSON，含两项状态的判定码、依据和组合结论。
- [x] AC5：GUI 启动后顶部显示两项状态，点击「刷新」重新检测；未打开配置文件时也显示。
- [x] AC6：测试确认 `internal/platform` 中没有注册表写入 / 外部命令调用；`check` / `trace` 的 e2e 测试不修改即通过。
- [x] AC7：根模块验证命令与 GUI 验证命令全部通过（含 Linux / macOS 交叉编译）。

## Out of Scope

- 修改注册表、组策略或任何系统设置（包括「一键修复」按钮）。
- 判断修改注册表后是否已重启。
- Linux / macOS 的 TUN 检测实现（只做接口与「暂不支持」占位）。
- 检测系统代理开关、浏览器安全 DNS、WebRTC 等其它系统层问题。
- 读取客户端运行时 API（external-controller）。
