# 技术设计：系统状态检测

需求见 `prd.md`；检测依据见 `research/tun-and-smart-resolution.md`；现有约定见 `.trellis/spec/backend/`、`.trellis/spec/frontend/`。

## 1. 结构

```
internal/platform/                 新包（根模块），只读采集 + 纯函数判定
  status.go                        Snapshot / 判定码 / Decide*()（无 OS 依赖，所有平台编译）
  facts.go                         原始事实结构 Facts（注册表读数、网卡列表、出口网卡）
  inspect_windows.go  //go:build windows   采集 Facts：注册表只读 + GetAdaptersAddresses + GetBestInterfaceEx
  inspect_other.go    //go:build !windows  返回 unsupported
  status_test.go                   判定逻辑全组合（所有平台都跑）
  readonly_test.go                 扫描本包源码，禁止写入 / 执行类调用（R6.1）
internal/report/                   新增 BuildStatusView / WriteStatus / StatusExitCode；文字进 messages_zh.go
cmd/dnsleak/main.go                新增 status 子命令
gui/app.go                         新增绑定 SystemStatus() report.StatusView
gui/frontend/src/                  新增 composables/useSystemStatus.ts、components/SystemStatusBar.vue
```

依赖方向：`cmd → platform, report`；`gui → platform, report`；`report → platform`（只用其数据类型）；`platform` 只依赖标准库与 `golang.org/x/sys`（Windows 文件）。`platform` 不依赖其它 internal 包，也不含任何提示文字。

## 2. 数据结构（`internal/platform`）

```go
// 判定码，供 report 翻译成文字
const (
    StateOn, StateOff                 = "on", "off"            // TUN
    StateDisabled, StateEnabled       = "disabled", "enabled"  // 智能多宿主名称解析：disabled = 已禁用（安全）
    StateUnknown, StateUnsupported    = "unknown", "unsupported"
)

type Adapter struct {
    Name, Description string
    IfIndex           uint32
    IfType            uint32
    Up                bool
    IPv4              []string
    Wintun            bool   // 判定为 wintun 虚拟网卡
}

type Facts struct {                 // 采集层的原始结果
    OS string
    Smart struct { Present bool; IsDWORD bool; Value uint32; Err string }
    Adapters []Adapter
    EgressIfIndex uint32            // GetBestInterfaceEx(1.1.1.1)；0 = 无
    NetErr string
}

type SmartStatus struct { State string; Value *uint32; KeyPath, ValueName, Reason string }
type TUNStatus   struct { State string; Adapter *Adapter; Egress *Adapter; Note, Reason string }
type Snapshot    struct { OS string; Smart SmartStatus; TUN TUNStatus; Risk bool }

func Inspect() Snapshot                // = Decide(collect())
func Decide(f Facts) Snapshot          // 纯函数，测试覆盖全部组合
```

判定规则：
- Smart：非 Windows → unsupported；`Err` 非空 → unknown；不存在或值 0 → enabled；值 1 → disabled；非 DWORD → unknown（Reason 记录类型）。
- TUN：非 Windows → unsupported；`NetErr` 非空 → unknown；存在 `Up && Wintun` 的网卡且 `EgressIfIndex` 等于它 → on；存在但出口不是它 → off + Note `adapter-not-egress`；不存在 → off。
- Risk = TUN on && Smart enabled（未禁用）。unknown 不算风险。

## 3. Windows 采集（`inspect_windows.go`）

- 注册表：`registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`, registry.QUERY_VALUE)`；`ErrNotExist` 视为不存在；`GetIntegerValue` 取值并检查类型为 `DWORD`。
- 网卡：`windows.GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST|SKIP_MULTICAST|SKIP_DNS_SERVER, …)`，取 FriendlyName、Description、IfIndex、IfType、OperStatus、IPv4 单播地址。
- 出口：`windows.GetBestInterfaceEx(&windows.SockaddrInet4{Addr: [4]byte{1,1,1,1}}, &idx)`——只查询路由表，不发任何数据包。
- wintun 识别规则（已采样，见 research「本机采样」）：
  - 主规则：只读枚举 `HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\*`，`NetCfgInstanceId` 匹配网卡 `AdapterName`（GUID）时读取 `ComponentId`，等于 `Wintun`（不区分大小写）即为 wintun。读取用 `registry.QUERY_VALUE | registry.ENUMERATE_SUB_KEYS`。
  - 备用规则（主规则读不到时）：IfType = 53 且 Description 以 ` Tunnel` 结尾；`Adapter` 增加字段 `MatchedBy`（`component-id` / `fallback`），报告中注明。
  - 单元测试用采样数据固定：`Mihomo` / `Meta Tunnel` / IfType 53 / `Wintun` / `198.18.0.1` 为 wintun；Hyper-V `vEthernet`（IfType 6）、WAN Miniport、WLAN（IfType 71）都不是。

## 4. 输出（`internal/report`）

- `type StatusView struct { OS string; Smart StatusItem; TUN StatusItem; Risk bool; Conclusion string; Fix []string }`，`StatusItem{State, Label, Detail []string, Note string}`；`BuildStatusView(platform.Snapshot) StatusView` 供 CLI JSON 与 GUI 共用（同 `CheckResult` 的做法）。
- 文字全部在 `messages_zh.go`：状态名、依据描述、组合结论、文章中的两种处理方法（组策略路径；`reg add … /d 1 /f` + 需重启），以纯文本展示。
- `WriteStatus(w, format, view)`：text / json；`StatusExitCode(view)`：Risk → 1，否则 0。

## 5. CLI

`dnsleak status [--format text|json]`；多余的位置参数 → 参数错误（2）。`help` 文本加入 status。`check` / `trace` 分支不变。

## 6. GUI

- 绑定 `func (a *App) SystemStatus() report.StatusView { return report.BuildStatusView(platform.Inspect()) }`；Wails 绑定调用是异步的，检测不会阻塞界面。
- 前端：`useSystemStatus()`（独立关注点，符合 frontend hook-guidelines）负责加载 / 刷新 / 序号保护；`SystemStatusBar.vue` 放在顶部操作栏下方，两个状态徽标（文字 + 颜色）、组合结论，Risk 时展开处理方法；「刷新」按钮。启动时自动检测一次。
- 不改动 `useCheck()` 与配置检查区域的行为。

## 7. 只读保证（R6.1）

注册表只允许 `registry.QUERY_VALUE`、`registry.ENUMERATE_SUB_KEYS` 两种访问权限。`readonly_test.go` 读取 `internal/platform/*.go`（非测试文件）源码，以下任一出现即失败：`CreateKey`、`SetDWordValue`、`SetQWordValue`、`SetStringValue`、`SetBinaryValue`、`DeleteKey`、`DeleteValue`、`registry.SET_VALUE`、`registry.WRITE`、`registry.ALL_ACCESS`、`"os/exec"`、`syscall.Exec`、`ShellExecute`。

## 8. 跨平台

- `golang.org/x/sys` 从 indirect 变为根模块的直接依赖（版本不变 v0.30.0）；只有 `_windows.go` 引用 `x/sys/windows`。
- `GOOS=linux` / `darwin` 编译走 `inspect_other.go`，`Decide` 与测试在所有平台通用。以后补 Linux / macOS 时只新增 `inspect_linux.go` / `inspect_darwin.go`。

## 9. 风险

- wintun 识别依赖采样：如果用户暂时无法开启 TUN，退路是使用候选规则并在结果中标注「按候选规则判断」，AC2 待用户确认。
- 其他软件（WireGuard、OpenVPN 新驱动）也可能使用 wintun：若其为公网出口，会被判定为 TUN 开启。这同样意味着 DNS 可能绕过它泄露，结论仍成立；依据中会显示网卡描述，便于用户分辨。
