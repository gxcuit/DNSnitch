# TUN 与智能多宿主名称解析：检测依据（2026-11-04）

## 来源文章

`docs/Windows系统下Clash系代理软件虚拟网卡（TUN）模式的 DNS 泄露问题及解决方案 – 野生网管.md`

- 原因：Windows 7+ 默认的「智能多宿主名称解析」会同时向所有网卡发 DNS 查询；Clash 拦截不到发往物理网卡的查询，所以**开启 TUN 且未禁用该策略时必然泄露**。
- 解决（本工具只检测，不执行）：组策略「计算机配置 → 管理模板 → 网络 → DNS 客户端 → 禁用智能多宿主名称解析 = 已启用」，等价于注册表
  `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient` 的 DWORD `DisableSmartNameResolution = 1`。家庭版用 `reg add` 写入后需要重启。

## 智能多宿主名称解析：判定

| 注册表状态 | 判定 |
|---|---|
| 值存在且 = 1 | 已禁用 |
| 键或值不存在、或值 = 0 | 未禁用（Windows 默认） |
| 值类型不是 DWORD / 读取失败 | 未知（显示原因） |

- 只读：`registry.OpenKey(LOCAL_MACHINE, path, registry.QUERY_VALUE)`；普通用户即可读取 HKLM\SOFTWARE\Policies，不需要管理员。
- 写入后需重启才生效：工具无法得知是否已重启，界面只提示。
- 本机当前（只读查询）：`DisableSmartNameResolution = 1` → 已禁用。

## TUN：mihomo 在 Windows 上的实际行为（源码，mihomo v1.19.33 / sing-tun v0.4.28）

- 网卡由 wintun 创建：`sing-tun@v0.4.28/tun_windows.go:46` `wintun.CreateAdapter(options.Name, TunnelType, …)`，`TunnelType = "sing-tun"`（`:26`）。
- 网卡名：`tun.device` 可自定义，未填时由 `CalculateInterfaceName` 生成（`sing-tun/tun.go:243`），各客户端也会自定义 → **不能按名字判断**。
- 地址：`fake-ip-range` 的第一个地址取 /30，默认 `198.18.0.1/30`（`mihomo config/config.go:1687-1692`）→ 用户改了 fake-ip-range 地址就会变，**只能作辅助信号**。
- `auto-route` 默认 true，开启后访问外网的路由指向 TUN 网卡。

## 本机现状（只读查询，TUN 关闭时）

- `Get-NetAdapter`：无 wintun / sing-tun 网卡；`Find-NetRoute 1.1.1.1` → `WLAN`。
## 本机采样：mihomo-party 开启 TUN 时（2026-11-04，只读查询）

| 字段 | 值 |
|---|---|
| Name（FriendlyName） | `Mihomo` |
| InterfaceDescription（GetAdaptersAddresses 的 Description） | `Meta Tunnel` |
| ifIndex | 21 |
| InterfaceType（IfType） | 53（IF_TYPE_PROP_VIRTUAL） |
| MediaType | `IP` |
| DriverDescription | `Wintun Userspace Tunnel` |
| ComponentID | `Wintun` |
| Virtual | True |
| IPv4 | `198.18.0.1/30` |
| `Find-NetRoute 1.1.1.1` / `223.5.5.5` | 均为 `Mihomo`（ifIndex 21） |

同时存在的其它虚拟网卡（不得误判）：Hyper-V `vEthernet (FSE HostVnic)`（IfType 6，ComponentID 空）、`vSwitch (FSE Switch)`（IfType 6，`vms_vsmp`）、WAN Miniport（IfType 6，`ms_ndiswan*`）。物理网卡 WLAN 为 IfType 71。

**结论：wintun 识别规则**
1. **主规则**：网卡驱动的 ComponentId 为 `Wintun`（不区分大小写）。只读读取 `HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\<NNNN>`：其中 `NetCfgInstanceId` 等于 GetAdaptersAddresses 的 `AdapterName`（GUID）时，取同键下的 `ComponentId`。
2. **备用规则**（主规则读取失败时）：IfType = 53 且 Description 以 ` Tunnel` 结尾（`Meta Tunnel`、`WireGuard Tunnel` 均为 wintun 的命名方式），结果中注明「按备用规则判断」。
   已验证（非管理员 PowerShell，只读）：类别键 `…\{4D36E972-…}\0017` 的 `NetCfgInstanceId = {9E6FE1DA-841B-EE9D-1002-5210FB95904A}`（= `Mihomo` 的 InterfaceGuid），`ComponentId = Wintun`。类别键下个别子键（如 `Properties`）可能拒绝访问，枚举时需跳过读不了的子键。
3. 网卡描述 `Meta Tunnel` 与源码 `TunnelType = "sing-tun"` 不一致，说明描述由客户端 / 版本决定，**不能只用描述字符串判断**。

## 可用 API（`golang.org/x/sys` v0.30.0，已在根模块 go.sum 中）

- `windows.GetAdaptersAddresses`：网卡名、描述、IfType、OperStatus、IP 地址。
- `windows.GetBestInterfaceEx(sockaddr, &ifIndex)`：到某个公网 IP 的出口网卡。
- `golang.org/x/sys/windows/registry`：只读打开注册表。
