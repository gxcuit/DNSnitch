# mihomo 配置文件 DNS 泄露静态检查 (P1)

## Goal

做一个命令行工具，读入一份 mihomo（Clash.Meta）YAML 配置文件，**不运行 mihomo、不联网**，找出因为规则或 DNS 写法不当，导致「该走代理的域名被不安全的 DNS 解析」的问题，并说明位置、原因和修法。

用户价值：手写或改写配置（加规则集、改 DNS 覆写）时，很容易忘加 `no-resolve`、在 nameserver 里混入明文 DNS，而这些错误不会报错，只能靠抓包发现。工具让用户在启用配置前就能看到这些问题。

## Background

- 泄露的定义：需要代理访问的域名，被直连 DNS 解析（`docs/解决DNS泄露最佳实践——基于ClashMeta.md` 第一节）。泄露成立需要同时满足两点：**该域名会触发本地解析**，并且**负责解析的 DNS 不安全**。
- 三篇参考文档：`docs/` 目录。
- mihomo 实际行为已对照源码核实，见 `research/mihomo-dns-semantics.md`。文档与源码冲突时以源码为准，已知冲突：
  - `default-nameserver` 允许加密的 IP 形式（如 `tls://223.5.5.5`），《DNS泄漏可能比你想的范围广…》说不允许是错的。
  - `GEOIP,...,no-resolve` 本身不是错误：用在 `GEOSITE,private` 之后匹配 lan 是正确用法，用作 CN 兜底才会让规则对域名请求失效。

## Key Decisions（已与用户确认）

| # | 决定 |
|---|---|
| D1 | 用 Go 实现，单一可执行文件，交叉编译 Windows / Linux / macOS |
| D2 | 只支持 mihomo，不兼容原版 Clash |
| D3 | 输入只接受配置文件路径；自动定位客户端配置、拉取订阅 URL 不在本期 |
| D4 | 本期功能：静态检查（`check`）+ 风险矩阵 + 单域名模拟（`trace`） |
| D5 | 泄露分级：明文 DNS 看到代理域名 = 高；直连的国内加密 DNS 看到 = 中 |
| D6 | trace 的数据只读本地缓存（rule-provider 的缓存文件、`GeoSite.dat`），不联网；找不到的标「未知」 |
| D7 | 策略组里只要有代理节点就当作代理，报告中注明这是假设；全部成员为 DIRECT / REJECT 才算直连 |
| D8 | 本期忽略 TUN 模式，只检查配置写法本身（规则层 + DNS 层），即按系统代理 / mixed-port 场景分析 |
| D9 | 报告文字用中文；检查项 ID、配置原文不翻译；提示文字集中管理，便于以后加英文 |
| D10 | 本工具以 GPL-3.0 发布；`.mrs` 读取直接复用 mihomo 的 `component/trie`、`component/cidr` 包（research 第 9 节） |

## Requirements

### R1 配置读取
- R1.1 读取 YAML，支持锚点与合并键；每个检查结果能定位到文件行号。
- R1.2 识别 age 加密的配置文件，报告「无法分析」，不崩溃（CFG-02）。
- R1.3 对顶层、`dns`、`dns.fallback-filter` 段的未知键给出警告，并在能判断时给出最接近的合法键名（CFG-01，例如 `nameserver-police` → `nameserver-policy`）。合法键列表见 research 第 6 节。
- R1.4 rule-provider 的本地数据查找顺序：`inline` 的 payload → `path` 指向的文件 → `http` 类型的默认缓存 `<home>/rules/<md5(url)>`。`<home>` 默认为配置文件所在目录，可用 `--home` 覆盖。支持 `yaml`、`text`、`mrs` 三种格式。
- R1.5 GeoSite 数据从 `<home>/GeoSite.dat` 读取（仅 trace 使用）；不存在时相关匹配标为「未知」。

### R2 策略分类
- R2.1 把 `proxies`、`proxy-groups`（递归展开，含 `use` 引用 proxy-providers 的情况）以及内置策略 `DIRECT` `REJECT` `REJECT-DROP` `PASS` `COMPATIBLE` 归类为：直连、代理、拒绝、PASS。规则按 D7 处理。
- R2.2 规则或 DNS `#名称` 引用了不存在的策略时报错误（CFG-03 / DNS-07）。

### R3 解析触发分析（规则层）
- R3.1 按 research 第 1 节判断每条规则是否触发解析：一定触发 / 有条件触发 / 不触发。
- R3.2 classical 规则集按内部顺序推算；逻辑规则按短路语义推算；规则集内容未知时，按 behavior 保守推断并在结果中注明。
- R3.3 找出第一条「一定触发」的规则 T，产出以下结果：

| ID | 条件 | 默认等级 |
|---|---|---|
| RULE-01 | T 之后还有「域名 → 代理」的规则：这些域名一定会被解析 | 由 R5 决定 |
| RULE-02 | T 之后由 `MATCH,代理` 兜底：未知域名会被解析 | 由 R5 决定 |
| RULE-03 | 同 RULE-01 / 02，但触发点是 classical 规则集内部的 IP 条目（引用时未加 `no-resolve`）；集合内排在它前面的域名条目不受影响 | 由 R5 决定 |
| RULE-04 | 同 RULE-01 / 02，但触发点是逻辑规则（AND/OR/NOT/SUB-RULE）中的 IP 子规则；AND 只影响满足前面条件的域名 | 由 R5 决定 |
| RULE-05 | `GEOIP,<非 lan>,...,no-resolve` 被当作兜底，对域名请求不生效 | 提示 |
| RULE-06 | `MATCH,DIRECT` 白名单模式：未知域名必然在本地解析 | 提示 |

### R4 解析器分析（DNS 层）
- R4.1 `dns.enable` 为 false 或缺少 `dns` 段时，解析器视为系统 DNS（明文）（DNS-01）。
- R4.2 规则匹配期解析器 = `nameserver-policy`（按顺序，静态分析时按 geosite / rule-set 名称或域名后缀对应）→ 否则 `nameserver` ∪ `fallback`。不使用 `direct-nameserver`。
- R4.3 每台服务器按 research 第 3 节分为：明文 / 加密直连（再用内置知名 DNS 列表细分国内、国外、未知）/ 经代理 / 安全。一组服务器取最差的一台。
- R4.4 独立检查：

| ID | 条件 | 等级 |
|---|---|---|
| DNS-02 | `nameserver` 或 `fallback` 中有明文服务器 | 中 |
| DNS-04 | `nameserver-policy` 把代理类域名集（如 `geolocation-!cn`、规则里指向代理的 geosite / rule-set）指向明文或国内 DNS | 明文 = 高，国内加密 = 中 |
| DNS-05 | 使用了 `fallback` | 提示 |
| DNS-06 | `respect-rules: true` 但缺少 `proxy-server-nameserver`（mihomo 会加载失败） | 错误 |
| DNS-07 | `#名称` 指向不存在的策略 | 错误 |
| DNS-08 | `default-nameserver` 为空列表或含非纯 IP 项（mihomo 会加载失败） | 错误 |
| DNS-09 | `proxy-server-nameserver` 为明文，会泄露代理节点域名 | 低 |

### R5 风险合成

| | 解析器含明文 | 最差为国内加密 | 最差为国外 / 未知加密 | 全部经代理或安全 |
|---|---|---|---|---|
| RULE-01（一定被解析） | 高 | 中 | 低 | 提示（多余解析） |
| RULE-02（仅未知域名） | 中 | 低 | 低 | 提示 |

RULE-03、RULE-04 按推算出的影响范围套用对应行；AND 条件限定的域名无法确定最终是否走代理，按 RULE-02 行定级。每条结果同时列出规则位置和解析器位置。

### R6 命令行
- R6.1 `check <配置文件>`：输出全部结果，按等级排序，末尾给出各等级数量汇总。
- R6.2 `trace <配置文件> <域名>`：逐条显示规则匹配过程；在触发解析的位置列出会收到查询的 DNS 服务器及其分级；给出最终命中的规则和策略。数据缺失的匹配步骤标为「未知」，并说明对结论的影响。
- R6.3 `--format text|json`，默认 text。
- R6.4 退出码：0 = 无「错误 / 高 / 中」结果；1 = 有「错误 / 高 / 中」结果；2 = 配置无法读取、无法解析或已加密。「错误」指会让 mihomo 加载失败的配置问题。
- R6.5 报告文字为中文（D9）。

### R7 跨平台约束
- R7.1 检查逻辑不依赖任何操作系统 API；只读文件系统。
- R7.2 文件路径处理使用 `path/filepath`，不得硬编码分隔符；同一份测试用例在 Windows 与 Linux 上结果一致。

## Acceptance Criteria

- [x] AC1：对《DNS泄漏可能比你想的范围广…》中「错误示范」的规则（`GEOIP,private` 不带 `no-resolve`，后面接代理域名规则集）配合 `nameserver: [8.8.8.8, https://doh.pub/dns-query]`，`check` 报 RULE-01 高，指出 GEOIP 规则行号和 `8.8.8.8` 行号，退出码 1。
- [x] AC2：同一配置把 GEOIP 规则加上 `no-resolve` 后，RULE-01 消失。
- [x] AC3：IP 规则全部放在域名规则之后、以 `MATCH,PROXY` 结尾、nameserver 全部 `#PROXY` 的配置（《Clash.Meta DNS 配置指南》的推荐配置），不报任何高 / 中结果，退出码 0。
- [x] AC4：clash-verge 默认覆写（nameserver 含裸 `8.8.8.8`）在规则无问题时报 DNS-02 中。
- [x] AC5：`RULE-SET,x,PROXY` 引用的 inline classical 规则集首条为 `IP-CIDR,...`（无 no-resolve）时报 RULE-03；引用时加上 `no-resolve` 后不再报。
- [x] AC6：`AND,((DOMAIN-SUFFIX,a.com),(IP-CIDR,1.0.0.0/8)),DIRECT` 只对 `a.com` 下的域名计为触发；`OR,((IP-CIDR,1.0.0.0/8),(DOMAIN,b.com)),DIRECT` 计为一定触发。
- [x] AC7：`dns.nameserver-police` 报 CFG-01，并建议 `nameserver-policy`。
- [x] AC8：`respect-rules: true` 且无 `proxy-server-nameserver` 报 DNS-06；`default-nameserver: [dns.alidns.com]` 报 DNS-08；`default-nameserver: [tls://223.5.5.5]` 不报。
- [x] AC9：缺少 `dns` 段、规则含无 no-resolve 的 IP 规则时，报 DNS-01，RULE-01 / RULE-02 按「明文」定级。
- [x] AC10：`trace cfg.yaml www.youtube.com` 对 AC1 的配置，显示在 GEOIP 规则处触发解析，列出 `8.8.8.8`（明文）与 `doh.pub`（加密·国内），给出泄露等级；GeoSite.dat 不存在时，GEOSITE 步骤显示「未知」而不报错。
- [x] AC11：`--format json` 输出可被解析的 JSON，字段至少包含 id、等级、消息、位置列表（文件、行号）、修复建议。
- [x] AC12：age 加密的配置文件报 CFG-02，退出码 2。
- [x] AC13：全部单元测试在 Windows 上通过；`GOOS=linux` 与 `GOOS=darwin` 交叉编译成功。（未在 Linux / macOS 上实际运行测试）
- [x] AC14：`RULE-SET` 引用的规则集缓存为 `.mrs`（domain 与 ipcidr 两种）时能读出内容：trace 能据此判断域名是否命中；ipcidr 的 `.mrs` 规则集未加 `no-resolve` 时计为一定触发。
- [x] AC15：仓库包含 GPL-3.0 `LICENSE` 文件。

## Out of Scope

- TUN 模式相关检查（dns-hijack、enhanced-mode 与 TUN 的组合、fake-ip-filter、strict-route、route-exclude-address、Tailscale 共存）。
- 系统层检查（Windows 智能多宿主名称解析、系统代理开关、系统 DNS 设置、WebRTC）。
- 自动定位客户端运行时配置（clash-verge-rev / mihomo party / FlClash）、拉取订阅 URL、下载远程规则集或 GeoSite 数据。
- 动态抓包验证。
- 原版 Clash（Premium）兼容。
- 自动修改配置文件。
