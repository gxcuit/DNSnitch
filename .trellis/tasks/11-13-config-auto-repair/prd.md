# 配置自动修复（dnsnitch fix + GUI 修复按钮）

## Goal

`dnsnitch check` 已经能指出泄露在哪一行、该怎么改，但几百行的订阅配置里逐条手改既慢又容易漏。本任务让工具把**有机械修复方式**的检查结果直接改好：生成一份修复后的配置写到**新文件**，展示改了哪些行（差异），并对修复后的内容重新检查，告诉用户还剩什么需要人工处理。原配置文件永远不被修改。

## Background

- 首个任务的 PRD 把「自动修改配置文件」列为不做（`.trellis/tasks/archive/2026-11/11-02-config-dns-leak-check/prd.md:120`），本任务解除这一条，但只针对配置文件。
- 每条检查结果已带修复建议（`internal/report/messages_zh.go:140-334`），本任务做的就是**执行这些已有建议中可以无歧义执行的部分**，替换用的 DNS 地址也沿用建议文字里的 `https://223.5.5.5/dns-query`。
- 检查结果的位置带 YAML 路径（`rules[3]`、`sub-rules.x[2]`、`dns.nameserver[0]`、`dns.nameserver-police`），由 `internal/config/config.go:101-108` 生成；修复按路径定位节点。
- no-resolve 的语义依据：`.trellis/spec/backend/mihomo-semantics.md:9-18`（`RULE-SET,x,T,no-resolve` 关闭整个集合的解析；逻辑规则内的 IP 子规则可单独带 no-resolve）。

## Key Decisions（已与用户确认）

| # | 决定 |
|---|---|
| F1 | 只修**配置文件**；Windows 智能多宿主名称解析等系统设置仍只展示处理方法 |
| F2 | 命令行（新子命令 `dnsnitch fix`）和 GUI（修复按钮 + 预览）都提供 |
| F3 | 修复结果写到**新文件**（默认与原文件同目录的 `<名>.fixed<扩展名>`），同时给出差异；原文件不动 |
| F4 | 自动修复的范围：RULE-01 / 02 / 03 / 04 加 no-resolve，DNS-02 / DNS-09 删除或替换明文 DNS，CFG-01 改正拼错的键名；其余检查结果仍只给建议 |
| F5 | 按原文逐行做最小修改（不重新序列化 YAML），注释、缩进、引号、空行、换行符（CRLF/LF）、BOM 都保持不变 |
| F6 | 明文 DNS 删掉后列表为空时（`nameserver` / `proxy-server-nameserver`），换成 `https://223.5.5.5/dns-query`，与现有 DNS-02 / DNS-09 / DNS-06 修复建议一致；`fallback` 删空则保留为空列表 |

## Requirements

### R1 可自动修复的检查结果

| ID | 条件 | 修改 |
|---|---|---|
| RULE-01 / RULE-02 | `kind = always` | 在触发规则（`trigger` 位置的那一行）末尾追加 `,no-resolve` |
| RULE-03 | `kind = always` / `conditional` | 在引用规则集的 `RULE-SET,…` 规则末尾追加 `,no-resolve`（不修改规则集文件本身） |
| RULE-04 | `kind = always` / `conditional` | 在逻辑规则（AND / OR / NOT / SUB-RULE 条件）里触发解析的那条 IP 子规则内追加 `,no-resolve`，如 `(IP-CIDR,1.0.0.0/8)` → `(IP-CIDR,1.0.0.0/8,no-resolve)` |
| DNS-02 | — | 从 `dns.nameserver` / `dns.fallback` 删除明文服务器；`nameserver` 删空时换成 `https://223.5.5.5/dns-query`；`fallback` 删空时保留为空列表 |
| DNS-09 | — | 从 `dns.proxy-server-nameserver` 删除明文服务器；删空时换成 `https://223.5.5.5/dns-query` |
| CFG-01 | 有 `suggest` 且不是锚点辅助键 | 把键名改成建议的键名 |

- R1.1 `kind = unknown`（规则集内容读不到）的 RULE-03 / RULE-04 不自动修：没有确认存在泄露。等级为「提示」的 RULE-01..04（查询本身经代理、只是多解析一次）也不自动修：不是泄露，加 no-resolve 只会改变分流而没有隐私收益（如 `testdata/ac3-recommended.yaml` 不应出现可修项）。
- R1.2 修改后的配置再按同一 `--home` 检查；一条规则在加了 no-resolve 后又暴露出下一个 IP 子规则时继续修，直到没有可修项或不再有进展（最多 8 轮）。
- R1.3 下列情况跳过并说明原因，不影响其它修改：节点通过 YAML 锚点 / 别名 / `<<` 合并引用（改一处会影响多处）；多行标量或多行 flow 列表；CFG-01 建议的键名在同一段里已存在；位置不在被检查的配置文件里；8 轮后仍未修完的触发点（`pass-limit`）。
- R1.4 任何一处修改都只改动对应的字符，文件其余字节与原文完全相同（F5）。

### R2 安全与校验

- R2.1 原配置文件永远不写。输出路径与原文件是同一文件（含大小写、`\\?\`、8.3 名、符号链接等别名，按 `os.SameFile` 判断）时拒绝。
- R2.2 写盘前对修复结果做完整解析与检查：解析失败，或出现原来没有的 `error` 级检查结果，则不写文件、报错（退出码 2）。
- R2.3 写入用临时文件 + 重命名，不留下半个文件。
- R2.4 没有任何可修改项时不写文件。

### R3 命令行 `dnsnitch fix`

- R3.1 `dnsnitch fix <config.yaml> [-o|--output <path>] [--force] [--dry-run] [--format text|json] [--home <dir>]`，参数可在位置参数前后出现（与现有子命令一致）。
- R3.2 默认输出 `<目录>/<名>.fixed<扩展名>`（`config.yaml` → `config.fixed.yaml`，无扩展名时加 `.fixed.yaml`）。输出文件已存在时拒绝（退出码 2），加 `--force` 覆盖。`--dry-run` 只输出、不写文件。
- R3.3 文本输出依次为：已修改项（检查结果 ID、原文件行号、修改前 → 修改后）、跳过项及原因、统一差异格式（unified diff，3 行上下文）、修复后仍存在的检查结果汇总、写入的路径（或「未写入」原因）。
- R3.4 `--format json` 输出 `report.FixResult`（字段见 design），GUI 绑定返回同一结构。
- R3.5 退出码：0 = 修复后的配置没有 error / high / medium 结果；1 = 仍有；2 = 参数错误、读取 / 解析失败、已加密、输出已存在未加 `--force`、输出即原文件、校验失败、写入失败。
- R3.6 `dnsnitch check` 的文本输出在汇总后多一行「其中 N 项可用 dnsnitch fix 自动修复」（N > 0 时）；JSON 的每条结果新增 `auto_fix` 布尔字段。其余输出与退出码不变。

### R4 GUI

- R4.1 检查结果中有可自动修复项时，汇总栏显示「自动修复（N 项）」按钮。
- R4.2 点击后显示修复预览：已修改项、跳过项、带颜色的差异、修复后剩余问题的等级汇总。
- R4.3 预览里「保存修复后的配置…」打开系统保存对话框，默认文件名与 R3.2 相同；保存成功后自动对新文件运行检查，界面切换到新文件的结果。
- R4.4 保存时若原配置在预览之后被修改过，拒绝保存并提示重新检查。
- R4.5 前端不能指定要写入的内容或任意路径：写入内容由 Go 侧根据最近一次检查的配置重新计算，路径只来自系统保存对话框。
- R4.6 深色 / 浅色主题下差异的增删行都清晰可读。

### R5 文档

- R5.1 README 新增「自动修复」一节（命令示例、会修什么、不修什么、写到新文件），并把「不改任何文件」改为准确表述（检查不改文件；fix 只写新文件）。
- R5.2 更新 `.trellis/spec/backend/cli-contract.md`、`gui-bindings.md`、`directory-structure.md`。

## Acceptance Criteria

- [ ] AC1：`dnsnitch fix testdata/ac1-geoip-without-no-resolve.yaml --dry-run` 显示 GEOIP 规则加上 `,no-resolve`、`8.8.8.8` 被删除；修复结果检查无 RULE-01 / DNS-02；不写任何文件。
- [ ] AC2：`dnsnitch fix examples/leaky-config.yaml -o <tmp>/out.yaml` 写出文件；`dnsnitch check <tmp>/out.yaml` 退出码 0；原文件哈希不变。
- [ ] AC3：差异之外的字节与原文一致：用带注释、单 / 双引号、CRLF、BOM、空行的夹具验证，修复结果与原文逐字节比较只有预期的修改。
- [ ] AC4：RULE-04：`AND,((DOMAIN-SUFFIX,a.com),(IP-CIDR,1.0.0.0/8)),DIRECT` 改为 `AND,((DOMAIN-SUFFIX,a.com),(IP-CIDR,1.0.0.0/8,no-resolve)),DIRECT`；含两个 IP 子规则的 OR 规则经多轮后两个都加上。
- [ ] AC5：RULE-03：classical 规则集引用 `RULE-SET,x,PROXY` 改为 `RULE-SET,x,PROXY,no-resolve`，规则集文件未被修改；`kind = unknown` 的不改；`testdata/ac3-recommended.yaml`（只有提示级结果）没有可修项。
- [ ] AC6：DNS-02：block 列表与单行 flow 列表（`[8.8.8.8, https://doh.pub/dns-query]`）都能删除明文项；全是明文的 `nameserver` 换成 `https://223.5.5.5/dns-query` 且缩进与原列表一致；DNS-09 同理。
- [ ] AC7：CFG-01：`nameserver-police` 改为 `nameserver-policy`；目标键已存在时跳过并说明。
- [ ] AC8：锚点 / 别名 / `<<` 合并、多行标量、多行 flow 列表的情况跳过并给出原因，其它修改照常。
- [ ] AC9：输出已存在时无 `--force` 退出码 2 且不覆盖；`-o` 指向原文件（含大小写不同的别名）退出码 2；校验失败（用测试注入使修复结果出现新 error）退出码 2 且不写文件。
- [ ] AC10：`--format json` 可解析，含 design 列出的全部字段；`check --format json` 每条结果有 `auto_fix`；现有 `check` / `trace` / `status` e2e 测试除新增字段 / 新增提示行外不需修改即通过。
- [ ] AC11：GUI：检查 `examples/leaky-config.yaml` 后出现「自动修复（2 项）」，预览显示差异；保存到新文件后界面显示新文件的检查结果（无 high / medium）；预览后修改原文件再保存被拒绝。
- [ ] AC12：根模块与 GUI 的验证命令全部通过（含 Linux / macOS 交叉编译、`TestProseOnlyInMessages`、GUI `prose_test.go`）。

## Out of Scope

- 修改原配置文件（原地修复）、修改规则集文件或 GeoSite 数据。
- 调整规则顺序（「把 IP 规则移到域名规则之后」这种修法）。
- DNS-01 / 04 / 05 / 06 / 07 / 08、CFG-03、RULE-05 / 06 的自动修复（需要用户判断，例如选哪个代理组、是否启用 DNS）。
- Windows 注册表 / 组策略等系统设置的修改。
- 拉取订阅、定位客户端运行时配置、通知客户端重新加载配置。
- 交互式逐项选择要应用的修复（本期一次应用全部可修项）。
