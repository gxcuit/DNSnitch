# 技术设计：mihomo 配置 DNS 泄露静态检查 (P1)

需求见 `prd.md`；mihomo 行为依据见 `research/mihomo-dns-semantics.md`（下称 research）。

## 1. 总体结构

```
cmd/dnsleak/main.go        命令行入口：子命令 check / trace，参数 --format --home
internal/model/            纯数据结构：Location、Rule、RuleProvider、Policy、DNSServer、Finding
internal/config/           读文件 → 加密检测 → yaml.v3 Node → model.Config（全部带行号）
                           schema.go：合法键白名单 + 相近键建议
internal/ruleparse/        规则字符串解析（含逻辑规则括号嵌套）
internal/policy/           proxies / proxy-groups 展开与分类
internal/dnsserver/        DNS 服务器地址解析与分级；knownservers.go 内置知名 DNS 表
internal/ruledata/         规则集与 GeoSite 数据读取（yaml / text / mrs / GeoSite.dat）
internal/analyze/          触发分析、解析器推断、各检查项、等级合成
internal/trace/            单域名模拟
internal/report/           文本（中文）与 JSON 输出；messages_zh.go 集中存放提示文字
testdata/                  验收用例配置及对应的规则集缓存文件
LICENSE                    GPL-3.0
```

依赖方向：`cmd → report / analyze / trace → policy / dnsserver / ruledata / ruleparse → config → model`。`model` 不依赖任何内部包。

## 2. 跨平台边界

- 本期所有代码只做文件读取和纯计算，不调用任何操作系统 API，不使用 build tag。
- 路径一律用 `path/filepath`；`--home` 默认取 `filepath.Dir(配置文件绝对路径)`。
- 输出统一使用 `\n`；读取输入时兼容 `\r\n`（YAML 与 text 规则集）。
- 后续扩展点（本期不建包）：
  - `internal/platform`：`ConfigLocator`（定位客户端运行时配置）与 `SystemInspector`（读取系统 DNS / 代理状态）接口，按 `_windows.go` / `_linux.go` / `_darwin.go` 实现。
  - 检查器只接收 `model.Config` 和一个「系统事实快照」结构，所以新增平台只需补实现文件，不改 `analyze`。

## 3. 关键数据结构（`internal/model`）

```go
type Location struct {
    File   string // 配置文件或规则集文件路径
    Line   int    // 1 起始；0 表示未知
    Path   string // YAML 路径，如 "rules[12]"、"dns.nameserver[0]"
    Text   string // 原文片段，用于报告展示
}

type Severity int // Error > High > Medium > Low > Info

type Finding struct {
    ID        string     // RULE-01、DNS-02、CFG-01 …
    Severity  Severity
    Message   string     // 中文一句话说明
    Locations []Location // 规则位置、解析器位置等，按重要性排序
    Fix       string     // 中文修复建议
    Notes     []string   // 依赖的假设，如「策略组 X 含 DIRECT，按代理处理」
}
```

`Rule`：`Index`、`Raw`、`Type`（大写）、`Payload`、`Target`、`Params`、`NoResolve`、`Src`、`Subs []Rule`（逻辑规则子规则）、`Loc`。

`RuleProvider`：`Name`、`Type`（file/http/inline）、`Behavior`（domain/ipcidr/classical）、`Format`（yaml/text/mrs）、`Path`、`URL`、`Payload`、`Loc`；加载后附加 `Data`（见第 6 节），加载失败时 `Data == nil` 并记录原因。

`DNSServer`：`Raw`、`Scheme`、`Host`、`ProxyName`、`Grade`（Plain / EncryptedDirect / ViaProxy / Safe）、`Region`（CN / Foreign / Unknown，仅对 EncryptedDirect 有意义）、`Loc`。

## 4. 配置读取（`internal/config`）

1. 读入字节；若以 `age-encryption.org/v1` 开头或包含 `-----BEGIN AGE ENCRYPTED FILE-----`，返回 `ErrEncrypted`（CFG-02，退出码 2）。
2. `yaml.v3` 解析为 `*yaml.Node`，展开锚点与 `<<` 合并键；从 Node 构建 `model.Config`，每个元素记录 `Node.Line`。
3. 键名校验：顶层、`dns`、`dns.fallback-filter` 的键与 research 第 6 节白名单比对；未知键产出 CFG-01，用编辑距离 ≤ 2 的合法键作建议。
4. 只解析检查需要的段：`proxies`、`proxy-groups`、`proxy-providers`（仅名字）、`rule-providers`、`rules`、`sub-rules`、`hosts`、`dns`。其余段只做键名校验。
5. 缺少 `dns` 段时按 mihomo 默认值构造（`enable: false`，research 第 5 节）。

## 5. 规则解析（`internal/ruleparse`）

- 普通规则按 mihomo `ParseRulePayload` 语义（research 第 1 节、`rules/common/base.go`）：逗号切分，`MATCH` 只有目标；`AND/OR/NOT/SUB-RULE/DOMAIN-REGEX/PROCESS-*-REGEX` 的最后一项是目标，中间整体为 payload；其余规则 `类型,payload,目标,参数…`。classical 规则集内的条目没有目标。
- 逻辑规则 payload 按括号配对拆出子规则，递归解析。
- `no-resolve`、`src` 参数解析：`src` 隐含 `no-resolve`。

## 6. 规则数据（`internal/ruledata`）

统一接口：

```go
type DomainSet interface { Match(domain string) bool }
type ProviderData struct {
    Domains  DomainSet       // behavior=domain
    CIDRs    []netip.Prefix  // behavior=ipcidr（mrs 时为 cidr.IpCidrSet 包装）
    Rules    []model.Rule    // behavior=classical
}
```

- 查找顺序（PRD R1.4）：inline payload → `path`（相对 `--home`）→ http 默认缓存 `<home>/rules/<md5(url) 十六进制>`。
- yaml 格式：读 `payload` 列表；text 格式：逐行，忽略空行和 `#` 注释。
- domain 规则写法：`+.a.com`（自身及子域）、`.a.com`（仅子域）、`*.a.com`（单层通配）、`a.com`（精确）。
- mrs：zstd 解压 → 校验魔数与 behavior → 跳过 count 与 extra → domain 用 `trie.ReadDomainSetBin`，ipcidr 用 `cidr.ReadIpCidrSet`（import `github.com/metacubex/mihomo/component/trie`、`component/cidr`，版本固定到 research 中的提交）。
- GeoSite.dat：用 `protowire` 手工解码 research 第 9 节的结构，按需只解出被引用的 geosite 名称；支持 `name@attr` 属性过滤；四种匹配类型 Plain / Regex / Domain / Full。
- 任何数据读不到都不报错，只返回「未知」并带原因；由调用方在 Notes 中说明。

## 7. 策略分类（`internal/policy`）

- 内置：`DIRECT` → 直连；`REJECT`、`REJECT-DROP` → 拒绝；`PASS` → PASS；`COMPATIBLE` → 直连。
- `proxies` 中的节点 → 代理。
- `proxy-groups`：递归展开 `proxies` 成员；含 `use`（proxy-providers）或 `include-all` 视为含代理节点；有环时停止并按代理处理。组内只要有代理节点 → 代理（并记录假设）；全部为直连 / 拒绝 → 直连（若含直连）或拒绝。
- 引用了不存在的名字 → CFG-03（规则目标）或 DNS-07（DNS `#名称`）。

## 8. DNS 服务器分级（`internal/dnsserver`）

按 research 第 3 节解析写法；`respect-rules: true` 时，nameserver / fallback / nameserver-policy 中没有 `#名称` 的服务器视为「经代理」。`#名称` 指向的策略被分类为直连时，按未写 `#` 处理。

地区判断用内置表（`knownservers.go`，按 IP 与主机名匹配），例：
- 国内：`223.5.5.5` `223.6.6.6` `dns.alidns.com` `119.29.29.29` `doh.pub` `dot.pub` `1.12.12.12` `120.53.53.53` `114.114.114.114` `114.114.115.115` `180.76.76.76` `180.184.1.1` `180.184.2.2` 及其 IPv6 地址
- 国外：`1.1.1.1` `1.0.0.1` `cloudflare-dns.com` `8.8.8.8` `8.8.4.4` `dns.google` `9.9.9.9` `dns.quad9.net` `208.67.222.222` `94.140.14.14` `185.222.222.222` `45.11.45.11` `101.101.101.101` 及其 IPv6 地址
- 表外 → Unknown，等级合成时按「国外 / 未知加密」处理。

## 9. 分析流程（`internal/analyze`）

### 9.1 触发分类（每条规则）

`Trigger{Kind: None | Always | Conditional | Unknown, Except, Guard, Reason}`：

- **Always**：除 `Except` 列出的域名外，所有走到这条规则的域名都会触发解析。
- **Conditional**：只有满足 `Guard` 的域名才会触发。
- **Unknown**：规则集内容读不到，无法判断。

分类规则：
- 原子 IP 规则（GEOIP / IP-ASN / IP-CIDR / IP-CIDR6 / IP-SUFFIX），未带 `no-resolve` 且非 src → Always。
- RULE-SET：带 `no-resolve` 或 `src` → None。否则按 provider behavior：
  - ipcidr → Always（不需要读内容）。
  - domain → None。
  - classical → 按内部顺序找第一条会触发的条目；找到 → Always，其前面的域名条目记入 `Except`（命中它们的域名会提前返回）；没有 → None；内容读不到 → Unknown。
- AND：第一个会触发的子规则之前的子规则全部要命中才会走到它 → 前面没有子规则时为 Always，否则 Conditional（`Guard` = 前面的子规则）。
- OR：第一个会触发的子规则之前的子规则命中时会提前返回 → Always，前面的子规则记入 `Except`。
- NOT：子规则会触发 → Always。
- SUB-RULE：条件规则按上面规则判断；被引用的 sub-rules 列表作为独立规则链递归分析。
- 其它规则 → None。

### 9.2 规则链扫描

1. 自上而下找第一条 `Always` 规则 T。
2. T 之后，目标为「代理」的域名类规则（DOMAIN*、GEOSITE、domain/classical RULE-SET、全由域名子规则构成的逻辑规则）记为「一定被解析」，按 PRD R5 的 RULE-01 行定级；T 之后由 `MATCH,代理` 兜底时，「未知域名」按 RULE-02 行定级。
3. Finding 的 ID 取决于 T 的形态：原子 IP 规则或 ipcidr 规则集 → RULE-01 / RULE-02；classical 规则集 → RULE-03；逻辑规则 → RULE-04。同一个 T 合并为一条 Finding，Locations 依次列出 T（classical 时再加规则集内的那一条）、受影响规则、解析器。
4. T 之前的 Conditional 规则 → RULE-04，影响范围为 `Guard` 描述的域名；这些域名最终是否走代理无法确定，按 RULE-02 行定级。
5. T 之前的 Unknown 规则 → 提示级 Finding（与触发它的规则同 ID），说明规则集内容读不到、无法判断。
6. 规则目标为 PASS 时视为不命中、继续向下扫描。
7. RULE-05：`GEOIP` 且国家不是 `lan`、带 `no-resolve`、位于所有域名规则之后（作为兜底）。
8. RULE-06：最终兜底目标为直连；没有 MATCH 时 mihomo 默认 DIRECT，同样适用。

### 9.3 解析器推断

对受影响的域名集合（某条规则覆盖的域名，或「未知域名」）：
1. `dns.enable` 为 false → 系统 DNS（明文），同时产出 DNS-01。
2. 在 `nameserver-policy` 中按顺序找静态对应项：`GEOSITE,x` ↔ `geosite:x`；`RULE-SET,x` ↔ `rule-set:x`；`DOMAIN` / `DOMAIN-SUFFIX` ↔ 能覆盖它的域名通配键。找到 → 使用该项服务器。
3. 否则若 `fallback-filter.domain` / `geosite` 对应 → 只用 fallback；否则 nameserver ∪ fallback。
4. 「未知域名」直接用 nameserver ∪ fallback。
5. 取集合内最差的分级，按 PRD R5 矩阵合成等级；静态对应是近似时在 Notes 中说明。

### 9.4 独立检查

CFG-01/02/03 与 DNS-02/04/05/06/07/08/09 按 PRD 表格逐项实现，每项一个函数，输入 `model.Config` 与已分类的策略，输出 `[]Finding`。

## 10. trace（`internal/trace`）

1. 若 `hosts` 中有该域名 → 说明不会发 DNS 查询，然后继续规则匹配。
2. 逐条规则模拟：域名类规则用第 6 节数据判断命中 / 不命中 / 未知；IP 类规则：
   - 带 `no-resolve` → 不匹配（无 IP），继续。
   - 否则若尚未解析 → 记录「触发解析」，用真实数据精确计算该域名的解析器（policy 实际匹配 → fallback-filter → nameserver ∪ fallback）。IP 是否命中无法静态得知：按「不命中」继续，并标注此假设。
3. 命中规则后展开策略：PASS 继续；否则得到最终策略。
4. 结论：发生过解析且最终策略为代理 → 泄露，等级按解析器分级；最终为直连 → 正常解析；中途有「未知」步骤 → 结论标注「不确定」并列出缺失的数据。
5. 输出：文本为逐步列表；JSON 为 steps 数组 + verdict。

## 11. 输出（`internal/report`）

- 文本：按等级（错误 > 高 > 中 > 低 > 提示）再按首个位置行号排序；每条显示 `[等级] ID 文件:行`、说明、相关位置、修复建议、假设；末尾汇总各等级数量。
- JSON：`{"findings":[{id,severity,message,locations:[{file,line,path,text}],fix,notes}],"summary":{...}}`；severity 用英文枚举（error/high/medium/low/info），文字字段为中文。
- 所有提示文字放在 `messages_zh.go`，以检查项 ID 为键，函数式模板，便于以后加 `messages_en.go`。

## 12. 依赖

| 依赖 | 用途 |
|---|---|
| `gopkg.in/yaml.v3` | 带行号的 YAML 解析 |
| `github.com/metacubex/mihomo`（仅 `component/trie`、`component/cidr`） | 读取 `.mrs` |
| `github.com/klauspost/compress/zstd` | 解压 `.mrs` |
| `google.golang.org/protobuf/encoding/protowire` | 解码 GeoSite.dat |

命令行解析用标准库 `flag`，不引入其它框架。

## 13. 风险与取舍

- **引入 mihomo 模块**：会把 mihomo 的依赖写入 go.sum（只编译用到的包）。如果 `component/trie` / `component/cidr` 间接拉入无法编译的包，退路是按 GPL-3.0 把这两个包的相关文件复制到 `internal/third_party/mihomo/` 并保留版权声明。implement 第 1 步先验证。
- **nameserver-policy 静态对应是近似**：例如 `geosite:google` 与规则 `GEOSITE,youtube` 有重叠但名字不同，会被判为不对应。结果在 Notes 中说明；trace 有数据时给出精确结果。
- **IP 规则命中与否不可静态得知**：trace 按「不命中」继续并标注，可能与实际最终策略不同。
- **知名 DNS 表需要维护**：表外加密 DNS 一律按「未知」处理，最多把「中」误判为「低」，不会漏报明文。

## 14. 回滚

本期只新增文件，不修改已有内容（`docs/`、`.trellis/` 除外的任务产物），回滚即删除新增的 Go 源码与 `go.mod` / `go.sum`。
