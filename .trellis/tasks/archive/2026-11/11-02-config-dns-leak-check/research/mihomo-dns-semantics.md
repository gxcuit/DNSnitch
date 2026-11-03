# mihomo DNS / 规则解析语义（源码核对）

- 源码：`github.com/MetaCubeX/mihomo` 分支 `Meta`，提交 `3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8`（2026-10-21）
- 下文 `path:line` 均指该提交。检查器的行为必须以本文件为准；与 `docs/` 中博客文章冲突时，以本文件为准。

## 1. 哪些规则会触发本地 DNS 解析

解析是**惰性**的：规则在 `Match()` 里调用 `helper.ResolveIP()`，每个连接最多解析一次（`tunnel/tunnel.go:327-349`，`resolved` 标志）。命中 `hosts` 的域名直接取 hosts 结果，不发 DNS 查询（`tunnel/tunnel.go:331-334`）。

**会调用 `helper.ResolveIP()` 的规则只有**（`grep -rl "helper.ResolveIP()" rules`）：

| 规则 | 文件 | 条件 |
|---|---|---|
| GEOIP | `rules/common/geoip.go:35-37` | 未带 `no-resolve` 且非 src |
| IP-ASN | `rules/common/ipasn.go` | 同上 |
| IP-CIDR / IP-CIDR6 | `rules/common/ipcidr.go:38-40` | 同上 |
| IP-SUFFIX | `rules/common/ipsuffix.go` | 同上 |
| behavior=ipcidr 的规则集 | `rules/provider/ipcidr_strategy.go:26-28` | 只要 helper.ResolveIP 未被置空 |

- `src` 参数隐含 `no-resolve`（`rules/common/base.go` `ParseParams`）；所有 `SRC-*` 规则都不解析。
- 其余规则（DOMAIN*、GEOSITE、PROCESS-*、DST-PORT、NETWORK、IN-*、UID、DSCP、MATCH 等）都不解析。
- 规则类型全集见 `rules/parser.go` 的 `switch`。

### 1.1 RULE-SET 的 `no-resolve`

`rules/provider/rule_set.go:23-33`：带 `no-resolve`（或 `src`）时把 `helper.ResolveIP = nil`，对整个规则集生效，包括 classical 规则集内部的 IP 规则。

### 1.2 classical 规则集

`rules/provider/classical_strategy.go:22-29`：内部规则**按顺序**逐条 `Match`，第一条命中即返回。内部 IP 规则若没有自己的 `no-resolve`，执行到它时就会解析——即使同一规则集后面的 DOMAIN 条目本可以命中。内部规则自己写的 `no-resolve` 有效（`payloadToRule` 会传 params）。classical 中不允许 `MATCH` / `RULE-SET` / `SUB-RULE`。

### 1.3 逻辑规则（AND / OR / NOT / SUB-RULE）

`rules/logic/logic.go:194-223`：
- AND：按顺序执行，遇到不匹配立即返回 false（短路）。
- OR：按顺序执行，遇到匹配立即返回 true（短路）。
- NOT：总是执行唯一的子规则。
- SUB-RULE：先执行条件规则，命中后再执行 `sub-rules` 里对应的规则列表。
- 子规则的 `no-resolve` 参数有效（`logic.go:77-86` 把 params 传给 parseRule）。

### 1.4 fake-ip 不能阻止规则触发解析

`tunnel/tunnel.go:289-313`：fake-ip 模式下，mihomo 通过 fake IP 反查出域名，写回 `metadata.Host` 并清空 `DstIP`。之后遇到不带 `no-resolve` 的 IP 规则，照样会走 `resolver.ResolveIP` 真解析。

### 1.5 匹配流程

`tunnel/tunnel.go:654-703`：规则自上而下匹配；命中的策略若展开后是 `PASS`，继续匹配后面的规则；`REMATCH` 会换规则集重匹配；全部未命中时用 DIRECT。

## 2. 规则匹配时用哪个 DNS 解析

- 规则匹配期的解析使用 `resolver.DefaultResolver`（`component/resolver/resolver.go:198-200`），即 nameserver-policy + nameserver + fallback。**不使用** `direct-nameserver`。
- `dns.enable: false` 时 `DefaultResolver = nil`（`hub/executor/executor.go:238-247`），解析回落到系统 DNS（`component/resolver/resolver.go:174` `SystemResolver`）。

### 2.1 解析顺序（`dns/resolver.go:299-343` `ipExchange`）

1. `nameserver-policy`：按书写顺序匹配，第一个命中的生效（`dns/resolver.go:261-277`）。
2. 若配置了 fallback 且域名命中 `fallback-filter.domain`/`geosite`：只查 fallback。
3. 否则 **nameserver 与 fallback 同时查询**（除非 `fallback-lazy-query: true`，此时先查 nameserver，结果被 fallback-filter 判为需回退时才查 fallback）。
4. 同一组服务器内是并发查询（`asyncExchange`），组内每台服务器都会收到该域名。

非 A/AAAA 查询：policy → nameserver，不走 fallback（`dns/resolver.go:210-219`）。

### 2.2 DIRECT 出站

`adapter/outbound/direct.go:29,53`：DIRECT 出站连接域名时用 `DirectHostResolver`。配置了 `direct-nameserver` 时就是它，否则等于 DefaultResolver（`hub/executor/executor.go:295-298`）。`direct-nameserver` 默认不走 policy，需 `direct-nameserver-follow-policy: true`（`dns/resolver.go:618-626`）。

### 2.3 代理节点域名

代理节点自身的域名（以及 ECH 配置）用 `ProxyServerHostResolver`：配置了 `proxy-server-nameserver`（可配 `proxy-server-nameserver-policy`）时用它，否则用 DefaultResolver（`hub/executor/executor.go:289-293`）。

## 3. DNS 服务器地址的写法与分类

`config/config.go:1203-1300` `parseNameServer`，以及 `parsePureDNSServer`：
- 不带 scheme 的 IP 或主机名 → `udp://`（例如 `8.8.8.8`、`dns.google` 都是明文 UDP）。
- `system` → 系统 DNS；`dhcp://system` 等价于 `system`。
- scheme 全集：`udp` `tcp` `tls` `https` `http` `quic` `system` `dhcp` `rcode` `ts`/`tailscale` `et`/`easytier`；其它 scheme 加载失败。
- `#片段`：不含 `=` 的部分是代理/策略名，`k=v` 是参数（如 `h3=true`、`ecs=...`）。例：`https://1.1.1.1/dns-query#PROXY&h3=true`。
- `respect-rules: true` 时，nameserver / fallback / nameserver-policy 中**未显式写 `#名称`** 的服务器会按 rules 选出站（`config.go` 中 `proxyName = dns.RespectRules`）。不影响 proxy-server-nameserver、direct-nameserver、default-nameserver。
- `rcode://xxx` 直接返回指定响应码，不发查询。

检查器分级（产品决定，见 prd.md）：

| 分级 | 写法 |
|---|---|
| 明文 | 无 scheme、`udp://`、`tcp://`、`http://`、`dhcp://`、`system` |
| 加密直连 | `tls://`、`https://`、`quic://`，且未经代理 |
| 经代理 | `#名称` 指向的策略是代理；或 respect-rules 生效；或 `ts://`、`et://` |
| 安全 | `rcode://` |

## 4. nameserver-policy 键的写法

`config/config.go:1340-1412`：
- 键可以是 `geosite:xxx`、`rule-set:xxx`（必须是 domain 行为的规则集）、或域名通配（`+.lan`、`*.example.com`）。
- 逗号分隔多个：`"geosite:cn,private"`、`"rule-set:a,b"`、`"+.lan,+.in-addr.arpa"`。
- 值可以是单个字符串或字符串列表，每项按第 3 节解析。

## 5. 默认值与加载期校验

`config/config.go:506-536`（`DefaultRawConfig`）：
- `dns.enable` 默认 **false**；`enhanced-mode` 默认 `redir-host`（DNSMapping）。
- `default-nameserver` 默认 `114.114.114.114`、`223.5.5.5`、`8.8.8.8`、`1.0.0.1`（全是明文）。
- `nameserver` 默认 `https://doh.pub/dns-query`、`tls://223.5.5.5:853`（仅在用户写了 `dns:` 段但没写 nameserver 时才可能用到；`enable: true` 且 nameserver 为空会报错）。

`config/config.go:1415-1500`（`parseDNS`）会让 mihomo **加载失败**的情况：
- `enable: true` 且 nameserver 为空。
- `respect-rules: true` 且 `proxy-server-nameserver` 为空。
- 设置了 `proxy-server-nameserver-policy` 但 `proxy-server-nameserver` 为空。
- `default-nameserver` 为空列表，或其中有非纯 IP 的项（`tls://223.5.5.5` 这类加密 IP 形式**合法**；`system` 合法）。

## 6. 配置文件解析特性

- `config/config.go:618`：`yaml.Unmarshal` 非严格模式，**未知键被静默忽略**。合法的顶层键（`RawConfig` 的 yaml tag，`config/config.go:404`）：
  `port socks-port redir-port tproxy-port mixed-port ss-config vmess-config inbound-tfo inbound-mptcp authentication skip-auth-prefixes lan-allowed-ips lan-disallowed-ips allow-lan bind-address mode unified-delay log-level ipv6 external-controller external-controller-routing-mark external-controller-pipe external-controller-unix external-controller-tls external-controller-cors external-ui external-ui-url external-ui-name external-doh-server secret interface-name routing-mark tunnels geo-auto-update geo-update-interval geodata-mode geodata-loader geosite-matcher tcp-concurrent find-process-mode global-client-fingerprint global-ua etag-support keep-alive-idle keep-alive-interval disable-keep-alive proxy-providers rule-providers proxies proxy-groups rules sub-rules listeners hosts dns ntp tun tuic-server iptables experimental profile geox-url sniffer tls clash-for-android`
- 合法的 `dns` 子键（`RawDNS`，`config/config.go:221-249`）：
  `enable prefer-h3 ipv6 ipv6-timeout use-hosts use-system-hosts respect-rules nameserver fallback fallback-filter fallback-lazy-query listen listen-routing-mark enhanced-mode fake-ip-range fake-ip-range6 fake-ip-filter fake-ip-filter-mode fake-ip-ttl default-nameserver cache-algorithm cache-max-size nameserver-policy proxy-server-nameserver proxy-server-nameserver-policy direct-nameserver direct-nameserver-follow-policy`
- `fallback-filter` 子键：`geoip geoip-code ipcidr domain geosite`。
- `config/config.go:613`：配置文件可能是 age 加密的，mihomo 会先 `age.DecryptBytes`。

## 7. rule-provider 与本地缓存

`rules/provider/parse.go:15-70`：
- 字段：`type behavior path url proxy format interval size-limit payload header path-in-bundle`。
- `type`：`file` / `http` / `inline`；`behavior`：`domain` / `ipcidr` / `classical`；`format`：`yaml`（默认）/ `text` / `mrs`。
- `http` 类型没写 `path` 时，缓存在 `<HomeDir>/rules/<md5(url)>`（`constant/path.go:120-124`，`common/utils/hash.go:15`）。
- 相对路径相对于 mihomo 的 HomeDir（`-d` 指定），**不一定是配置文件所在目录**。
- GeoSite 数据：`<HomeDir>/GeoSite.dat`（文件名大小写不敏感，`constant/path.go:212-228`）。

## 9. 规则数据二进制格式与许可证

mihomo 许可证为 **GPL-3.0**（仓库根目录 `LICENSE`）。

- **`.mrs` 规则集**（`rules/provider/mrs_reader.go:13-70`）：整个文件是 zstd 压缩流；解压后依次为魔数 `MRS\x01`、1 字节 behavior、int64 大端条目数、int64 大端 extra 长度 + extra 数据，然后是数据体：
  - domain 行为：mihomo 自定义的 succinct trie 序列化（`component/trie/domain_set_bin.go`，115 行；依赖 `component/trie/domain_set.go` 336 行与 `github.com/openacid/low/bitmap`）。
  - ipcidr 行为：`component/cidr/ipcidr_set_bin.go`（77 行）。
  - classical 不支持 mrs。
  - 只有 mihomo 有这套读取代码。直接 import（`github.com/metacubex/mihomo/component/trie`、`component/cidr`）或改写，都会让本工具成为 GPL-3.0 衍生作品。
- **GeoSite.dat**：v2ray 的 protobuf 格式（源自 MIT 许可的 v2ray-core）：`GeoSiteList{ repeated GeoSite entry = 1 }`，`GeoSite{ string country_code = 1; repeated Domain domain = 2 }`，`Domain{ Type type = 1; string value = 2; repeated Attribute attribute = 3 }`，`Type`：0=Plain（关键字）、1=Regex、2=Domain（后缀）、3=Full。可用 `google.golang.org/protobuf/encoding/protowire` 手工解码，不需要 mihomo 代码。geosite 名称中的 `@cn` 等属性过滤对应 Domain.attribute。
- mihomo 的 go.mod 有 `replace google.golang.org/protobuf => github.com/metacubex/protobuf-go`；被当作依赖引入时 replace 不生效，所以不要 import `component/geodata`。

## 8. TUN（本期不做，仅记录）

- `dns-hijack` 默认 `0.0.0.0:53`（`config/config.go:549`）；scheme 前缀会被去掉，同一列表同时作用于 TCP 和 UDP；`any` 等于 `0.0.0.0`，未指定地址匹配任意目标的 53 端口（`listener/sing_tun/server.go:285-296`，`listener/sing_tun/dns.go:21-28`）。TUN 网关地址的 53 端口总会被劫持（`server.go:298-307`）。
- 未核实：`tun.dns-mode`（disabled/native/hijack）与 Windows `strict-route` 的具体行为，实现在 `github.com/metacubex/sing-tun v0.4.28`。
