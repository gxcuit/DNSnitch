# 滴水不漏 DNSnitch

English | [简体中文](README.zh-CN.md)

DNS leak detection for Clash / mihomo configs.

About the name: 滴水不漏 (*dī shuǐ bù lòu*, "not a single drop leaks", i.e. watertight) is what this tool tries to help you achieve, and 滴 happens to be pronounced like the letter D, which leaves a spot for DNS. The English name combines DNS and snitch: a leaking DNS query is the snitch that tells on you. The program itself is always lowercase `dnsnitch`.

You're watching YouTube through a proxy, and the traffic really does go through your proxy node, yet your ISP may still know you're visiting `www.youtube.com`. The cause is usually a few patterns in the config that make domains meant for the proxy get looked up in local DNS first. This page first explains how such leaks happen, then how to use the tool and how to read the risk levels it reports.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/gui-check-dark.png">
  <img src="docs/images/gui-check.png" alt="dnsnitch desktop window: check results on the left, the config source on the right with line 16 highlighted">
</picture>

## What a DNS leak is

Normally, once mihomo decides `youtube.com` should go through the proxy, it hands the domain name to the proxy node as is, and the node resolves it. No DNS query for `youtube.com` ever appears on your local network.

If the domain is looked up locally even once, whoever receives that query already knows you're about to visit YouTube, even if the traffic itself still goes through the proxy. Who can see it depends on where the query goes:

- To a plaintext DNS server such as `8.8.8.8`, `223.5.5.5` or `114.114.114.114`: everyone along the path can see it, including your ISP.
- To an encrypted DNS server in mainland China such as `https://223.5.5.5/dns-query`: your ISP can't see it, but the DNS provider (Alibaba, Tencent, …) can.
- To encrypted DNS sent through the proxy, such as `https://1.1.1.1/dns-query#PROXY`: nobody on your local network can see it.

By the way, many tutorials say switching your DNS to `8.8.8.8` is enough. But `8.8.8.8` is queried over plaintext UDP by default, so anyone along the path can still see what you looked up.

## Common config mistakes

### IP rules without no-resolve

This is the most common one. mihomo matches rules from top to bottom. When it reaches an IP rule such as `GEOIP` or `IP-CIDR` and the request is for a domain, it must first resolve the domain to an IP to evaluate the rule. That lookup uses `nameserver`, and at this point mihomo doesn't yet know whether the domain will end up going direct or through the proxy.

```yaml
rules:
  - RULE-SET,apple_domain,Apple
  - GEOIP,private,DIRECT          # no no-resolve: every domain reaching this line is looked up in DNS first
  - GEOSITE,youtube,PROXY         # youtube.com was already looked up on the line above
  - MATCH,PROXY
dns:
  enable: true
  nameserver:
    - 8.8.8.8                     # plaintext: youtube.com is exposed
    - https://doh.pub/dns-query
```

Add `no-resolve` to the IP rule, or move all IP rules below the domain rules:

```yaml
  - GEOIP,private,DIRECT,no-resolve
```

The same applies to classical rule sets that mix IP and domain entries, to IP rule sets referenced without `no-resolve` (e.g. `RULE-SET,cn_ip,DIRECT`), and to IP conditions inside logic rules such as `AND` / `OR`.

### Plaintext DNS mixed into nameserver

```yaml
dns:
  nameserver:
    - 8.8.8.8                     # clash-verge's default DNS override adds exactly this line
    - https://doh.pub/dns-query
    - https://dns.alidns.com/dns-query
```

mihomo queries all of these servers at the same time, so the two DoH servers don't help: the query to `8.8.8.8` still goes out in plaintext. While your rules are correct it may never be used, but the moment one rule goes wrong, it leaks. If you use clash-verge with DNS override turned on, a config from your proxy provider that was fine on its own gets broken by this one line.

### TUN mode on Windows

Windows has "smart multi-homed name resolution" turned on by default, which sends DNS queries to all network adapters at once. With TUN turned on, Clash can only intercept the copy sent to the virtual adapter; the copy sent to the physical adapter goes straight to your ISP. In other words, turning on TUN with the default Windows settings always leaks.

On Pro editions, enable "Computer Configuration → Administrative Templates → Network → DNS Client → Turn off smart multi-homed name resolution" in Group Policy. Home editions have no Group Policy editor; run the following command as administrator, then restart:

```bat
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v DisableSmartNameResolution /t REG_DWORD /d 1 /f
```

### Others

- Misspelled keys, e.g. `nameserver-police` instead of `nameserver-policy`. mihomo doesn't complain; it silently ignores the whole section, which is hard to notice.
- Using `GEOIP,CN,DIRECT,no-resolve` as a catch-all. With `no-resolve`, the rule never matches domain requests.
- Missing `dns.enable: true`. mihomo's own DNS is off by default, so whenever a rule needs a lookup it uses the system DNS, which is plaintext.

## What dnsnitch does

These problems are hard to spot by reading the config, and subscription configs with hundreds or thousands of lines are impossible to review by eye. A packet capture can confirm whether something leaks, but not which line causes it. So I wrote dnsnitch, which analyzes the config file directly:

- It doesn't run mihomo and doesn't go online. Checking only reads the config and never modifies any file; `fix` only writes its result to a new file and leaves the original config untouched.
- Its logic has been checked against the mihomo v1.19.33 source code: which rules trigger lookups, and which DNS server each query goes to.
- Reports point to exact line numbers and explain which rule causes which domains to be looked up, which DNS server receives them, and how to fix it.
- On Windows it can also check, read-only, whether TUN is actually on and whether smart multi-homed name resolution is turned off.

There is a command-line version and a desktop window. Both currently print their results in Chinese.

### Command line

```bash
dnsnitch check config.yaml                    # check a config
dnsnitch trace config.yaml www.youtube.com    # see which DNS server will look up this domain
dnsnitch fix config.yaml                      # auto-fix, writing the result to config.fixed.yaml
dnsnitch status                               # check this machine's TUN and smart multi-homed name resolution
```

All of them accept `--format json`. The first example above, with proxies and proxy groups added, is in [examples/leaky-config.yaml](examples/leaky-config.yaml). Running it gives:

```
$ dnsnitch check examples/leaky-config.yaml

[高] RULE-01  examples/leaky-config.yaml:15
  规则 "GEOIP,private,DIRECT" 没有 no-resolve，会对所有走到这里的域名做本地 DNS 解析：其后指向代理的域名规则（1 条）所匹配的域名，以及未被前面规则匹配、由 "MATCH,PROXY" 兜底走代理的域名，在走代理之前会先发给明文 DNS。
  位置：
    触发规则   examples/leaky-config.yaml:15  GEOIP,private,DIRECT
    受影响    examples/leaky-config.yaml:16  GEOSITE,youtube,PROXY  → 明文 DNS（nameserver）
    受影响    examples/leaky-config.yaml:17  MATCH,PROXY  → 明文 DNS（nameserver）
    解析器    examples/leaky-config.yaml:22  8.8.8.8
  修复：给该规则加上 no-resolve（"GEOIP,private,DIRECT,no-resolve"），或把它移到所有域名规则之后。

[中] DNS-02  examples/leaky-config.yaml:22
  nameserver / fallback 中有明文 DNS：8.8.8.8。mihomo 会同时向组内所有服务器查询，同组的加密服务器挡不住明文查询被看到。
  修复：删除这些明文服务器；需要国内直连解析时改用加密地址（如 https://223.5.5.5/dns-query）。

汇总：错误 0，高 1，中 1，低 0，提示 0
其中 2 项可用 dnsnitch fix 自动修复。
```

In short: RULE-01 (high) says `GEOIP,private,DIRECT` has no `no-resolve`, so the domains matched by the `GEOSITE,youtube,PROXY` rule below it, and everything falling through to `MATCH,PROXY`, are first sent to the plaintext DNS server `8.8.8.8` on line 22. DNS-02 (medium) says `nameserver` contains plaintext DNS. The last line says both can be fixed automatically with `dnsnitch fix`.

Add `no-resolve` to the GEOIP rule as suggested and run it again: the high-risk finding is gone, leaving only `8.8.8.8` in `nameserver`. dnsnitch can also make both changes for you; see "Auto-fix" below.

Rule-set caches and `GeoSite.dat` are looked up in the config file's directory by default; if they live elsewhere, point `--home` at mihomo's data directory. Also note that the config a client actually uses is not necessarily the one you subscribed to; mihomo-party, for example, uses `%APPDATA%\mihomo-party\work\config.yaml`.

### Auto-fix

Problems that have a fixed solution can be fixed by dnsnitch directly. Using the same example:

```
$ dnsnitch fix examples/leaky-config.yaml
自动修复：examples/leaky-config.yaml

已修改（2 处）：
  RULE-01  examples/leaky-config.yaml:15
    修改前：- GEOIP,private,DIRECT
    修改后：- GEOIP,private,DIRECT,no-resolve
  DNS-02  examples/leaky-config.yaml:22
    修改前：- 8.8.8.8
    修改后：（删除这一行）

差异：
--- examples/leaky-config.yaml
+++ examples/leaky-config.fixed.yaml
@@ -12,12 +12,11 @@
 
 rules:
   - RULE-SET,apple_domain,Apple
-  - GEOIP,private,DIRECT
+  - GEOIP,private,DIRECT,no-resolve
   - GEOSITE,youtube,PROXY
   - MATCH,PROXY
 
 dns:
   enable: true
   nameserver:
-    - 8.8.8.8
     - https://doh.pub/dns-query

修复后仍存在的检查结果：

未发现问题。

修复前：错误 0，高 1，中 1，低 0，提示 0
修复后：错误 0，高 0，中 0，低 0，提示 0

已写入：examples/leaky-config.fixed.yaml（原配置文件未修改）
```

It lists the two edits (line 15 gets `,no-resolve`, line 22 is deleted), shows the diff, re-checks the result (no problems left: high 1 / medium 1 before, all zero after), and reports that it wrote `examples/leaky-config.fixed.yaml` without touching the original.

The result goes to a new file, by default next to the original and named `<name>.fixed.yaml` (`.fixed.yml` for `.yml` files); the original config is never modified. Before writing, dnsnitch checks the fixed content in full; if it wouldn't load, or it has an error-level finding the original didn't have, nothing is written.

What gets fixed automatically:

- IP rules that trigger local lookups, including `RULE-SET` references to IP or classical rule sets and IP conditions inside `AND` / `OR` / `NOT`: `no-resolve` is added. Findings at the info level are left alone; in that case the query already goes through the proxy, so it isn't a leak.
- Plaintext DNS in `nameserver`, `fallback` and `proxy-server-nameserver`: removed. If `nameserver` or `proxy-server-nameserver` would end up empty, it is replaced with `https://223.5.5.5/dns-query`.
- Misspelled keys, e.g. `nameserver-police` becomes `nameserver-policy`.

Only the affected characters change; comments, indentation, quotes, blank lines and line endings stay as they were. The following cases are not changed; they are listed under 「未自动修改」 ("not changed automatically") with a reason: content referenced through YAML anchors, aliases or `<<` merges (changing one place would affect others); rules or lists written across several lines; a target key name that already exists in the same section; problems inside a rule-set file. Things that need your judgment, such as DNS being turned off, rule order, or which proxy group to use, still only get advice.

An IP rule with `no-resolve` no longer matches domain requests. If you relied on it to route domains, for example `GEOIP,CN,DIRECT` to send Chinese sites direct, add a domain rule as well (such as `GEOSITE,cn,DIRECT`).

Options:

- `--dry-run`: only show what would change and the diff; write nothing.
- `-o <path>`: write to the given file.
- `--force`: overwrite the output file if it already exists. Without it, nothing is overwritten. If the output path is the original config, nothing is written even with `--force`.

The exit code reflects the fixed config: 0 if there are no error, high or medium findings, otherwise 1. It is 2 if the output file already exists, verification fails or writing fails.

### Desktop window

Open `dnsnitch-gui`, then choose a config file or drag one in. Check results are on the left; click a line number in a result and the right side jumps to that place in the config source. The screenshot at the top of this page shows the result for `examples/leaky-config.yaml`.

When some findings can be fixed automatically, a 「自动修复（N 项）」 ("auto-fix N items") button appears. It opens a preview of the edits and the diff; saving goes through the system save dialog, writes a new file, and then checks that new file.

The top of the window always shows this machine's TUN and smart multi-homed name resolution status, which you can refresh at any time. Expand 「检测依据」 ("evidence") to see the registry value and adapter information behind the verdict:

![System status: smart multi-homed name resolution is turned off and TUN is on, with the registry value and wintun adapter details listed below](docs/images/gui-status.png)

## Risk levels

The level depends on two things: who can see the query, and whether it happens every time or only might happen. The output uses the Chinese names 错误 (error), 高 (high), 中 (medium), 低 (low) and 提示 (info).

**High**: your ISP can see which proxied sites you visit. For example, the first example above: an IP rule without `no-resolve` plus plaintext DNS in `nameserver`; or `nameserver-policy` handing `geosite:geolocation-!cn` to `114.114.114.114`. On the system side, TUN turned on while smart multi-homed name resolution is not turned off is also high.

**Medium**: your ISP can't see it, but a DNS provider in mainland China can. For example, the same IP rule without `no-resolve`, but with `https://223.5.5.5/dns-query` as the nameserver. Another kind is "not leaking now, but easy to leak": `8.8.8.8` mixed into `nameserver`; sites named in your rules are fine, but sites not covered by any rule are looked up once in plaintext when they fall through to `MATCH,PROXY`; a misspelled DNS-related key, so the setting never takes effect.

**Low**: only a provider outside mainland China can see it, or what leaks is not the site you visit. For example, queries sent to `https://1.1.1.1/dns-query` without `#PROXY`; plaintext DNS in `proxy-server-nameserver`, which leaks your proxy nodes' domain names.

**Info**: not a leak, but could be improved. For example, the DNS query itself goes through the proxy and is just made one extra time (the config recommended in the "Clash.Meta DNS Configuration Guide" works this way); `GEOIP,CN,DIRECT,no-resolve` as a catch-all doesn't work; whitelist-style `MATCH,DIRECT`; still using `fallback`.

**Error**: the config is wrong and mihomo won't load it at all. For example, `respect-rules` turned on without `proxy-server-nameserver`, a domain name in `default-nameserver`, or a rule referencing a proxy group that doesn't exist.

If there is any error, high or medium finding, the command-line exit code is 1 and the window shows 「发现需要处理的问题」 ("problems need attention"). With only low and info findings it shows 「未发现泄露风险」 ("no leak risk found").

## Download

Current version: v0.1.0. Earlier versions are on the [Releases](https://github.com/gxcuit/DNSnitch/releases) page.

| Build | Download |
| --- | --- |
| Windows desktop window | [dnsnitch-gui_v0.1.0_windows_amd64.zip](https://github.com/gxcuit/DNSnitch/releases/download/v0.1.0/dnsnitch-gui_v0.1.0_windows_amd64.zip) |
| Windows command line (x64) | [dnsnitch_v0.1.0_windows_amd64.zip](https://github.com/gxcuit/DNSnitch/releases/download/v0.1.0/dnsnitch_v0.1.0_windows_amd64.zip) |
| Windows command line (ARM64) | [dnsnitch_v0.1.0_windows_arm64.zip](https://github.com/gxcuit/DNSnitch/releases/download/v0.1.0/dnsnitch_v0.1.0_windows_arm64.zip) |
| macOS command line (Apple silicon) | [dnsnitch_v0.1.0_darwin_arm64.tar.gz](https://github.com/gxcuit/DNSnitch/releases/download/v0.1.0/dnsnitch_v0.1.0_darwin_arm64.tar.gz) |
| macOS command line (Intel) | [dnsnitch_v0.1.0_darwin_amd64.tar.gz](https://github.com/gxcuit/DNSnitch/releases/download/v0.1.0/dnsnitch_v0.1.0_darwin_amd64.tar.gz) |
| Linux command line (x86_64) | [dnsnitch_v0.1.0_linux_amd64.tar.gz](https://github.com/gxcuit/DNSnitch/releases/download/v0.1.0/dnsnitch_v0.1.0_linux_amd64.tar.gz) |
| Linux command line (ARM64) | [dnsnitch_v0.1.0_linux_arm64.tar.gz](https://github.com/gxcuit/DNSnitch/releases/download/v0.1.0/dnsnitch_v0.1.0_linux_arm64.tar.gz) |

Checksums: [SHA256SUMS.txt](https://github.com/gxcuit/DNSnitch/releases/download/v0.1.0/SHA256SUMS.txt). Latest build of the main branch: [nightly](https://github.com/gxcuit/DNSnitch/releases/tag/nightly).

If macOS says the developer cannot be verified, run `xattr -d com.apple.quarantine ./dnsnitch`.

## Building

Requires Go 1.27 or later.

```bash
go build -o dnsnitch ./cmd/dnsnitch
```

The command-line version is pure Go and cross-compiles directly to Linux and macOS. The desktop window uses Wails v2 and Vue 3 and additionally needs Node.js and the Wails CLI; see [gui/README.md](gui/README.md) (in Chinese) for details:

```bash
go install github.com/wailsapp/wails/v2/cmd/wails@v2.17.1
cd gui && wails build
```

## Not done yet

- Config checks currently assume the system proxy / mixed-port setup. TUN-mode settings such as fake-ip and dns-hijack aren't checked yet; the only TUN-related check is `status`.
- `nameserver-policy` entries are matched to rules by name, so rule sets with different names but overlapping content aren't recognized. To check a specific domain, use `trace`.
- The system status check only supports Windows.
- Only mihomo (Clash.Meta) is supported, not the original Clash, which is no longer maintained.
- Output and the desktop window are in Chinese only.

## References

The detection logic is mainly based on these articles (in Chinese):

- [解决DNS泄露最佳实践——基于 ClashMeta](https://blog.arisa.moe/blog/2025/250814-best-practice-of-anti-dns-leak/) ("Best practices for avoiding DNS leaks with ClashMeta"), Akiba Arisa
- [Clash.Meta DNS 配置指南](https://blog.akise.app/posts/clash-dns-configure/) ("Clash.Meta DNS Configuration Guide"), Aki Akise
- DNS 泄漏可能比你想的范围广，以及 clash 与 tailscale 共同使用的配置 ("DNS leaks may be wider than you think, plus a config for using clash together with tailscale")
- [Windows 系统下 Clash 系代理软件虚拟网卡（TUN）模式的 DNS 泄露问题及解决方案](https://wildprobe.com/soft-technical/dnsleak/) ("DNS leaks with Clash-family proxies in TUN mode on Windows, and how to fix them"), 野生网管

## Acknowledgements

Thanks to the [LINUX DO](https://linux.do) community.

## License

[GPL-3.0](LICENSE). The code for reading `.mrs` rule sets comes from [mihomo](https://github.com/MetaCubeX/mihomo).
