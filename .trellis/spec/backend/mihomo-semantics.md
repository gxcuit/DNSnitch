# mihomo Behavior Contract

> The checker is only correct if it models mihomo exactly. These facts were verified against mihomo commit `3f27ef39` (v1.19.33, the version pinned in go.mod). Full notes with source line anchors: `.trellis/tasks/**/11-02-config-dns-leak-check/research/mihomo-dns-semantics.md`. When bumping mihomo, re-verify every item below.

## Which rules trigger local DNS resolution

Only these call `helper.ResolveIP()` (lazy, at most once per connection; `hosts` hits skip DNS):

| Rule | Triggers when |
|---|---|
| GEOIP, IP-ASN, IP-CIDR, IP-CIDR6, IP-SUFFIX | no `no-resolve` and no `src` |
| RULE-SET with behavior `ipcidr` | reference has no `no-resolve`/`src` (content not needed) |
| RULE-SET with behavior `classical` | reference has no `no-resolve`/`src` AND an inner IP entry without its own `no-resolve` is reached |
| AND / OR / NOT / SUB-RULE | an IP sub-rule without `no-resolve` is reached (short-circuit order) |

- `RULE-SET,x,TARGET,no-resolve` disables resolution for the whole set, including classical inner IP entries.
- Classical sets match entries in order: an IP entry triggers for every domain not already matched by entries before it.
- `SRC-*` rules and `src` param never resolve. Domain/process/port rules never resolve.
- fake-ip does NOT prevent this: mihomo maps the fake IP back to the host, then IP rules resolve it for real.

> **Gotcha**: `GEOIP,CN,DIRECT,no-resolve` as a catch-all is ineffective for domain requests (RULE-05), but `GEOIP,lan,...,no-resolve` after `GEOSITE,private` is correct. GEOIP also reuses an IP already resolved by an earlier rule.

## Which resolver answers rule-time resolution

1. `dns.enable: false` or no `dns:` section → system DNS (treat as plaintext). `enable` defaults to **false**.
2. `nameserver-policy`, first matching key in file order.
3. Domain matches `fallback-filter.domain/geosite` → fallback only.
4. Otherwise nameserver **and** fallback are queried concurrently (unless `fallback-lazy-query`). Every server in the group sees the domain.

- `direct-nameserver` is NOT used for rule-time resolution (only by the DIRECT outbound).
- `respect-rules: true` routes nameserver / fallback / policy servers without explicit `#name` through rules; it does not affect `proxy-server-nameserver`, `direct-nameserver`, `default-nameserver`.

## Server grading

| Grade | Forms |
|---|---|
| plaintext | bare IP or host (→ `udp://`), `udp://`, `tcp://`, `http://`, `dhcp://`, `system` |
| encrypted direct | `tls://`, `https://`, `quic://` without proxy (region via `knownservers.go`) |
| via proxy | `#name` resolving to a proxy policy; respect-rules; `ts://`, `et://` |
| safe | `rcode://`; `#name` resolving to REJECT |

`system` / `dhcp` are never upgraded to via-proxy.

## Load-time failures (severity `error`)

- `respect-rules: true` without `proxy-server-nameserver` (DNS-06).
- `default-nameserver` empty or not pure IP — encrypted IP forms like `tls://223.5.5.5` ARE valid (DNS-08).
- Undefined policy / rule-set / sub-rules referenced (CFG-03).
- `parseDNS` runs even when `enable: false`, so these apply whenever a `dns:` section exists.

## Config parsing

- Unknown keys are silently ignored by mihomo (non-strict yaml) → CFG-01 is the only way users learn about typos like `nameserver-police`.
- Duplicate keys make mihomo fail → treat as parse error (exit 2).
- Config may be age-encrypted; detect only at file start.
