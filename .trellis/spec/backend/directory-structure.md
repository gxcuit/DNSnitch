# Directory Structure

> How the `dnsleak` Go code is organized.

---

## Overview

`dnsleak` is a single Go module (`module dnsleak`, GPL-3.0) that builds one CLI binary. All logic lives under `internal/`; `cmd/dnsleak` only parses arguments, wires packages together and maps results to exit codes.

---

## Directory Layout

```
cmd/dnsleak/          CLI entry (main.go) + end-to-end acceptance tests (main_test.go)
internal/model/       Plain data types (Config, Rule, RuleProvider, DNSServer, Finding, Location, Severity). Imports no internal package.
internal/config/      File → age detection → yaml.v3 Node → model.Config (with line numbers); schema.go = known-key whitelist
internal/ruleparse/   Rule string parsing (mirrors mihomo ParseRulePayload + logic-rule brackets)
internal/dnsserver/   Nameserver URL parsing, grading, knownservers.go, resolver selection shared by check and trace
internal/policy/      proxies / proxy-groups expansion and classification (direct / proxy / reject / pass)
internal/ruledata/    Rule-provider data (yaml / text / mrs) and GeoSite.dat; local files only
internal/analyze/     Trigger classification, rule-chain scan, independent checks, severity matrix
internal/trace/       Single-domain simulation (reuses analyze.Env)
internal/report/      Text (Chinese) and JSON renderers; messages_zh.go holds ALL user-facing prose
internal/testutil/    Test helpers that generate .mrs and GeoSite.dat in-memory
testdata/             Acceptance fixtures, named ac<N>-<case>.yaml
```

---

## Module Organization

Dependency direction (no cycles; verify with `go list -deps`):

```
cmd → report, trace, analyze, config
trace → analyze
analyze → policy, dnsserver, ruledata, ruleparse, model
config → ruleparse, dnsserver, model
ruleparse, dnsserver → model
model → (nothing internal)
```

- A new check goes in `internal/analyze` as a function `func (e *Env) checkXxx() []model.Finding` called from `Env.Check()`. Its text goes in `messages_zh.go` keyed by the finding ID.
- Anything that needs mihomo behavior must cite the source in `.trellis/spec/backend/mihomo-semantics.md`.
- Future OS-specific work (locating client configs, reading system DNS) goes in a new `internal/platform` package with `_windows.go` / `_linux.go` / `_darwin.go` files behind interfaces; `analyze` must keep receiving plain data only.

---

## Naming Conventions

- Finding IDs: `RULE-NN`, `DNS-NN`, `CFG-NN` (two digits, never reused).
- Fixtures: `testdata/ac<acceptance#>-<short-case>.yaml`.
- Binary name: `dnsleak` (`dnsleak.exe` on Windows); built binaries are git-ignored.

---

## Examples

- Independent checks: `checkUnknownKeys`, `checkMissingRefs`, `checkDNS`, `checkPolicyProxySets` in `internal/analyze/checks.go`.
- Shared logic reused by two features: `dnsserver` resolver selection used by both `analyze` (static) and `trace` (exact).
