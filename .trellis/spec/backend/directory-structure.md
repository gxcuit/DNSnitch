# Directory Structure

> How the `dnsnitch` Go code is organized.

---

## Overview

The repo has two Go modules (GPL-3.0):

- `module dnsnitch` (root): the CLI and all check logic under `internal/`. Pure Go, no CGO, cross-compiles from Windows.
- `module dnsnitch/gui` (`gui/`, nested, `replace dnsnitch => ../`): the Wails v2 desktop app. It may import `dnsnitch/internal/...` (internal visibility is by import path). Root `./...` never includes it, so root checks and cross-compiles are unaffected by Wails/CGO.

`cmd/dnsnitch` only parses arguments and maps results to exit codes; `gui/app.go` only adapts results for the frontend. Both get results through `internal/app`.

---

## Directory Layout

```
cmd/dnsnitch/         CLI entry (main.go) + end-to-end acceptance tests (main_test.go)
internal/app/         Use cases shared by CLI and GUI: RunCheck / LoadEnv / ErrorKind (app.go); PlanFix / SaveFix / DefaultFixOutput (fix.go)
internal/model/       Plain data types (Config, Rule, RuleProvider, DNSServer, Finding, Location, Severity). Imports no internal package.
internal/config/      File → age detection → yaml.v3 Node → model.Config (with line numbers); schema.go = known-key whitelist; nodes.go = Nodes / Doc.Find(path) back to the yaml.Node (anchor / alias / merge flags) for fix
internal/ruleparse/   Rule string parsing (mirrors mihomo ParseRulePayload + logic-rule brackets)
internal/dnsserver/   Nameserver URL parsing, grading, knownservers.go, resolver selection shared by check and trace
internal/policy/      proxies / proxy-groups expansion and classification (direct / proxy / reject / pass)
internal/ruledata/    Rule-provider data (yaml / text / mrs) and GeoSite.dat; local files only
internal/analyze/     Trigger classification, rule-chain scan, independent checks, severity matrix
internal/trace/       Single-domain simulation (reuses analyze.Env)
internal/fix/         Automatic repair plan: Eligible, Build (rule passes + DNS phase, re-check injected as CheckFunc), byte-level text edits (text.go), line diff (diff.go). Pure: no file I/O, no prose
internal/report/      Text (Chinese) and JSON renderers; messages_zh.go holds ALL user-facing prose
internal/platform/    Read-only OS inspection (TUN / smart name resolution): Facts → Decide() → Snapshot (codes only); inspect_windows.go / inspect_other.go
internal/testutil/    Test helpers that generate .mrs and GeoSite.dat in-memory
testdata/             Acceptance fixtures, named ac<N>-<case>.yaml
gui/                  Nested module dnsnitch/gui (Wails v2): main.go, app.go (bound methods), wails.json, README.md
gui/frontend/         Vue 3 + TS app — see .trellis/spec/frontend/
```

---

## Module Organization

Dependency direction (no cycles; verify with `go list -deps`):

```
gui (module dnsnitch/gui) → app, report, platform   (never the other way round)
cmd → app, report, trace, platform
report → analyze, trace, dnsserver, fix, platform, model   (rendering only: data types, analyze.SortFindings, fix.Eligible for auto_fix, fix.Unified)
platform → (nothing internal; stdlib + golang.org/x/sys)
app → config, analyze, fix, model            (no report: prose stays out of the use case)
fix → config, ruleparse, model               (never analyze / app: checking is injected via fix.CheckFunc)
trace → analyze
analyze → policy, dnsserver, ruledata, ruleparse, model
config → ruleparse, dnsserver, model
ruleparse, dnsserver → model
model → (nothing internal)
```

- A new check goes in `internal/analyze` as a function `func (e *Env) checkXxx() []model.Finding` called from `Env.Check()`. Its text goes in `messages_zh.go` keyed by the finding ID.
- A new automatic fix goes in `internal/fix`: make `Eligible` accept the finding, plan a byte-level change, and give every new skip reason a text in `messages_zh.go` (`fixSkipZh`). A fixable finding must end up in `Plan.Edits` or `Plan.Skips`, never neither. Only exception: the RULE-04 of a SUB-RULE whose classical rule-set is referenced from its chain is fixed through the chain's own RULE-03 / RULE-04 finding and is skipped only if it is still reported after the rule passes.
- Anything that needs mihomo behavior must cite the source in `.trellis/spec/backend/mihomo-semantics.md`.
- Future OS-specific work (locating client configs, reading system DNS) goes in a new `internal/platform` package with `_windows.go` / `_linux.go` / `_darwin.go` files behind interfaces; `analyze` must keep receiving plain data only.

---

## Naming Conventions

- Finding IDs: `RULE-NN`, `DNS-NN`, `CFG-NN` (two digits, never reused).
- Fixtures: `testdata/ac<acceptance#>-<short-case>.yaml`; fix fixtures are `testdata/ac15-fix-<case>.yaml` (LF only; CRLF / BOM variants are generated in tests).
- Binary name: `dnsnitch` (`dnsnitch.exe` on Windows); built binaries are git-ignored.

---

## Examples

- Independent checks: `checkUnknownKeys`, `checkMissingRefs`, `checkDNS`, `checkPolicyProxySets` in `internal/analyze/checks.go`.
- Shared logic reused by two features: `dnsserver` resolver selection used by both `analyze` (static) and `trace` (exact).
