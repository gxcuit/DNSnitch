# CLI Contract: `dnsnitch`

> Executable contract for the command-line interface. Change this file together with any change to arguments, output shape or exit codes.

## 1. Scope / Trigger

- Trigger: `dnsnitch` is the only public interface. Scripts and CI rely on its exit codes and JSON fields.

## 2. Signatures

```
dnsnitch check <config.yaml> [--format text|json] [--home <dir>]
dnsnitch trace <config.yaml> <domain> [--format text|json] [--home <dir>]
dnsnitch status [--format text|json]
dnsnitch help | -h | --help
```

- `status` takes no positional argument and no `--home`; it inspects the machine read-only via `platform.Inspect()` (injectable as `inspectSystem` in `main.go` so tests never depend on the machine).

- Flags may appear before or after positional arguments.
- `--home` defaults to the directory of the config file. Rule-provider `path`, the http cache `<home>/rules/<md5(url) hex>` and `<home>/GeoSite.dat` are resolved against it.
- Entry point: `run(args []string, stdout, stderr io.Writer) int` in `cmd/dnsnitch/main.go` (tests call it directly). `check` goes through `app.RunCheck(file, home)`, `trace` through `app.LoadEnv`; error classification (`read` / `parse` / `encrypted`) lives in `internal/app`, never in `main.go`.

## 3. Contracts

**check JSON** (`report.BuildCheckResult` → `report.CheckResult`, written by `writeCheckJSON`). The GUI returns the very same `CheckResult` from its `Check` binding, so any field change here is also a GUI contract change (`gui-bindings.md`):

| Field | Type | Notes |
|---|---|---|
| `file` | string | config path as given |
| `findings[].id` | string | `RULE-NN` / `DNS-NN` / `CFG-NN` |
| `findings[].severity` | string | `error` `high` `medium` `low` `info` (English enum) |
| `findings[].message` / `fix` | string | Chinese prose from `messages_zh.go` |
| `findings[].locations[]` | object | `file`, `line` (1-based, 0 = unknown), `path`, `text`, `role` (`trigger` `trigger-entry` `affected` `resolver` `config` `related`), optional `resolver{level,source,policy_key}` on `affected` |
| `findings[].notes[]` | string | assumptions behind the finding |
| `summary` | object | count per severity |

Ordering: severity (error > high > medium > low > info), then first location line.

**trace JSON** (`report.writeTraceJSON`): top level `file`, `domain`, optional `hosts`, `steps[]`, `verdict`.

| Field | Values |
|---|---|
| `steps[].outcome` | `match` `no-match` `unknown` `assumed-no-match` (IP condition, assumed miss) `pass` `hosts` |
| `steps[]` other | `step` `depth` `rule` `file` `line` `reason` `name` `data_file` `target` `class` |
| `steps[].resolution` | `via_hosts`, `source`, `policy_key`, `servers[]{server,grade,file,line}`, `level` — present on the step that triggered resolution |
| `verdict.code` | `leak` `redundant` `proxy` `direct` `reject` `hosts-proxy` `resolved-direct` |
| `verdict` other | `severity` (leak only), `message`, `final_rule`, `final_target`, `final_class`, `uncertain`, `impact`, `unknown_steps[]`, `notes[]` |

**status JSON** (`report.BuildStatusView` → `report.StatusView`; the GUI `SystemStatus` binding returns the same struct):

| Field | Values |
|---|---|
| `os` | `runtime.GOOS` |
| `smart.state` | `disabled` (safe) `enabled` (Windows default) `unknown` `unsupported` |
| `tun.state` | `on` `off` `unknown` `unsupported` |
| `smart` / `tun` other | `title`, `label` (display names), `reason` (`platform.Reason*` code), `detail[]` (evidence lines), `note` (`tun`: wintun present but not the egress) |
| `risk` | true only for `tun.state = on` and `smart.state = enabled` |
| `conclusion_code` | `risk` `protected` `tun-off` `unknown` `unsupported` |
| `conclusion` | Chinese text |
| `fix[]` | `{text, command?}` display-only remedy from the article; non-empty when `smart.state` is `enabled` or `unknown` |

## 4. Validation & Error Matrix

| Condition | Output | Exit |
|---|---|---|
| no findings of error/high/medium | report | 0 |
| any error/high/medium finding | report | 1 |
| trace verdict = leak with severity ≥ medium | report | 1 |
| status: TUN on + smart name resolution not disabled | report | 1 |
| status: any other combination (incl. unknown / unsupported) | report | 0 |
| status with a positional argument or `--home` | arg error on stderr | 2 |
| no args / unknown subcommand / wrong arg count / empty domain | usage or arg error on stderr | 2 |
| `--format` not text/json | error on stderr | 2 |
| file unreadable | read error on stderr | 2 |
| invalid YAML, duplicate keys, non-mapping root | parse error on stderr | 2 |
| age-encrypted file (armor or binary header at start) | CFG-02 finding on stdout | 2 |
| rule-set / GeoSite data missing or corrupt | finding/step marked unknown + note; never fails | 0/1 by findings |

"error" severity = a config problem that makes mihomo itself refuse to load (DNS-06, DNS-07, DNS-08, CFG-03).

## 5. Good / Base / Bad Cases

- Good: `testdata/ac3-recommended.yaml` → only info findings, exit 0.
- Base: `testdata/ac4-clash-verge-override.yaml` → DNS-02 medium, exit 1.
- Bad: `testdata/ac1-geoip-without-no-resolve.yaml` → RULE-01 high + DNS-02 medium, exit 1; `testdata/ac12-encrypted.yaml` → CFG-02, exit 2.

## 6. Tests Required

- `cmd/dnsnitch/main_test.go`: one e2e test per acceptance case asserting finding IDs, severities, line numbers of trigger/affected/resolver locations, and exit code.
- `internal/report/report_test.go`: `TestProseOnlyInMessages` (no Chinese outside `messages_zh.go`), JSON field presence, both resolver wordings.
- Any new flag or exit-code rule needs a `run(...)` test with captured stdout/stderr.

## 7. Wrong vs Correct

#### Wrong
```go
// exit code depends on text output, or a check prints directly
fmt.Println("发现明文 DNS")
os.Exit(1)
```
#### Correct
```go
// checks return data; only report renders prose; only run() picks the exit code
fs := env.Check()
report.WriteCheck(stdout, o.format, file, fs)
return report.ExitCode(fs)
```
