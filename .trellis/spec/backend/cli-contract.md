# CLI Contract: `dnsnitch`

> Executable contract for the command-line interface. Change this file together with any change to arguments, output shape or exit codes.

## 1. Scope / Trigger

- Trigger: `dnsnitch` is the only public interface. Scripts and CI rely on its exit codes and JSON fields.

## 2. Signatures

```
dnsnitch check <config.yaml> [--format text|json] [--home <dir>]
dnsnitch trace <config.yaml> <domain> [--format text|json] [--home <dir>]
dnsnitch fix <config.yaml> [-o|--output <path>] [--force] [--dry-run] [--format text|json] [--home <dir>]
dnsnitch status [--format text|json]
dnsnitch help | -h | --help
```

- `status` takes no positional argument and no `--home`; it inspects the machine read-only via `platform.Inspect()` (injectable as `inspectSystem` in `main.go` so tests never depend on the machine).

- `fix` writes the fixed config to a **new** file: `-o/--output`, default `app.DefaultFixOutput(file)` (`config.yaml` → `config.fixed.yaml`, `config.yml` → `config.fixed.yml`, no extension → `config.fixed.yaml`). The config itself is never written. `--force` overwrites an existing output; `--dry-run` writes nothing. `-o/--output`, `--force`, `--dry-run` with any other subcommand (even `--force=false`) is an argument error (detail `report.ArgFixOnly`).
- Flags may appear before or after positional arguments.
- `--home` defaults to the directory of the config file. Rule-provider `path`, the http cache `<home>/rules/<md5(url) hex>` and `<home>/GeoSite.dat` are resolved against it.
- Entry point: `run(args []string, stdout, stderr io.Writer) int` in `cmd/dnsnitch/main.go` (tests call it directly). `check` goes through `app.RunCheck(file, home)`, `trace` through `app.LoadEnv`, `fix` through `app.PlanFix(file, home)` (package variable `planFix`, replaced by tests to inject a verification failure) and then `app.SaveFix(out, dest, force)` unless `--dry-run` or there are no edits; error classification lives in `internal/app`, never in `main.go`.

```go
// internal/app
func PlanFix(file, home string) (FixOutcome, ErrorKind, error)          // never writes; ErrVerify still returns the outcome
func DefaultFixOutput(file string) string
func SaveFix(out FixOutcome, dest string, force bool) (ErrorKind, error) // no edits -> writes nothing, ErrNone
// internal/report
func BuildFixResult(file, output string, plan *fix.Plan, before, after []model.Finding, written bool) FixResult
func WriteFix(w io.Writer, format string, r FixResult) error
```

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
| `findings[].auto_fix` | bool | `fix.Eligible(f)`: `dnsnitch fix` has a mechanical fix for it (it may still be skipped, e.g. `key-exists`) |
| `summary` | object | count per severity |

Ordering: severity (error > high > medium > low > info), then first location line.

**check text**: after the `汇总：…` line, one more line `其中 N 项可用 dnsnitch fix 自动修复。` when N (findings with `auto_fix`) > 0. Nothing else in check / trace / status output depends on `fix`.

**fix eligibility** (`fix.Eligible`, also the source of `auto_fix`):

| ID | Condition | Change |
|---|---|---|
| RULE-01 / RULE-02 | `kind = always` and severity > info | append `,no-resolve` to the trigger rule |
| RULE-03 / RULE-04 | `kind` ∈ `always`, `conditional` and severity > info | `,no-resolve` on the `RULE-SET` rule / inside the resolving logic sub-rule |
| DNS-02 / DNS-09 | always | delete plaintext servers; an emptied `nameserver` / `proxy-server-nameserver` becomes `https://223.5.5.5/dns-query`, an emptied `fallback` becomes `[]` |
| CFG-01 | `suggest` set and not an anchor helper key | rename the key |

**fix JSON** (`report.BuildFixResult` → `report.FixResult`, written by `report.WriteFix`; the GUI fix bindings return the same struct):

| Field | Type | Notes |
|---|---|---|
| `file` | string | config path as given |
| `output` | string | path written, or the path it would be written to (`--dry-run`, nothing to fix) |
| `written` | bool | the output file was written |
| `not_written_reason` | string | `dry-run` (edits exist, not written) / `nothing-to-fix` / `""` when written |
| `edits[]` | object | `id`, `line` (original file), `path`, `before`, `after` — whole lines; `after` is `""` for a deleted line. One per finding ID and line, sorted by line |
| `skipped[]` | object | `id`, `line` (original file; for `other-file` a line of that other file), `path`, `reason`, `reason_text` (Chinese, `messages_zh.go`) |
| `skipped[].reason` | string | `shared-node` `multiline` `layout` `key-exists` `other-file` `rename-breaks-load` `pass-limit` |
| `diff[]` | object | hunks: `old_start`, `old_lines`, `new_start`, `new_lines`, `lines[]{op, text, no_newline?}`; `op` is `" "`, `"-"` or `"+"`; 3 lines of context |
| `before` / `after` | object | per-severity counts of the config / the fixed text (same shape as `summary`) |
| `remaining[]` | object | findings of the fixed text, same element type as `findings[]` (incl. `auto_fix`). When there are edits, locations in the config carry `output` as `file` (their lines are lines of the fixed text) |

Arrays are never `null`. **fix text** (`writeFixText`), in order: header; `已修改（N 处）` with `ID  file:line`, `修改前：` / `修改后：` (trimmed lines; `（删除这一行）` for deletions) or `没有可以自动修改的项。`; `未自动修改（N 处）` with reason texts (if any); `差异：` + `fix.Unified(file, output, diff)` (if any); `修复后仍存在的检查结果：` + the remaining findings rendered like `check`, then `修复前：` / `修复后：` summary lines (no edits: `检查结果（配置未修改）：` + `汇总：`); last line `已写入：<output>…` or the not-written reason.

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
| `-o` / `--output` / `--force` / `--dry-run` with a subcommand other than `fix` | arg error on stderr | 2 |
| fix: fixed config has no error/high/medium finding (incl. nothing to fix, `--dry-run`) | report | 0 |
| fix: fixed config still has an error/high/medium finding | report (file written unless `--dry-run`) | 1 |
| fix: output exists and no `--force` (`exists`) | error on stderr, nothing written | 2 |
| fix: output is the config itself, any alias by `os.SameFile` (case, `.`/`..`, hard / symbolic link), even with `--force` (`same-file`) | error on stderr, nothing written | 2 |
| fix: fixed text does not load or has an error finding the config did not have (`verify`) | error on stderr, nothing written | 2 |
| fix: temp file / sync / rename failed, output is a directory (`write`) | error on stderr, temp file removed | 2 |
| `--format` not text/json | error on stderr | 2 |
| file unreadable | read error on stderr | 2 |
| invalid YAML, duplicate keys, non-mapping root | parse error on stderr | 2 |
| age-encrypted file (armor or binary header at start) | CFG-02 finding on stdout (check, trace and fix alike) | 2 |
| rule-set / GeoSite data missing or corrupt | finding/step marked unknown + note; never fails | 0/1 by findings |

"error" severity = a config problem that makes mihomo itself refuse to load (DNS-06, DNS-07, DNS-08, CFG-03).

## 5. Good / Base / Bad Cases

- Good: `testdata/ac3-recommended.yaml` → only info findings, exit 0.
- Base: `testdata/ac4-clash-verge-override.yaml` → DNS-02 medium, exit 1.
- Bad: `testdata/ac1-geoip-without-no-resolve.yaml` → RULE-01 high + DNS-02 medium, exit 1; `testdata/ac12-encrypted.yaml` → CFG-02, exit 2.
- fix Good: `fix examples/leaky-config.yaml -o out.yaml` → 2 edits (RULE-01 line 15, DNS-02 line 22), written, exit 0; `check out.yaml` → exit 0.
- fix Base: `testdata/ac15-fix-mixed.yaml` → 8 edits over several passes, CFG-01 `dns.enhanced-mod` skipped as `key-exists`, exit 1; as CRLF + BOM only the same characters change. `testdata/ac3-recommended.yaml` (info only) → nothing to fix, exit 0.
- fix Bad: `testdata/ac15-fix-skips.yaml` → anchor / merge (`shared-node`) and multi-line (`multiline`) items skipped, the other two fixed, exit 1; `-o` pointing at the config → exit 2.

## 6. Tests Required

- `cmd/dnsnitch/main_test.go`: one e2e test per acceptance case asserting finding IDs, severities, line numbers of trigger/affected/resolver locations, and exit code.
- `internal/report/report_test.go`: `TestProseOnlyInMessages` (no Chinese outside `messages_zh.go`), JSON field presence, both resolver wordings.
- Any new flag or exit-code rule needs a `run(...)` test with captured stdout/stderr.
- fix (`cmd/dnsnitch/main_test.go`, `TestFix*`): `--dry-run` writes nothing (also with `-o`); the `-o` output checks clean and the original bytes are unchanged; exact output bytes for `ac15-fix-mixed.yaml` as LF and as generated CRLF + BOM; skip reasons; existing output with and without `--force`; the config and a case-different alias as output (with and without `--force`); injected `ErrVerify` writes nothing; all `FixResult` fields; `auto_fix` on every check finding; fix-only flags on other subcommands → 2.
- `internal/report/fix_test.go`: `BuildFixResult` (reasons, relocation of remaining locations, empty arrays), text order, every skip reason and fix error kind has its own text.
- `internal/app/fix_test.go`: same-file aliases, exists / force, atomic write failure leaves no temp file, config changed after planning, real verification failure.

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

#### Wrong
```go
// fix: re-serializing the YAML, or writing in place
out, _ := yaml.Marshal(node)
os.WriteFile(file, out, 0o644)
```
#### Correct
```go
// fix: byte-level edits planned by internal/fix, written by app.SaveFix to a new file
out, kind, err := planFix(file, o.home)
if kind, err := app.SaveFix(out, dest, o.force); kind != app.ErrNone { /* stderr, exit 2 */ }
report.WriteFix(stdout, o.format, report.BuildFixResult(file, dest, out.Plan, out.Before, out.After, true))
return report.ExitCode(out.After)
```
