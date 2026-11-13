# Error Handling

> How `dnsnitch` handles bad input and internal failures.

---

## Principles

1. **The tool never panics on user input.** Malformed rules, empty files, non-mapping YAML, corrupt rule-set caches and circular references are reported or skipped.
2. **Three outcomes only**: findings (exit 0/1), a fatal input problem (exit 2), or a usage error (exit 2). The full matrix is in `cli-contract.md` §4.
3. **Missing data is not an error.** Absent/corrupt rule-set or GeoSite files make the affected step `unknown` and add a note explaining the impact on the conclusion.

---

## Error Types

| Type | Package | Meaning | CLI result |
|---|---|---|---|
| `config.ErrEncrypted` | config | age-encrypted file | CFG-02 finding, exit 2 |
| `*config.ParseError` | config | invalid YAML / duplicate key / bad root | parse error on stderr, exit 2 |
| other `config.Load` error | config | read failure | read error on stderr, exit 2 |
| rule-set / GeoSite load error | ruledata | missing or corrupt data | stored as reason; caller marks unknown |

Match with `errors.Is` / `errors.As`; never compare error strings.

### `app.ErrorKind`

`internal/app` classifies every failure into an `ErrorKind`; the CLI maps it to `report.ErrKind*` (same strings) and `report.ErrorText(kind, detail)`, and always exits 2.

| Kind | Returned by | Meaning | `ErrorText` detail |
|---|---|---|---|
| `read` | RunCheck, LoadEnv, PlanFix, SaveFix | config unreadable (SaveFix: config vanished before saving) | the error |
| `parse` | RunCheck, LoadEnv, PlanFix | invalid YAML / duplicate key / non-mapping root | the error |
| `encrypted` | RunCheck, LoadEnv, PlanFix | age-encrypted (CLI prints CFG-02 instead of an error) | — |
| `verify` | PlanFix | the fixed text does not load, or has an `error` finding (ID + first location path) the config did not have; the outcome is still returned for display, nothing may be written | the error |
| `same-file` | SaveFix | output is the config itself (`os.SameFile`: case, `.`/`..`, hard / symbolic links), checked before `exists` so `--force` cannot bypass it | output path |
| `exists` | SaveFix | output exists (a file, not a directory) and `force` is false | output path |
| `write` | SaveFix | temp file / write / sync / rename failed, output is a directory (with or without `force`); the temp file is removed | the error |
| `changed` | SaveFix | the config bytes differ from `FixOutcome.SourceHash` (edited after planning; GUI preview → save) | config path |

`fix.Build` itself never fails on odd input: a node it cannot edit safely becomes a `fix.Skip` with a reason code (`shared-node`, `multiline`, `layout`, `key-exists`, `other-file`, `rename-breaks-load`, `pass-limit`), shown with a text from `messages_zh.go`; it returns an error only when the original does not load or an internal step fails (PlanFix reports that as `verify`).

---

## Patterns

- Binary decoders (`.mrs`, GeoSite.dat) wrap their work in a recover-to-error boundary and cap decompressed size.
- Error text shown to users comes from `report.ErrorText(kind, detail)` (prose in `messages_zh.go`).

---

## Common Mistakes

- Returning exit 1 for unreadable input: exit 1 means "the config has leak/load problems", exit 2 means "could not analyze".
- Letting an unknown rule-set silently count as "no trigger": it must produce an info-level finding saying the content could not be read.
- Writing the fix output directly with `os.WriteFile`: a failure leaves half a file. `app.SaveFix` writes a temp file in the output directory, syncs it and renames it over the output.
- Mapping a new `ErrorKind` to the default (read) error text in the CLI: every kind needs its own `ErrorText` case.
