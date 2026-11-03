# Error Handling

> How `dnsleak` handles bad input and internal failures.

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

---

## Patterns

- Binary decoders (`.mrs`, GeoSite.dat) wrap their work in a recover-to-error boundary and cap decompressed size.
- Error text shown to users comes from `report.ErrorText(kind, detail)` (prose in `messages_zh.go`).

---

## Common Mistakes

- Returning exit 1 for unreadable input: exit 1 means "the config has leak/load problems", exit 2 means "could not analyze".
- Letting an unknown rule-set silently count as "no trigger": it must produce an info-level finding saying the content could not be read.
