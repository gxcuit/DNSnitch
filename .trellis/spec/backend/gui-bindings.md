# GUI Binding Contract (`gui/app.go`)

> Contract between the Go side of the Wails app and the Vue frontend. Wails generates `gui/frontend/wailsjs/go/main/App.{js,d.ts}` and `wailsjs/go/models.ts` from these Go types — regenerate (`wails generate module`) and commit after any change.

## 1. Scope / Trigger

- Trigger: methods on `*App` are an API callable from the WebView, `ReadSource` reads local files on the user's machine, and `SaveFix` writes one.

## 2. Signatures

```go
func (a *App) ChooseFile() (string, error)              // native open dialog; "" when cancelled
func (a *App) Check(path string) GUIResult              // absolutizes path, app.RunCheck(path, "")
func (a *App) ReadSource(path string) (SourceFile, error)
func (a *App) Labels() report.Labels                   // display names for codes
func (a *App) SystemStatus() report.StatusView         // read-only TUN / smart name resolution status, same as `dnsnitch status --format json`
func (a *App) PlanFix() GUIFixResult                   // app.PlanFix on the config of the latest Check (home ""), nothing written; stores the outcome
func (a *App) SaveFix() GUISaveResult                  // native save dialog, then app.SaveFix(stored outcome, path, force=true)
```

`PlanFix` / `SaveFix` take **no parameters**: the frontend can choose neither the content to write nor an arbitrary path (PRD R4.5). The file is the config of the latest started `Check` (`a.config`, set together with `seq`), the content is the `FixOutcome` computed by `PlanFix` and kept under `mu` (`a.planned`), and the path comes only from the native save dialog. Do not add a binding that accepts a path or text to write.

- `PlanFix`: clears the stored outcome, runs `app.PlanFix(config, "")`, renders it with `report.BuildFixResult(..., written=false)` (same JSON as `dnsnitch fix --dry-run --format json`; `file` / `output` are absolute here) and stores the outcome only if no `Check` or other `PlanFix` started meanwhile. Any `Check` clears it, so a stored plan always belongs to the latest Check.
- `SaveFix`: needs a stored outcome with edits (else `no-fix`); refuses a config whose bytes no longer match `SourceHash` **before** opening the dialog (`changed`); opens `saveDialog` (DefaultDirectory = config dir, DefaultFilename = base of `app.DefaultFixOutput`, title `report.GUISaveDialogTitle`, YAML + all-files filters); `""` → `{cancelled: true}`; re-checks that the stored outcome is still the same one (a Check during the dialog → `no-fix`); then `app.SaveFix(out, abs(path), true)` — force because the native dialog already confirmed overwriting; `app.SaveFix` still refuses the config itself (`os.SameFile`) and re-checks the hash right before the atomic write. Success → `{path}` (absolute); the frontend then calls `Check(path)`, which moves the `ReadSource` whitelist to the new file as for any Check.
- `saveDialog` is a package-level variable (default `runtime.SaveFileDialog`), injectable like `inspectSystem`, so tests never open a window. The native dialogs confirm overwriting (Windows `IFileSaveDialog` default `FOS_OVERWRITEPROMPT`, GTK `do_overwrite_confirmation`, macOS `NSSavePanel`).

`SystemStatus` is independent of `Check` (no file needed); the frontend calls it once on mount and from the 刷新 button via `useSystemStatus()`. Its remedy text is display-only: no binding may change system settings.

File drop is NOT a binding: the frontend calls the JS runtime `OnFileDrop(cb, false)` (only the JS call registers the window `drop` listener in Wails v2.17.1), then calls `Check(paths[0])`. `options.DragAndDrop{EnableFileDrop: true}`; keep `DisableWebViewDrop: false` (true blocks external drops in WebView2).

## 3. Contracts

| Type | Fields |
|---|---|
| `GUIResult` | `result?: report.CheckResult` (same struct as CLI JSON) **or** `error?: GUIError` — exactly one is set |
| `GUIError` | `kind`: `read` / `parse` / `encrypted` (Check, PlanFix), `verify` (PlanFix), `same-file` / `exists` / `write` / `changed` (SaveFix), `no-config` (PlanFix before any Check), `no-fix` (SaveFix without a stored plan with edits); `message`: Chinese text from `report.ErrorText`. `internal` is frontend-only (a rejected binding call) |
| `GUIFixResult` | `result?: report.FixResult` (same struct as `dnsnitch fix --format json`; `written = false`, `not_written_reason` = `dry-run` / `nothing-to-fix`) **or** `error?: GUIError` — exactly one is set |
| `GUISaveResult` | exactly one of `path?: string` (absolute, written), `cancelled?: true` (dialog cancelled, nothing written), `error?: GUIError` |
| `SourceFile` | `path`; `lines[]` without terminators (`lines[i]` = line i+1, `\r` stripped) |
| `report.Labels` | maps `severity`, `role`, `level`, `resolver_source`, `text` (keys `LabelText*`) code → display name |

## 4. Validation & Error Matrix (`ReadSource`)

| Input | Result |
|---|---|
| config of the latest `Check` (even if that Check failed to parse) | allowed |
| absolute `file` of any location in the latest `Check` result | allowed |
| aliases of an allowed file: `file.`, `\\?\` prefix, 8.3 name, symlink, junction, other case/separators | allowed (identity via `os.SameFile` on the opened handle) |
| relative path, empty path, directory, any other file | refused, generic "not allowed" text (no existence leak) |
| NTFS stream syntax (`file:stream`, `::$DATA`) | refused |
| allowed file > 32 MB | refused (`ErrKindSourceRead`) |
| allowed file containing NUL (e.g. `.mrs`) | refused (`ErrKindSourceBinary`) |
| result of a superseded `Check` finishing late | ignored; whitelist always belongs to the latest started Check |

### Error matrix (`PlanFix` / `SaveFix`)

| Situation | Result | Written |
|---|---|---|
| `PlanFix` before any `Check` | `error.kind = "no-config"` | — |
| latest Check's config unreadable / invalid / encrypted | `error.kind = "read"` / `"parse"` / `"encrypted"` | — |
| fixed text does not load or has a new `error` finding | `error.kind = "verify"` (outcome not stored) | — |
| no fixable finding | `result` with empty `edits`, `not_written_reason = "nothing-to-fix"`; `SaveFix` → `no-fix` without a dialog | no |
| `SaveFix` without `PlanFix`, after a later `Check` (also of the same file), or with a `Check` / `PlanFix` started while the dialog was open | `error.kind = "no-fix"` | no |
| config edited after `PlanFix` (before or during the dialog) | `error.kind = "changed"`, text asks to re-check | no |
| dialog cancelled | `cancelled: true`; stored plan kept (the user may save again) | no |
| dialog returns the config itself (any alias: case, `.` segments, `/` separators, links) | `error.kind = "same-file"` | no |
| dialog returns another existing file | overwritten (the dialog confirmed it) | yes |
| dialog fails / temp file, write or rename fails | `error.kind = "write"`, temp file removed | no |

Concurrency: bound methods run concurrently. `ctx` is set once in `startup`; `seq` / `allowed` / `config` / `fixSeq` / `planned` are guarded by `mu`; `allowed` is replaced, never mutated; `SaveFix` does not hold `mu` while the dialog is open.

## 5. Good / Base / Bad Cases

- Good: `Check(ac1 fixture)` → `result.summary = {high:1, medium:1}`; `ReadSource(same path)` line 44 = `  - GEOSITE,youtube,…`.
- Base: `Check(ac12-encrypted.yaml)` → `error.kind = "encrypted"` (the CLI prints a CFG-02 finding for the same file instead).
- Bad: `ReadSource("C:\\…\\config.yaml:hidden")` → refused.
- Good: `Check(examples/leaky-config.yaml)` → summary bar shows 「自动修复（2 项）」; `PlanFix()` → 2 edits (RULE-01 `,no-resolve`, DNS-02 delete `8.8.8.8`), one hunk `@@ -12,12 +12,11 @@`, `after` without high / medium; `edits` / `diff` / `before` / `after` / `remaining` identical to `dnsnitch fix examples/leaky-config.yaml --dry-run --format json`.
- Bad: `SaveFix()` after the config was edited post-preview → `changed`; the dialog does not even open.

## 6. Tests Required

- `gui/app_test.go`: Check success / read / parse / encrypted; whitelist replacement by a later Check; stale results ignored; size and binary limits; symlink.
- `gui/app_test.go` (fix, `saveDialog` injected): `PlanFix` / `SaveFix` before any Check; `PlanFix` on `examples/leaky-config.yaml` (2 edits, `written = false`, same JSON as `report.BuildFixResult` of `app.PlanFix`); read / parse / encrypted; nothing to fix; save writes the chosen file with the original unchanged, dialog options, then `Check(path)` moves the whitelist; overwrite of a confirmed existing file; cancelled; dialog error; config changed before (dialog not opened) and during the dialog; same-file incl. case / separator variants on Windows; a later Check (other file, same file, during the dialog) invalidates the plan.
- `gui/app_windows_test.go`: streams, `\\?\` / `\\.\`, trailing dot/space, 8.3 names, junctions.
- `gui/prose_test.go`: no Chinese in non-test `gui/*.go`.
- UI acceptance via `wails dev` + browser at `http://localhost:34115`: trigger the real drop path with `window.runtime.EventsEmit("wails:file-drop", x, y, [absPath])`; compare `await window.go.main.App.Check(p)` with `dnsnitch check --format json` (same findings + summary). Fix: drop `examples/leaky-config.yaml`, click 「自动修复（2 项）」, check the preview in light and dark mode, compare `await window.go.main.App.PlanFix()` with `dnsnitch fix ... --dry-run --format json`; open the preview of a scratch copy, edit the copy, click save → inline `changed` error. Saving an unchanged config opens the native dialog on the desktop window (not automatable from the browser): confirm one save manually in a `wails build` binary.

## 7. Wrong vs Correct

#### Wrong
```go
// Go-only drop handling: never fires in Wails v2.17.1, the JS listener is missing
runtime.OnFileDrop(ctx, func(x, y int, paths []string) { runtime.EventsEmit(ctx, "file-dropped", paths) })
// whitelist by string comparison only: "C:\cfg.yaml:hidden" and 8.3 aliases slip through
if path == a.config { return os.ReadFile(path) }
// fix binding that trusts the frontend: any page script could write any file
func (a *App) SaveFix(path, content string) error { return os.WriteFile(path, []byte(content), 0o644) }
```
#### Correct
```ts
OnFileDrop((_x, _y, paths) => onDropped(paths), false) // frontend registers the drop listener
```
```go
f, err := a.openAllowed(path) // rejects stream syntax, then compares f.Stat() with each allowed file via os.SameFile
func (a *App) SaveFix() GUISaveResult // content = stored PlanFix outcome, path = native save dialog only
```
