# GUI Binding Contract (`gui/app.go`)

> Contract between the Go side of the Wails app and the Vue frontend. Wails generates `gui/frontend/wailsjs/go/main/App.{js,d.ts}` and `wailsjs/go/models.ts` from these Go types — regenerate (`wails generate module`) and commit after any change.

## 1. Scope / Trigger

- Trigger: methods on `*App` are an API callable from the WebView, and `ReadSource` reads local files on the user's machine.

## 2. Signatures

```go
func (a *App) ChooseFile() (string, error)              // native open dialog; "" when cancelled
func (a *App) Check(path string) GUIResult              // absolutizes path, app.RunCheck(path, "")
func (a *App) ReadSource(path string) (SourceFile, error)
func (a *App) Labels() report.Labels                   // display names for codes
func (a *App) SystemStatus() report.StatusView         // read-only TUN / smart name resolution status, same as `dnsnitch status --format json`
```

`SystemStatus` is independent of `Check` (no file needed); the frontend calls it once on mount and from the 刷新 button via `useSystemStatus()`. Its remedy text is display-only: no binding may change system settings.

File drop is NOT a binding: the frontend calls the JS runtime `OnFileDrop(cb, false)` (only the JS call registers the window `drop` listener in Wails v2.17.1), then calls `Check(paths[0])`. `options.DragAndDrop{EnableFileDrop: true}`; keep `DisableWebViewDrop: false` (true blocks external drops in WebView2).

## 3. Contracts

| Type | Fields |
|---|---|
| `GUIResult` | `result?: report.CheckResult` (same struct as CLI JSON) **or** `error?: GUIError` — exactly one is set |
| `GUIError` | `kind`: `read` / `parse` / `encrypted`; `message`: Chinese text from `report.ErrorText` |
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

Concurrency: bound methods run concurrently. `ctx` is set once in `startup`; `seq`/`allowed` are guarded by `mu`; `allowed` is replaced, never mutated.

## 5. Good / Base / Bad Cases

- Good: `Check(ac1 fixture)` → `result.summary = {high:1, medium:1}`; `ReadSource(same path)` line 44 = `  - GEOSITE,youtube,…`.
- Base: `Check(ac12-encrypted.yaml)` → `error.kind = "encrypted"` (the CLI prints a CFG-02 finding for the same file instead).
- Bad: `ReadSource("C:\\…\\config.yaml:hidden")` → refused.

## 6. Tests Required

- `gui/app_test.go`: Check success / read / parse / encrypted; whitelist replacement by a later Check; stale results ignored; size and binary limits; symlink.
- `gui/app_windows_test.go`: streams, `\\?\` / `\\.\`, trailing dot/space, 8.3 names, junctions.
- `gui/prose_test.go`: no Chinese in non-test `gui/*.go`.
- UI acceptance via `wails dev` + browser at `http://localhost:34115`: trigger the real drop path with `window.runtime.EventsEmit("wails:file-drop", x, y, [absPath])`; compare `await window.go.main.App.Check(p)` with `dnsnitch check --format json` (same findings + summary).

## 7. Wrong vs Correct

#### Wrong
```go
// Go-only drop handling: never fires in Wails v2.17.1, the JS listener is missing
runtime.OnFileDrop(ctx, func(x, y int, paths []string) { runtime.EventsEmit(ctx, "file-dropped", paths) })
// whitelist by string comparison only: "C:\cfg.yaml:hidden" and 8.3 aliases slip through
if path == a.config { return os.ReadFile(path) }
```
#### Correct
```ts
OnFileDrop((_x, _y, paths) => onDropped(paths), false) // frontend registers the drop listener
```
```go
f, err := a.openAllowed(path) // rejects stream syntax, then compares f.Stat() with each allowed file via os.SameFile
```
