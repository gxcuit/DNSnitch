# State Management

> No Pinia, no router: all state lives in `useCheck()`.

---

## State Categories

| State | Kind | Notes |
|---|---|---|
| `currentFile`, `loading`, `notice` | `ref` | `notice` holds hints such as "only the first dropped file was checked" |
| `result` (`report.CheckResult`), `error` (`main.GUIError`) | `shallowRef` | exactly one is set after a Check |
| `labels` (`report.Labels`) | `shallowRef` | loaded once at startup; may stay `null` |
| `selected`, `sourcePath`, `source`, `highlightLine`, `reveal` | refs | source view; `reveal` is bumped to re-scroll even to the same line |
| `isClean` | `computed` | no error/high/medium in `result.summary` |

## When to Use Global State

Never for this app: state is created once in `App.vue` via `useCheck()` and passed down as props. If a second window or page is ever added, revisit (Pinia) rather than adding module-level singletons.

## Server State

The Go backend is the source of truth. The frontend never derives findings, severities or counts; it only selects and displays.

## Common Mistakes

- Keeping a stale `source` when switching files: `resetSource()` must run when a new Check starts.
- Mutating `result.value` in place — replace it so `shallowRef` triggers updates.
