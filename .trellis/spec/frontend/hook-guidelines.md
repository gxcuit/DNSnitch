# Composable Guidelines

> Vue composables (this project's equivalent of hooks).

---

## Custom Composable Patterns

- One composable, `useCheck()` in `src/composables/useCheck.ts`, owns all app state and all calls to Go bindings (`Check`, `ChooseFile`, `ReadSource`, `Labels`).
- Add a new composable only for an independent concern; don't split `useCheck` state across several composables that need to stay in sync.

## Data Fetching (calling Go bindings)

- Every async binding call is guarded by a sequence number (`checkSeq`, `sourceSeq`): results of a superseded request are dropped. Copy this pattern for any new async call.
- Binding failures (rejected Promise) become a visible error with kind `INTERNAL_ERROR`; config problems arrive as `GUIResult.error` and are shown as-is.
- Use `shallowRef` for large backend payloads (`CheckResult`, `SourceFile`); they are replaced, not mutated.

## Naming Conventions

- `useXxx()` returning refs and action functions (`check`, `choose`, `recheck`, `onDropped`, `selectLocation`).

## Common Mistakes

- Awaiting a binding and writing its result without checking that it is still the latest request → stale results overwrite newer ones when the user opens files quickly.
