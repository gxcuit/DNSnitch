# Component Guidelines

> How Vue components are written in `gui/frontend/src/components/`.

---

## Component Structure

- `<script setup lang="ts">` + `<template>` + `<style scoped>`; every component in this repo follows it.
- Props via `defineProps<{...}>()` with generated types (`report.FindingView`, `model.Location`, `main.SourceFile`); events via typed `defineEmits<{...}>()`.
- Components are presentational: no direct calls to `wailsjs/go/...` bindings. `App.vue` gets everything from `useCheck()` and passes it down.

## Props Conventions

- Pass backend objects as-is; don't reshape findings into new view models.
- Pass `labels: report.Labels | null` down and render codes with `label(labels, group, code)`; `null` labels must still render (falls back to the code).

## Styling Patterns

- Colors only through CSS variables from `src/style.css` (`--bg`, `--panel`, `--fg`, `--accent`, `--sev-*`, `--highlight` …). Dark mode redefines the variables under `@media (prefers-color-scheme: dark)`; components never hard-code colors.
- No UI component library.
- Severity is shown as **text plus color** (badge text from labels), never color alone.

## Performance

- `SourceView` renders only visible lines with a fixed row height (`ROW = 20` px) because rule-set files can be large; keep the fixed height if you change its CSS.
- Location lists show the first 8 entries with a "show all" toggle.

## Accessibility

- Interactive elements are real `<button type="button">`; decorative elements (spinner) carry `aria-hidden="true"`.
- Disabled states use the `disabled` attribute (e.g. 重新检查 without a file or while loading).

## Display-only commands

`SystemStatusBar` shows fix commands (e.g. the `reg add …` line) as selectable `<code>` text under "仅供参考，本工具不会执行". Never add a button that runs, or copies-and-runs, a command: the system inspection is strictly read-only (backend `quality-guidelines.md`, `internal/platform` read-only tests).

## Fix preview (the only write)

The only thing the GUI ever writes is the fixed config, as a **new file**: `SummaryBar` shows 「自动修复（N 项）」 (N = findings with `auto_fix`), `FixPreview` (modal, `role="dialog"`, Esc / 关闭 / backdrop click close it) renders the backend `report.FixResult` as-is — edits, skipped items with `reason_text`, the diff (`@@` header, `+` / `-` / context rows with old / new line numbers, `\` no-newline row, horizontally scrollable), before / after severity chips — and emits `save` / `close`. Diff colors use only `--diff-add-*`, `--diff-del-*`, `--diff-hunk-*` and `--backdrop` from `style.css`; `+` / `-` markers stay so color is never the only signal. The component never passes content or a path anywhere: saving is `useFix().save()` → `SaveFix()` (backend `gui-bindings.md`).

## Common Mistakes

- Re-sorting or filtering `result.findings` in a component — order is the backend's contract (same as CLI).
- Writing Chinese finding/severity text in a component instead of using backend labels.
