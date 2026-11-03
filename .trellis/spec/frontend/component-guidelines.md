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

## Common Mistakes

- Re-sorting or filtering `result.findings` in a component — order is the backend's contract (same as CLI).
- Writing Chinese finding/severity text in a component instead of using backend labels.
