# Quality Guidelines

> Frontend checks and rules for `gui/frontend/`.

---

## Required Checks

```bash
cd gui/frontend && npm ci            # lock file is committed
npx vue-tsc --noEmit                 # type check (also part of npm run build)
npm run build                        # vue-tsc + vite build into dist/
cd .. && wails build                 # full app, regenerates wailsjs/
```

There is no frontend unit-test runner. Behavior is verified through Go binding tests (`gui/app_test.go`) plus browser acceptance in `wails dev` (see backend `gui-bindings.md` §6).

## Forbidden Patterns

- Duplicating backend prose (finding text, severity / role / level names, error messages) in the frontend.
- Re-sorting or filtering findings.
- Calling bindings from components instead of `useCheck()`.
- Hard-coded colors outside `style.css` variables; color as the only severity signal.
- UI component libraries or state libraries without a planning decision.

## Required Patterns

- Sequence-guard every async binding call.
- Light and dark themes via `prefers-color-scheme` variables.
- Loading overlay while a Check runs; error box for `GUIResult.error`; the window stays usable after errors.

## Code Review Checklist

- [ ] `vue-tsc --noEmit` and `npm run build` pass
- [ ] `wailsjs/` regenerated and committed if Go bindings changed
- [ ] No new Chinese strings outside `src/i18n/zh.ts`
- [ ] Verified in `wails dev` + browser: drop via `window.runtime.EventsEmit("wails:file-drop", x, y, [path])`, location click scrolls + highlights, dark mode
