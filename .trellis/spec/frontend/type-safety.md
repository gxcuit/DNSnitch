# Type Safety

> TypeScript types come from Go via Wails code generation.

---

## Type Organization

- Backend types are imported from the generated module: `import type {main, model, report} from '../../wailsjs/go/models'` and bindings from `wailsjs/go/main/App`.
- Never hand-write a duplicate interface for a backend struct. Change the Go struct, run `wails generate module` (or `wails dev` / `wails build`), commit the regenerated `wailsjs/`.
- Frontend-only types (e.g. `Selection`) live next to the code that owns them (`useCheck.ts`).

## Validation

- Data from bindings is trusted to match the generated types (same build); the frontend does not re-validate it.
- Optional fields (`location.resolver`, `GUIResult.result` / `.error`) must be narrowed before use.

## Common Patterns

- Codes are typed as `string` in generated models; keep known code lists as `as const` arrays (`SEVERITIES` in `labels.ts`).

## Forbidden Patterns

- Editing files under `wailsjs/` by hand (they are overwritten on the next build).
- `any` for backend payloads.
