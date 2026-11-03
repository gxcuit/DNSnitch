# Quality Guidelines

> Code standards for `dnsleak`.

---

## Required Checks (all must pass before commit)

```bash
export PATH="/c/Program Files/Go/bin:$PATH"   # Windows dev box: Go is not on the default PATH of agent shells
gofmt -l .                                     # must print nothing
go vet ./...
go test ./...
GOOS=linux  GOARCH=amd64 go build ./...
GOOS=darwin GOARCH=arm64 go build ./...
```

When `gui/` or anything it imports changed, also run:

```bash
export PATH="/c/Program Files/Go/bin:$HOME/go/bin:$PATH"   # wails CLI lives in $HOME/go/bin
(cd gui && gofmt -l . && go vet ./... && go test ./...)
(cd gui/frontend && npx vue-tsc --noEmit && npm run build)
(cd gui && wails build)                                     # → gui/build/bin/dnsleak-gui.exe (git-ignored)
```

Delete any binary you build outside ignored dirs (`*.exe`, `/dnsleak` are git-ignored but should not be left around). Exception: the user may rely on `dnsleak.exe` in the repo root as their CLI build — rebuild it rather than leaving it deleted.

> **Gotcha (Windows dev box)**: Smart App Control can block freshly built unsigned binaries (including `go test` binaries) for a few minutes with "An Application Control policy has blocked this file". Retry; it is not a code failure.

> **Gotcha (line endings)**: global `core.autocrlf=true` is overridden by `.gitattributes` `* text=auto eol=lf`. Without it, checkouts turn `.go` files into CRLF and `gofmt -l` flags every file.

---

## Conventions

### Convention: all user-facing prose lives in `internal/report/messages_zh.go`

**Why**: decision D9 — Chinese output now, English later by adding `messages_en.go` without touching checks.
Checks return `model.Finding{ID, Severity, Args, Notes{Key, Args}, Locations}`; `Args` hold config text or language-neutral codes only. `TestProseOnlyInMessages` fails if Chinese text appears in any other non-test `.go` file.

### Convention: offline and OS-agnostic

- Never fetch rule-providers, GeoSite or subscriptions. Missing data → mark unknown + add a note; never error out.
- No OS APIs, no build tags in current packages; paths via `path/filepath` only; accept `\r\n` input.

### Convention: model mihomo, don't guess

Every behavior the checker relies on must be listed in `mihomo-semantics.md` with its source. If a doc/blog disagrees with mihomo source, source wins.

### Convention: test data is generated, not committed

`.mrs` and `GeoSite.dat` test inputs are built in-memory by `internal/testutil` (using mihomo's `component/trie` / `component/cidr` writers and `protowire`). Do not commit binary fixtures.

---

## Forbidden Patterns

### Don't: import mihomo packages beyond `component/trie` and `component/cidr`

**Why**: mihomo's go.mod has `replace google.golang.org/protobuf => metacubex/protobuf-go`, which does not apply when mihomo is a dependency; `component/geodata` and most other packages will not build correctly. GeoSite.dat is decoded by hand with `protowire`.

### Don't: trust sizes read from binary files

**Problem**: mihomo's `.mrs` readers allocate slices sized by values in the file; a corrupt file can panic or exhaust memory.
**Instead**: decompress with a size cap, validate segment lengths first, and convert panics into a parse error (see `ruledata/provider.go`).

### Don't: lower-case regex patterns

GeoSite `Regex` entries must keep their case (`\D` ≠ `\d`); only non-regex values are lower-cased.

---

## Common Mistakes

### Common Mistake: recursion over user-defined graphs without a cycle guard

**Symptom**: `trace` hung forever on circular `sub-rules`.
**Fix/Prevention**: any walk over sub-rules, proxy-groups or rule references needs a `seen` set or memo; add a circular-input test for every new walker.

### Common Mistake: reporting only the worst resolver in a merged finding

**Symptom**: a RULE-0x finding said all affected domains went to plaintext DNS when only one rule did.
**Fix**: severity = worst item, but each `affected` location carries its own `Resolver` info and all distinct resolver servers are listed.

### Common Mistake: typo suggestions on YAML anchor helper keys

Top-level keys that only define an anchor (`u: &u ...`) must not get a medium-severity "did you mean" CFG-01; they are reported low with an explanation.
