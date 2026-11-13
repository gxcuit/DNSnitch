package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"dnsnitch/internal/app"
	"dnsnitch/internal/report"
)

const ruleSetConfig = `proxies:
  - name: node
    type: ss
    server: node.example.com
    port: 8388
    cipher: aes-128-gcm
    password: example
proxy-groups:
  - name: PROXY
    type: select
    proxies: [node]

rule-providers:
  telegram:
    type: file
    behavior: classical
    format: text
    path: ./rs/telegram.list

rules:
  - RULE-SET,telegram,PROXY
  - MATCH,PROXY

dns:
  enable: true
  nameserver:
    - 223.5.5.5
`

// setup writes a config that references a local rule-set file, plus an
// unrelated file next to it. It returns the config, rule-set and other path.
func setup(t *testing.T) (cfg, rs, other string) {
	t.Helper()
	dir := t.TempDir()
	cfg = filepath.Join(dir, "config.yaml")
	rs = filepath.Join(dir, "rs", "telegram.list")
	other = filepath.Join(dir, "secret.txt")
	write(t, cfg, strings.ReplaceAll(ruleSetConfig, "\n", "\r\n"))
	write(t, rs, "IP-CIDR,91.108.4.0/22\nDOMAIN-SUFFIX,telegram.org\n")
	write(t, other, "secret\n")
	return cfg, rs, other
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCheckOK(t *testing.T) {
	a := NewApp()
	r := a.Check(filepath.Join("..", "testdata", "ac1-geoip-without-no-resolve.yaml"))
	if r.Error != nil || r.Result == nil {
		t.Fatalf("result = %+v", r)
	}
	if !filepath.IsAbs(r.Result.File) {
		t.Errorf("file must be absolute: %s", r.Result.File)
	}
	if s := r.Result.Summary; s.High != 1 || s.Medium != 1 || s.Error != 0 {
		t.Errorf("summary = %+v", s)
	}
	if f := r.Result.Findings[0]; f.ID != "RULE-01" || f.Severity != "high" || f.Message == "" {
		t.Errorf("first finding = %+v", f)
	}
}

func TestCheckErrors(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	write(t, bad, "a: [1, 2\n")
	for _, c := range []struct{ path, kind string }{
		{filepath.Join(dir, "missing.yaml"), "read"},
		{bad, "parse"},
		{filepath.Join("..", "testdata", "ac12-encrypted.yaml"), "encrypted"},
	} {
		r := NewApp().Check(c.path)
		if r.Result != nil || r.Error == nil || r.Error.Kind != c.kind || r.Error.Message == "" {
			t.Errorf("%s: %+v", c.path, r)
		}
	}
}

func TestReadSourceWhitelist(t *testing.T) {
	cfg, rs, other := setup(t)
	a := NewApp()

	if _, err := a.ReadSource(cfg); err == nil {
		t.Errorf("reading before any Check must fail")
	}

	r := a.Check(cfg)
	if r.Result == nil {
		t.Fatalf("check failed: %+v", r.Error)
	}
	referenced := false
	for _, f := range r.Result.Findings {
		for _, l := range f.Locations {
			if filepath.Clean(l.File) == filepath.Clean(rs) {
				referenced = true
			}
		}
	}
	if !referenced {
		t.Fatalf("fixture must reference the rule-set file: %+v", r.Result.Findings)
	}

	src, err := a.ReadSource(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(src.Lines) == 0 || src.Lines[0] != "proxies:" {
		t.Errorf("lines = %q", src.Lines[:1])
	}
	for _, l := range src.Lines {
		if strings.Contains(l, "\r") {
			t.Fatalf("\\r not removed: %q", l)
		}
	}
	if src, err := a.ReadSource(rs); err != nil || len(src.Lines) != 2 {
		t.Errorf("rule-set: %v %q", err, src.Lines)
	}

	allowed := []string{
		filepath.Join(filepath.Dir(cfg), "rs", "..", "config.yaml"),
		filepath.Dir(cfg) + string(filepath.Separator) + "." + string(filepath.Separator) + "config.yaml",
	}
	if goruntime.GOOS == "windows" {
		allowed = append(allowed, strings.ToUpper(cfg), strings.ReplaceAll(cfg, `\`, "/"))
	}
	for _, p := range allowed {
		if _, err := a.ReadSource(p); err != nil {
			t.Errorf("%s should be allowed: %v", p, err)
		}
	}

	refused := []string{
		other,
		filepath.Join(filepath.Dir(rs), "..", "secret.txt"),
		filepath.Dir(cfg),
		"config.yaml",
		filepath.Join("..", "testdata", "ac1-geoip-without-no-resolve.yaml"),
		"",
	}
	if goruntime.GOOS == "windows" {
		refused = append(refused, strings.ToUpper(other))
	}
	for _, p := range refused {
		if _, err := a.ReadSource(p); err == nil {
			t.Errorf("%q must be refused", p)
		}
	}

	// A new Check replaces the whitelist.
	if r := a.Check(filepath.Join("..", "testdata", "ac3-recommended.yaml")); r.Result == nil {
		t.Fatalf("check failed: %+v", r.Error)
	}
	if _, err := a.ReadSource(rs); err == nil {
		t.Errorf("files of the previous check must be refused")
	}
}

func TestReadSourceAfterFailedCheck(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	write(t, bad, "a: [1, 2\n")
	a := NewApp()
	if r := a.Check(bad); r.Error == nil || r.Error.Kind != "parse" {
		t.Fatalf("want parse error: %+v", r)
	}
	if src, err := a.ReadSource(bad); err != nil || len(src.Lines) != 1 {
		t.Errorf("config of a failed check should be viewable: %v %q", err, src.Lines)
	}
}

func TestStaleCheckDoesNotReplaceWhitelist(t *testing.T) {
	cfg, _, other := setup(t)
	a := NewApp()
	a.Check(cfg)
	// Simulate an older Check finishing after the latest one.
	a.mu.Lock()
	stale := a.seq - 1
	a.mu.Unlock()
	a.setAllowed(stale, app.CheckOutcome{File: other})
	if _, err := a.ReadSource(other); err == nil {
		t.Errorf("stale check must not change the whitelist")
	}
	if _, err := a.ReadSource(cfg); err != nil {
		t.Errorf("latest check whitelist lost: %v", err)
	}
}

func TestReadSourceBinary(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "c.yaml")
	write(t, cfg, "a: 1\n\x00\x01")
	a := NewApp()
	a.Check(cfg)
	if _, err := a.ReadSource(cfg); err == nil {
		t.Errorf("binary content must be refused")
	}
}

func TestReadSourceSymlink(t *testing.T) {
	cfg, _, other := setup(t)
	a := NewApp()
	a.Check(cfg)
	dir := filepath.Dir(cfg)
	toOther := filepath.Join(dir, "to-other.yaml")
	toCfg := filepath.Join(dir, "to-config.yaml")
	if err := os.Symlink(other, toOther); err != nil {
		t.Skipf("symlinks not available: %v", err)
	}
	if err := os.Symlink(cfg, toCfg); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ReadSource(toOther); err == nil {
		t.Errorf("symlink to a file outside the whitelist must be refused")
	}
	if _, err := a.ReadSource(toCfg); err != nil {
		t.Errorf("symlink to the config should be allowed: %v", err)
	}
}

func TestReadLimited(t *testing.T) {
	if _, err := readLimited(strings.NewReader("12345"), 4); err != errSourceTooLarge {
		t.Errorf("err = %v, want errSourceTooLarge", err)
	}
	if b, err := readLimited(strings.NewReader("1234"), 4); err != nil || string(b) != "1234" {
		t.Errorf("readLimited = %q, %v", b, err)
	}
}

// leakyConfig copies examples/leaky-config.yaml (RULE-01 + DNS-02, both
// fixable) into an empty temp dir and returns its path.
func leakyConfig(t *testing.T) string {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	write(t, cfg, readFile(t, filepath.Join("..", "examples", "leaky-config.yaml")))
	return cfg
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// fakeDialog records the calls of the injected saveDialog.
type fakeDialog struct {
	calls int
	opts  runtime.SaveDialogOptions
}

// useDialog makes saveDialog return (path, err) for the rest of the test.
func useDialog(t *testing.T, path string, err error) *fakeDialog {
	t.Helper()
	d := &fakeDialog{}
	old := saveDialog
	saveDialog = func(_ context.Context, o runtime.SaveDialogOptions) (string, error) {
		d.calls++
		d.opts = o
		return path, err
	}
	t.Cleanup(func() { saveDialog = old })
	return d
}

// planned runs Check and PlanFix on cfg and fails unless both succeed.
func planned(t *testing.T, a *App, cfg string) *report.FixResult {
	t.Helper()
	if r := a.Check(cfg); r.Result == nil {
		t.Fatalf("check failed: %+v", r.Error)
	}
	r := a.PlanFix()
	if r.Error != nil || r.Result == nil {
		t.Fatalf("PlanFix = %+v", r)
	}
	return r.Result
}

func TestPlanFixBeforeCheck(t *testing.T) {
	a := NewApp()
	r := a.PlanFix()
	if r.Result != nil || r.Error == nil || r.Error.Kind != report.ErrKindNoConfig || r.Error.Message == "" {
		t.Fatalf("PlanFix = %+v", r)
	}
	d := useDialog(t, filepath.Join(t.TempDir(), "out.yaml"), nil)
	s := a.SaveFix()
	if s.Error == nil || s.Error.Kind != report.ErrKindNoFix || s.Path != "" || s.Cancelled || d.calls != 0 {
		t.Fatalf("SaveFix = %+v (dialog calls %d)", s, d.calls)
	}
	args := report.ErrorText(report.ErrKindArgs, "")
	if r.Error.Message == args || s.Error.Message == args || r.Error.Message == s.Error.Message {
		t.Errorf("no-config / no-fix need their own texts: %q %q", r.Error.Message, s.Error.Message)
	}
}

func TestPlanFixLeakyExample(t *testing.T) {
	cfg, err := filepath.Abs(filepath.Join("..", "examples", "leaky-config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	orig := readFile(t, cfg)
	a := NewApp()
	got := planned(t, a, cfg)
	if got.File != cfg || got.Output != app.DefaultFixOutput(cfg) || got.Written || got.NotWrittenReason != report.NotWrittenDryRun {
		t.Errorf("result header = %+v", got)
	}
	if len(got.Edits) != 2 || got.Edits[0].ID != "RULE-01" || got.Edits[1].ID != "DNS-02" || got.Edits[1].After != "" {
		t.Errorf("edits = %+v", got.Edits)
	}
	if len(got.Diff) == 0 || len(got.Skipped) != 0 {
		t.Errorf("diff = %+v, skipped = %+v", got.Diff, got.Skipped)
	}
	if got.Before.High != 1 || got.Before.Medium != 1 || got.After.High+got.After.Medium+got.After.Error != 0 {
		t.Errorf("before = %+v, after = %+v", got.Before, got.After)
	}
	if _, err := os.Stat(got.Output); err == nil {
		t.Errorf("PlanFix must not write %s", got.Output)
	}
	if readFile(t, cfg) != orig {
		t.Errorf("PlanFix modified the config")
	}

	// Same rendering as `dnsnitch fix --dry-run --format json`.
	out, kind, err := app.PlanFix(cfg, "")
	if kind != app.ErrNone {
		t.Fatal(err)
	}
	want := report.BuildFixResult(out.File, out.Output, out.Plan, out.Before, out.After, false)
	ga, _ := json.Marshal(got)
	wa, _ := json.Marshal(want)
	if !bytes.Equal(ga, wa) {
		t.Errorf("binding:\n%s\ncli:\n%s", ga, wa)
	}
}

func TestPlanFixErrors(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	write(t, bad, "a: [1, 2\n")
	for _, c := range []struct{ path, kind string }{
		{filepath.Join(dir, "missing.yaml"), report.ErrKindRead},
		{bad, report.ErrKindParse},
		{filepath.Join("..", "testdata", "ac12-encrypted.yaml"), report.ErrKindEncrypted},
	} {
		a := NewApp()
		a.Check(c.path)
		r := a.PlanFix()
		if r.Result != nil || r.Error == nil || r.Error.Kind != c.kind || r.Error.Message == "" {
			t.Errorf("%s: %+v", c.path, r)
		}
		d := useDialog(t, filepath.Join(dir, "out.yaml"), nil)
		if s := a.SaveFix(); s.Error == nil || s.Error.Kind != report.ErrKindNoFix || d.calls != 0 {
			t.Errorf("%s: SaveFix = %+v", c.path, s)
		}
	}
}

func TestPlanFixNothingToFix(t *testing.T) {
	a := NewApp()
	got := planned(t, a, filepath.Join("..", "testdata", "ac3-recommended.yaml"))
	if len(got.Edits) != 0 || len(got.Diff) != 0 || got.NotWrittenReason != report.NotWrittenNothing {
		t.Errorf("result = %+v", got)
	}
	d := useDialog(t, filepath.Join(t.TempDir(), "out.yaml"), nil)
	if s := a.SaveFix(); s.Error == nil || s.Error.Kind != report.ErrKindNoFix || d.calls != 0 {
		t.Errorf("SaveFix without edits = %+v (dialog calls %d)", s, d.calls)
	}
}

func TestSaveFix(t *testing.T) {
	cfg := leakyConfig(t)
	orig := readFile(t, cfg)
	a := NewApp()
	planned(t, a, cfg)

	dest := filepath.Join(filepath.Dir(cfg), "out.yaml")
	d := useDialog(t, dest, nil)
	s := a.SaveFix()
	if s.Error != nil || s.Cancelled || s.Path != dest {
		t.Fatalf("SaveFix = %+v", s)
	}
	o := d.opts
	if d.calls != 1 || o.DefaultDirectory != filepath.Dir(cfg) || o.DefaultFilename != "config.fixed.yaml" ||
		o.Title == "" || len(o.Filters) == 0 {
		t.Errorf("dialog options = %+v", o)
	}
	if readFile(t, cfg) != orig {
		t.Errorf("the config was modified")
	}
	fixed := readFile(t, dest)
	if !strings.Contains(fixed, "GEOIP,private,DIRECT,no-resolve") || strings.Contains(fixed, "8.8.8.8") {
		t.Errorf("written content:\n%s", fixed)
	}

	// The frontend then checks the saved file: the result and the
	// ReadSource whitelist follow it, and the old plan is gone.
	r := a.Check(s.Path)
	if r.Result == nil || r.Result.Summary.High+r.Result.Summary.Medium+r.Result.Summary.Error != 0 {
		t.Fatalf("check of the saved file = %+v", r)
	}
	if _, err := a.ReadSource(s.Path); err != nil {
		t.Errorf("saved file must be viewable: %v", err)
	}
	if _, err := a.ReadSource(cfg); err == nil {
		t.Errorf("the previous config must leave the whitelist")
	}
	if s := a.SaveFix(); s.Error == nil || s.Error.Kind != report.ErrKindNoFix {
		t.Errorf("SaveFix after a new Check = %+v", s)
	}
}

func TestSaveFixOverwritesConfirmedFile(t *testing.T) {
	cfg := leakyConfig(t)
	a := NewApp()
	planned(t, a, cfg)
	dest := filepath.Join(filepath.Dir(cfg), "existing.yaml")
	write(t, dest, "old: content\n")
	useDialog(t, dest, nil) // the native dialog asked before returning an existing file
	if s := a.SaveFix(); s.Error != nil || s.Path != dest {
		t.Fatalf("SaveFix = %+v", s)
	}
	if strings.Contains(readFile(t, dest), "old: content") {
		t.Errorf("existing file not replaced")
	}
}

func TestSaveFixCancelled(t *testing.T) {
	cfg := leakyConfig(t)
	a := NewApp()
	planned(t, a, cfg)
	d := useDialog(t, "", nil)
	if s := a.SaveFix(); !s.Cancelled || s.Error != nil || s.Path != "" || d.calls != 1 {
		t.Fatalf("SaveFix = %+v", s)
	}
	entries, err := os.ReadDir(filepath.Dir(cfg))
	if err != nil || len(entries) != 1 {
		t.Errorf("nothing may be written: %v %v", entries, err)
	}
	// The plan is kept: the user may open the dialog again.
	dest := filepath.Join(filepath.Dir(cfg), "out.yaml")
	useDialog(t, dest, nil)
	if s := a.SaveFix(); s.Error != nil || s.Path != dest {
		t.Errorf("second SaveFix = %+v", s)
	}
}

func TestSaveFixDialogError(t *testing.T) {
	cfg := leakyConfig(t)
	a := NewApp()
	planned(t, a, cfg)
	useDialog(t, "", errors.New("dialog failed"))
	if s := a.SaveFix(); s.Error == nil || s.Error.Kind != report.ErrKindWrite || !strings.Contains(s.Error.Message, "dialog failed") {
		t.Fatalf("SaveFix = %+v", s)
	}
}

func TestSaveFixConfigChanged(t *testing.T) {
	cfg := leakyConfig(t)
	a := NewApp()
	planned(t, a, cfg)
	changed := readFile(t, cfg) + "# edited after the preview\n"
	write(t, cfg, changed)

	dest := filepath.Join(filepath.Dir(cfg), "out.yaml")
	d := useDialog(t, dest, nil)
	s := a.SaveFix()
	if s.Error == nil || s.Error.Kind != report.ErrKindChanged || !strings.Contains(s.Error.Message, cfg) {
		t.Fatalf("SaveFix = %+v", s)
	}
	if d.calls != 0 {
		t.Errorf("a changed config must be refused before the dialog opens")
	}
	if _, err := os.Stat(dest); err == nil {
		t.Errorf("nothing may be written after the config changed")
	}
	if readFile(t, cfg) != changed {
		t.Errorf("the config was modified")
	}

	// Edited while the save dialog is open: app.SaveFix refuses it.
	a2 := NewApp()
	planned(t, a2, cfg)
	saveDialog = func(context.Context, runtime.SaveDialogOptions) (string, error) {
		write(t, cfg, changed+"# edited again\n")
		return dest, nil
	}
	if s := a2.SaveFix(); s.Error == nil || s.Error.Kind != report.ErrKindChanged {
		t.Fatalf("SaveFix with an edit during the dialog = %+v", s)
	}
	if _, err := os.Stat(dest); err == nil {
		t.Errorf("nothing may be written after the config changed")
	}
}

func TestSaveFixSameFile(t *testing.T) {
	cfg := leakyConfig(t)
	orig := readFile(t, cfg)
	aliases := []string{cfg, filepath.Join(filepath.Dir(cfg), ".", "config.yaml")}
	if goruntime.GOOS == "windows" {
		aliases = append(aliases, strings.ToUpper(cfg), strings.ReplaceAll(cfg, `\`, "/"))
	}
	a := NewApp()
	planned(t, a, cfg)
	for _, p := range aliases {
		useDialog(t, p, nil)
		s := a.SaveFix()
		if s.Error == nil || s.Error.Kind != report.ErrKindSameFile || s.Path != "" {
			t.Errorf("%s: SaveFix = %+v", p, s)
		}
		if readFile(t, cfg) != orig {
			t.Fatalf("%s: the config was overwritten", p)
		}
	}
	if entries, err := os.ReadDir(filepath.Dir(cfg)); err != nil || len(entries) != 1 {
		t.Errorf("no temp file may be left: %v %v", entries, err)
	}
}

func TestCheckInvalidatesPlan(t *testing.T) {
	cfg := leakyConfig(t)
	dest := filepath.Join(filepath.Dir(cfg), "out.yaml")

	// A later Check of another file.
	a := NewApp()
	planned(t, a, cfg)
	a.Check(filepath.Join("..", "testdata", "ac1-geoip-without-no-resolve.yaml"))
	d := useDialog(t, dest, nil)
	if s := a.SaveFix(); s.Error == nil || s.Error.Kind != report.ErrKindNoFix || d.calls != 0 {
		t.Errorf("SaveFix after another Check = %+v", s)
	}

	// A re-check of the same file also needs a new preview.
	planned(t, a, cfg)
	a.Check(cfg)
	if s := a.SaveFix(); s.Error == nil || s.Error.Kind != report.ErrKindNoFix {
		t.Errorf("SaveFix after a re-check = %+v", s)
	}

	// A Check started while the save dialog is open.
	planned(t, a, cfg)
	saveDialog = func(context.Context, runtime.SaveDialogOptions) (string, error) {
		a.Check(cfg)
		return dest, nil
	}
	if s := a.SaveFix(); s.Error == nil || s.Error.Kind != report.ErrKindNoFix {
		t.Errorf("SaveFix with a Check during the dialog = %+v", s)
	}
	if _, err := os.Stat(dest); err == nil {
		t.Errorf("stale plans must not be written")
	}
}
