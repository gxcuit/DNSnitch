package app

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dnsnitch/internal/fix"
	"dnsnitch/internal/model"
)

// copyConfig copies a repo config into a temp dir and returns its path.
func copyConfig(t *testing.T, src string) string {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return dst
}

var leaky = filepath.Join("..", "..", "examples", "leaky-config.yaml")

func hash(t *testing.T, file string) [32]byte {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(data)
}

func TestPlanAndSaveFix(t *testing.T) {
	cfg := copyConfig(t, leaky)
	orig := hash(t, cfg)
	out, kind, err := PlanFix(cfg, "")
	if kind != ErrNone || err != nil {
		t.Fatalf("PlanFix: %q %v", kind, err)
	}
	if out.File != cfg || out.Output != DefaultFixOutput(cfg) || out.SourceHash != orig {
		t.Errorf("outcome = %+v", out)
	}
	if len(out.Plan.Edits) != 2 || out.Plan.Edits[0].ID != "RULE-01" || out.Plan.Edits[1].ID != "DNS-02" {
		t.Fatalf("edits = %+v", out.Plan.Edits)
	}
	if !hasSeverity(out.Before, model.High) || hasSeverity(out.After, model.High) || hasSeverity(out.After, model.Medium) {
		t.Errorf("before = %v, after = %v", out.Before, out.After)
	}
	if _, err := os.Stat(out.Output); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("PlanFix must not write")
	}

	if kind, err := SaveFix(out, out.Output, false); kind != ErrNone || err != nil {
		t.Fatalf("SaveFix: %q %v", kind, err)
	}
	got, err := os.ReadFile(out.Output)
	if err != nil || !bytes.Equal(got, out.Plan.Fixed) {
		t.Fatalf("written = %q, %v", got, err)
	}
	if hash(t, cfg) != orig {
		t.Error("the config was modified")
	}
	assertNoTemp(t, filepath.Dir(cfg))

	// The written file checks clean.
	res := RunCheck(out.Output, "")
	if res.ErrKind != ErrNone || hasSeverity(res.Findings, model.High) || hasSeverity(res.Findings, model.Medium) {
		t.Errorf("check of fixed file: %q %v", res.ErrKind, res.Findings)
	}

	// Existing output: refused without force, replaced with force.
	if err := os.WriteFile(out.Output, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if kind, err := SaveFix(out, out.Output, false); kind != ErrExists || err == nil {
		t.Errorf("existing output: %q %v", kind, err)
	}
	if got, _ := os.ReadFile(out.Output); string(got) != "old" {
		t.Error("existing output was overwritten without force")
	}
	if kind, err := SaveFix(out, out.Output, true); kind != ErrNone || err != nil {
		t.Errorf("force: %q %v", kind, err)
	}
	if got, _ := os.ReadFile(out.Output); !bytes.Equal(got, out.Plan.Fixed) {
		t.Error("force did not replace the output")
	}
	assertNoTemp(t, filepath.Dir(cfg))
	if hash(t, cfg) != orig {
		t.Error("the config was modified")
	}
}

func TestSaveFixSameFile(t *testing.T) {
	cfg := copyConfig(t, leaky)
	orig := hash(t, cfg)
	out, kind, err := PlanFix(cfg, "")
	if kind != ErrNone || err != nil {
		t.Fatal(kind, err)
	}
	dir := filepath.Dir(cfg)
	sep := string(filepath.Separator)
	aliases := []string{cfg, dir + sep + "." + sep + "config.yaml", dir + sep + "sub" + sep + ".." + sep + "config.yaml"}
	// Other spelling of the same name on case-insensitive file systems
	// (Windows, default macOS).
	upper := filepath.Join(dir, "CONFIG.YAML")
	if a, err := os.Stat(upper); err == nil {
		if b, _ := os.Stat(cfg); os.SameFile(a, b) {
			aliases = append(aliases, upper)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "hard.yaml")
	if err := os.Link(cfg, link); err == nil {
		aliases = append(aliases, link)
	}
	sym := filepath.Join(dir, "sym.yaml")
	if err := os.Symlink(cfg, sym); err == nil {
		aliases = append(aliases, sym)
	}
	if rel, err := filepath.Rel(mustWd(t), cfg); err == nil {
		aliases = append(aliases, rel)
	}
	t.Logf("aliases: %q", aliases)
	for _, a := range aliases {
		for _, force := range []bool{false, true} {
			if kind, err := SaveFix(out, a, force); kind != ErrSameFile || err == nil {
				t.Errorf("%s (force=%v): %q %v", a, force, kind, err)
			}
		}
	}
	if hash(t, cfg) != orig {
		t.Error("the config was modified")
	}
	assertNoTemp(t, dir)
}

func mustWd(t *testing.T) string {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return wd
}

func TestSaveFixChangedAndNothingToFix(t *testing.T) {
	cfg := copyConfig(t, leaky)
	out, kind, err := PlanFix(cfg, "")
	if kind != ErrNone || err != nil {
		t.Fatal(kind, err)
	}
	if err := os.WriteFile(cfg, append(out.Plan.Original, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if kind, err := SaveFix(out, out.Output, false); kind != ErrChanged || err == nil {
		t.Errorf("changed config: %q %v", kind, err)
	}
	if _, err := os.Stat(out.Output); !errors.Is(err, os.ErrNotExist) {
		t.Error("output written for a changed config")
	}

	clean := copyConfig(t, filepath.Join("..", "..", "testdata", "ac8-default-ns-tls-ip.yaml"))
	out, kind, err = PlanFix(clean, "")
	if kind != ErrNone || err != nil || len(out.Plan.Edits) != 0 {
		t.Fatalf("clean config: %q %v %+v", kind, err, out.Plan)
	}
	if !bytes.Equal(out.Plan.Fixed, out.Plan.Original) || len(out.After) != len(out.Before) {
		t.Error("no edits: Fixed must equal Original and After equal Before")
	}
	if kind, err := SaveFix(out, out.Output, false); kind != ErrNone || err != nil {
		t.Errorf("nothing to fix: %q %v", kind, err)
	}
	if _, err := os.Stat(out.Output); !errors.Is(err, os.ErrNotExist) {
		t.Error("output written although there was nothing to fix")
	}
}

func TestSaveFixWriteFailure(t *testing.T) {
	cfg := copyConfig(t, leaky)
	out, kind, err := PlanFix(cfg, "")
	if kind != ErrNone || err != nil {
		t.Fatal(kind, err)
	}
	old := rename
	rename = func(string, string) error { return errors.New("disk full") }
	defer func() { rename = old }()
	if kind, err := SaveFix(out, out.Output, false); kind != ErrWrite || err == nil {
		t.Errorf("rename failure: %q %v", kind, err)
	}
	rename = old
	if _, err := os.Stat(out.Output); !errors.Is(err, os.ErrNotExist) {
		t.Error("output exists after a failed write")
	}
	assertNoTemp(t, filepath.Dir(cfg))

	missingDir := filepath.Join(filepath.Dir(cfg), "missing", "out.yaml")
	if kind, err := SaveFix(out, missingDir, false); kind != ErrWrite || err == nil {
		t.Errorf("missing directory: %q %v", kind, err)
	}
	dir := filepath.Join(filepath.Dir(cfg), "adir")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, force := range []bool{false, true} {
		if kind, err := SaveFix(out, dir, force); kind != ErrWrite || err == nil {
			t.Errorf("directory output (force=%v): %q %v", force, kind, err)
		}
	}
	assertNoTemp(t, filepath.Dir(cfg))
}

// A fixed text with a new error finding is refused and nothing is written.
func TestPlanFixVerifyFailure(t *testing.T) {
	cfg := copyConfig(t, leaky)
	orig, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	injected := func(file, home string) fix.CheckFunc {
		real := newChecker(file, home)
		return func(data []byte) ([]model.Finding, error) {
			fs, err := real(data)
			if err == nil && !bytes.Equal(data, orig) {
				fs = append(fs, model.Finding{ID: "DNS-06", Severity: model.Error,
					Locations: []model.Location{{File: file, Line: 1, Path: "dns.respect-rules"}}})
			}
			return fs, err
		}
	}
	out, kind, err := planFix(cfg, "", injected)
	if kind != ErrVerify || err == nil {
		t.Fatalf("verify: %q %v", kind, err)
	}
	if out.Plan == nil || len(out.Plan.Edits) == 0 {
		t.Error("the plan should still be returned for display")
	}
	if _, err := os.Stat(out.Output); !errors.Is(err, os.ErrNotExist) {
		t.Error("output written on verification failure")
	}

	broken := func(file, home string) fix.CheckFunc {
		real := newChecker(file, home)
		return func(data []byte) ([]model.Finding, error) {
			if !bytes.Equal(data, orig) && strings.Contains(string(data), "DIRECT,no-resolve") {
				return nil, errors.New("does not load")
			}
			return real(data)
		}
	}
	// A pass that does not load is undone inside fix.Build; the remaining
	// DNS fix still verifies.
	out, kind, err = planFix(cfg, "", broken)
	if kind != ErrNone || err != nil || len(out.Plan.Edits) != 1 || out.Plan.Edits[0].ID != "DNS-02" {
		t.Errorf("broken pass: %q %v %+v", kind, err, out.Plan)
	}
	if got, _ := os.ReadFile(cfg); !bytes.Equal(got, orig) {
		t.Error("the config was modified")
	}
}

func TestPlanFixLoadErrors(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("a: [1, 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		file string
		want ErrorKind
	}{
		{filepath.Join(dir, "missing.yaml"), ErrRead},
		{bad, ErrParse},
		{filepath.Join("..", "..", "testdata", "ac12-encrypted.yaml"), ErrEncrypted},
	} {
		out, kind, err := PlanFix(c.file, "")
		if kind != c.want || err == nil || out.Plan != nil {
			t.Errorf("%s: kind = %q, err = %v", c.file, kind, err)
		}
	}
}

func TestDefaultFixOutput(t *testing.T) {
	for in, want := range map[string]string{
		"config.yaml":                            "config.fixed.yaml",
		"config.yml":                             "config.fixed.yml",
		"config":                                 "config.fixed.yaml",
		filepath.Join("a.d", "config"):           filepath.Join("a.d", "config.fixed.yaml"),
		filepath.Join("dir", "my.config.yaml"):   filepath.Join("dir", "my.config.fixed.yaml"),
		filepath.Join("C:", "x", "Profile.YAML"): filepath.Join("C:", "x", "Profile.fixed.YAML"),
	} {
		if got := DefaultFixOutput(in); got != want {
			t.Errorf("DefaultFixOutput(%q) = %q, want %q", in, got, want)
		}
	}
}

func hasSeverity(fs []model.Finding, s model.Severity) bool {
	for _, f := range fs {
		if f.Severity == s {
			return true
		}
	}
	return false
}

// assertNoTemp fails when a temporary output file is left in dir.
func assertNoTemp(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temporary file left: %s", e.Name())
		}
	}
}
