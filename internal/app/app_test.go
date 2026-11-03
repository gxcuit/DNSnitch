package app

import (
	"os"
	"path/filepath"
	"testing"

	"dnsleak/internal/model"
)

func TestRunCheckOK(t *testing.T) {
	out := RunCheck(filepath.Join("..", "..", "testdata", "ac1-geoip-without-no-resolve.yaml"), "")
	if out.ErrKind != ErrNone || out.Err != nil {
		t.Fatalf("unexpected error: %v %v", out.ErrKind, out.Err)
	}
	if len(out.Findings) < 2 || out.Findings[0].ID != "RULE-01" || out.Findings[0].Severity != model.High {
		t.Fatalf("findings = %+v", out.Findings)
	}
	for i := 1; i < len(out.Findings); i++ {
		if out.Findings[i].Severity > out.Findings[i-1].Severity {
			t.Errorf("findings not sorted at %d", i)
		}
	}
}

func TestRunCheckErrors(t *testing.T) {
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
		out := RunCheck(c.file, "")
		if out.ErrKind != c.want || out.Err == nil || out.Findings != nil {
			t.Errorf("%s: kind = %q, err = %v, findings = %d", c.file, out.ErrKind, out.Err, len(out.Findings))
		}
	}
}

func TestDefaultHome(t *testing.T) {
	abs, _ := filepath.Abs(filepath.Join("x", "c.yaml"))
	if got := DefaultHome(filepath.Join("x", "c.yaml")); got != filepath.Dir(abs) {
		t.Errorf("DefaultHome = %s", got)
	}
}
