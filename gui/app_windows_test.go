package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

// TestReadSourceWindowsAliases covers Windows-specific spellings of a path:
// aliases of an allowed file are accepted, while NTFS alternate data
// streams of the allowed file and aliases of other files are refused.
func TestReadSourceWindowsAliases(t *testing.T) {
	cfg, _, other := setup(t)
	a := NewApp()
	if r := a.Check(cfg); r.Result == nil {
		t.Fatalf("check failed: %+v", r.Error)
	}
	if err := os.WriteFile(cfg+":hidden", []byte("stream content\n"), 0o644); err != nil {
		t.Fatalf("cannot create alternate data stream: %v", err)
	}
	const long = `\\?\`

	allowed := []string{cfg + ".", long + cfg}
	refused := []string{
		cfg + ":hidden", cfg + ":hidden:$DATA", cfg + "::$DATA", long + cfg + ":hidden",
		other + ".", other + " ", long + other, `\\.\` + other,
	}
	if s := shortPath(t, other); s != other {
		refused = append(refused, s)
	}
	if s := shortPath(t, cfg); s != cfg {
		allowed = append(allowed, s)
	}

	dir := filepath.Dir(cfg)
	j := filepath.Join(t.TempDir(), "junction")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", j, dir).CombinedOutput(); err == nil {
		t.Cleanup(func() { os.Remove(j) })
		allowed = append(allowed, filepath.Join(j, "config.yaml"))
		refused = append(refused, filepath.Join(j, "secret.txt"))
	} else {
		t.Logf("junction not created: %v %s", err, out)
	}

	for _, p := range allowed {
		if _, err := a.ReadSource(p); err != nil {
			t.Errorf("%s should be allowed: %v", p, err)
		}
	}
	for _, p := range refused {
		if src, err := a.ReadSource(p); err == nil {
			t.Errorf("%s must be refused, got %q", p, src.Lines)
		}
	}
}

func shortPath(t *testing.T, p string) string {
	t.Helper()
	u, err := syscall.UTF16FromString(p)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, syscall.MAX_LONG_PATH)
	n, err := syscall.GetShortPathName(&u[0], &buf[0], uint32(len(buf)))
	if err != nil || n == 0 {
		return p
	}
	return syscall.UTF16ToString(buf[:n])
}
