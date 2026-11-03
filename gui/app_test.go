package main

import (
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"

	"dnsleak/internal/app"
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
