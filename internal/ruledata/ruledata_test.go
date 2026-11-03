package ruledata

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"

	"dnsleak/internal/model"
	"dnsleak/internal/testutil"
)

func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := testutil.WriteFile(path, data); err != nil {
		t.Fatal(err)
	}
}

func TestMrsDomain(t *testing.T) {
	home := t.TempDir()
	data, err := testutil.DomainMrs([]string{"+.google.com", "full.example.org", ".sub-only.net", "*.wild.io"})
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(home, "ruleset", "g.mrs"), data)
	p := LoadProvider(&model.RuleProvider{Name: "g", Type: "file", Behavior: "domain", Format: "mrs", Path: "./ruleset/g.mrs"}, home)
	if !p.Loaded || p.Count != 4 {
		t.Fatalf("provider = %+v", p)
	}
	for domain, want := range map[string]model.Tri{
		"google.com": model.Yes, "www.google.com": model.Yes, "WWW.Google.COM": model.Yes,
		"full.example.org": model.Yes, "a.full.example.org": model.No,
		"sub-only.net": model.No, "a.sub-only.net": model.Yes,
		"a.wild.io": model.Yes, "a.b.wild.io": model.No, "youtube.com": model.No,
	} {
		if got := p.MatchDomain(domain); got != want {
			t.Errorf("%s: %v, want %v", domain, got, want)
		}
	}
}

func TestMrsIPCIDR(t *testing.T) {
	home := t.TempDir()
	data, err := testutil.IPCIDRMrs([]string{"91.108.4.0/22", "2001:b28:f23d::/48"})
	if err != nil {
		t.Fatal(err)
	}
	url := "https://example.com/tg.mrs"
	write(t, CachePath(home, url), data)
	p := LoadProvider(&model.RuleProvider{Name: "tg", Type: "http", Behavior: "ipcidr", Format: "mrs", URL: url}, home)
	if !p.Loaded || p.Count != 2 || p.CIDRs == nil {
		t.Fatalf("provider = %+v", p)
	}
	if !p.CIDRs.IsContain(netip.MustParseAddr("91.108.5.1")) || p.CIDRs.IsContain(netip.MustParseAddr("8.8.8.8")) {
		t.Errorf("ipcidr content wrong")
	}

	// behavior mismatch is a decode error
	p = LoadProvider(&model.RuleProvider{Name: "tg", Type: "http", Behavior: "domain", Format: "mrs", URL: url}, home)
	if p.Loaded || p.Reason != ReasonParseError {
		t.Errorf("mismatch = %+v", p)
	}
	// classical does not support mrs
	p = LoadProvider(&model.RuleProvider{Name: "tg", Type: "http", Behavior: "classical", Format: "mrs", URL: url}, home)
	if p.Loaded || p.Reason != ReasonBadFormat {
		t.Errorf("classical mrs = %+v", p)
	}
}

func TestMrsCorrupt(t *testing.T) {
	home := t.TempDir()
	// A valid header followed by a domain set whose first segment claims
	// 2^60 entries: mihomo's reader would try to allocate it.
	raw := []byte{'M', 'R', 'S', 1, 0}
	raw = append(raw, make([]byte, 16)...) // count, extra length
	raw = append(raw, 1)                   // set version
	raw = binary.BigEndian.AppendUint64(raw, 1<<60)
	var buf bytes.Buffer
	enc, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enc.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"huge.mrs":    buf.Bytes(),
		"garbage.mrs": []byte("not zstd at all"),
		"empty.mrs":   nil,
	} {
		write(t, filepath.Join(home, name), data)
		p := LoadProvider(&model.RuleProvider{Name: name, Type: "file", Behavior: "domain", Format: "mrs", Path: name}, home)
		if p.Loaded || p.Reason != ReasonParseError {
			t.Errorf("%s: provider = %+v", name, p)
		}
	}
}

func TestCachePath(t *testing.T) {
	url := "https://example.com/a.yaml"
	sum := md5.Sum([]byte(url))
	want := filepath.Join("home", "rules", hex.EncodeToString(sum[:]))
	if got := CachePath("home", url); got != want {
		t.Errorf("CachePath = %s, want %s", got, want)
	}
}

func TestTextAndYAML(t *testing.T) {
	home := t.TempDir()
	write(t, filepath.Join(home, "c.txt"), []byte("# comment\r\n\r\nDOMAIN-SUFFIX,a.com\r\n// premium comment\r\nIP-CIDR,1.0.0.0/8,no-resolve\r\nBAD-TYPE,x\r\n"))
	p := LoadProvider(&model.RuleProvider{Name: "c", Type: "file", Behavior: "classical", Format: "text", Path: "c.txt"}, home)
	if !p.Loaded || len(p.Rules) != 2 {
		t.Fatalf("text classical = %+v", p)
	}
	if p.Rules[0].Loc.Line != 3 || p.Rules[1].Loc.Line != 5 || !p.Rules[1].NoResolve {
		t.Errorf("text rules = %+v", p.Rules)
	}

	write(t, filepath.Join(home, "d.yaml"), []byte("payload:\n  - '+.google.com'\n  - 'a.com'\n"))
	p = LoadProvider(&model.RuleProvider{Name: "d", Type: "file", Behavior: "domain", Format: "yaml", Path: "d.yaml"}, home)
	if !p.Loaded || p.Count != 2 || p.MatchDomain("www.google.com") != model.Yes {
		t.Errorf("yaml domain = %+v", p)
	}

	// missing file / undefined source
	p = LoadProvider(&model.RuleProvider{Name: "m", Type: "http", Behavior: "domain", URL: "https://x/y"}, home)
	if p.Loaded || p.Reason != ReasonNoFile || p.Source != CachePath(home, "https://x/y") {
		t.Errorf("missing = %+v", p)
	}
	p = LoadProvider(&model.RuleProvider{Name: "m", Type: "file", Behavior: "domain"}, home)
	if p.Reason != ReasonNoSource {
		t.Errorf("no source = %+v", p)
	}
}

func TestInline(t *testing.T) {
	def := &model.RuleProvider{
		Name: "i", Type: "inline", Behavior: "classical",
		Payload:     []string{"IP-CIDR,1.0.0.0/8", "DOMAIN,b.com"},
		PayloadLocs: []model.Location{{File: "cfg.yaml", Line: 10}, {File: "cfg.yaml", Line: 11}},
	}
	p := LoadProvider(def, "")
	if !p.Loaded || len(p.Rules) != 2 || p.Rules[0].Loc.Line != 10 {
		t.Errorf("inline = %+v", p)
	}
	if p.MatchDomain("b.com") != model.Yes {
		t.Errorf("classical domain entry should match")
	}
}

func TestGeoSite(t *testing.T) {
	home := t.TempDir()
	dat := testutil.GeoSiteDat(map[string][]testutil.GeoDomain{
		"GOOGLE": {
			{Type: testutil.GeoSuffix, Value: "google.com"},
			{Type: testutil.GeoSuffix, Value: "google.cn", Attrs: []string{"cn"}},
			{Type: testutil.GeoFull, Value: "exact.gstatic.com"},
			{Type: testutil.GeoPlain, Value: "googleapis"},
			{Type: testutil.GeoRegex, Value: `^g\d+\.ggpht\.com$`},
			{Type: testutil.GeoRegex, Value: `^cdn\D+\.example\.net$`}, // \D must not become \d
		},
		"GEOLOCATION-!CN": {{Type: testutil.GeoSuffix, Value: "youtube.com"}},
	})
	write(t, filepath.Join(home, "geosite.dat"), dat) // file name is case-insensitive
	s := NewStore(&model.Config{}, home)
	for _, c := range []struct {
		name, domain string
		want         model.Tri
	}{
		{"google", "www.google.com", model.Yes},
		{"Google", "google.com", model.Yes},
		{"google", "exact.gstatic.com", model.Yes},
		{"google", "a.exact.gstatic.com", model.No},
		{"google", "fonts.googleapis.com", model.Yes},
		{"google", "g12.ggpht.com", model.Yes},
		{"google", "cdnx.example.net", model.Yes},
		{"google", "cdn1.example.net", model.No},
		{"google", "example.com", model.No},
		{"google@cn", "www.google.cn", model.Yes},
		{"google@cn", "www.google.com", model.No},
		{"geolocation-!cn", "m.youtube.com", model.Yes},
	} {
		if got, why := s.MatchGeoSite(c.name, c.domain); got != c.want {
			t.Errorf("%s/%s = %v (%s), want %v", c.name, c.domain, got, why, c.want)
		}
	}
	if got, why := s.MatchGeoSite("nope", "a.com"); got != model.Unknown || why != ReasonGeoSiteNoList {
		t.Errorf("missing list = %v %s", got, why)
	}

	empty := NewStore(&model.Config{}, t.TempDir())
	if got, why := empty.MatchGeoSite("google", "google.com"); got != model.Unknown || why != ReasonGeoSiteMissing {
		t.Errorf("missing dat = %v %s", got, why)
	}
	bad := t.TempDir()
	write(t, filepath.Join(bad, "GeoSite.dat"), []byte{0xff, 0xff, 0xff})
	if got, why := NewStore(&model.Config{}, bad).MatchGeoSite("google", "google.com"); got != model.Unknown || why != ReasonGeoSiteError {
		t.Errorf("corrupt dat = %v %s", got, why)
	}
}

func TestPatternMatch(t *testing.T) {
	for _, c := range []struct {
		pattern, domain string
		want            bool
	}{
		{"+.a.com", "a.com", true},
		{"+.a.com", "x.y.a.com", true},
		{".a.com", "a.com", false},
		{".a.com", "x.a.com", true},
		{"*.a.com", "x.a.com", true},
		{"*.a.com", "x.y.a.com", false},
		{"a.com", "A.COM", true},
		{"a.com", "b.a.com", false},
	} {
		if got := PatternMatch(c.pattern, c.domain); got != c.want {
			t.Errorf("PatternMatch(%q, %q) = %v", c.pattern, c.domain, got)
		}
	}
}

func TestMatchDomainRule(t *testing.T) {
	for _, c := range []struct {
		typ, payload, domain string
		want                 model.Tri
	}{
		{"DOMAIN", "a.com", "A.com", model.Yes},
		{"DOMAIN", "a.com", "b.a.com", model.No},
		{"DOMAIN-SUFFIX", "a.com", "a.com", model.Yes},
		{"DOMAIN-SUFFIX", "a.com", "x.a.com", model.Yes},
		{"DOMAIN-SUFFIX", "a.com", "xa.com", model.No},
		{"DOMAIN-KEYWORD", "goo", "www.google.com", model.Yes},
		{"DOMAIN-WILDCARD", "*.a.com", "x.y.a.com", model.Yes},
		{"DOMAIN-WILDCARD", "?.a.com", "xy.a.com", model.No},
		{"DOMAIN-REGEX", `^www\.`, "www.a.com", model.Yes},
		{"DOMAIN-REGEX", `(?<=x)a`, "xa.com", model.Unknown},
	} {
		r := model.Rule{Type: c.typ, Payload: c.payload}
		if got := MatchDomainRule(r, c.domain); got != c.want {
			t.Errorf("%s,%s vs %s = %v", c.typ, c.payload, c.domain, got)
		}
	}
}

func TestStoreUndefined(t *testing.T) {
	s := NewStore(&model.Config{}, t.TempDir())
	p := s.Provider("x")
	if p.Def != nil || p.Reason != ReasonNotDefined || p.MatchDomain("a.com") != model.Unknown {
		t.Errorf("undefined = %+v", p)
	}
}
