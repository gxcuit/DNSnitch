package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dnsnitch/internal/ruledata"
	"dnsnitch/internal/testutil"
)

type jsonLoc struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Path     string `json:"path"`
	Text     string `json:"text"`
	Role     string `json:"role"`
	Resolver *struct {
		Level     string `json:"level"`
		Source    string `json:"source"`
		PolicyKey string `json:"policy_key"`
	} `json:"resolver"`
}

type jsonFinding struct {
	ID        string    `json:"id"`
	Severity  string    `json:"severity"`
	Message   string    `json:"message"`
	Locations []jsonLoc `json:"locations"`
	Fix       string    `json:"fix"`
	Notes     []string  `json:"notes"`
}

type jsonCheck struct {
	File     string         `json:"file"`
	Findings []jsonFinding  `json:"findings"`
	Summary  map[string]int `json:"summary"`
}

type jsonServer struct {
	Server string `json:"server"`
	Grade  string `json:"grade"`
	Line   int    `json:"line"`
}

type jsonStep struct {
	Step       int    `json:"step"`
	Rule       string `json:"rule"`
	Line       int    `json:"line"`
	Outcome    string `json:"outcome"`
	Reason     string `json:"reason"`
	Class      string `json:"class"`
	Resolution *struct {
		Source  string       `json:"source"`
		Servers []jsonServer `json:"servers"`
		Level   string       `json:"level"`
	} `json:"resolution"`
}

type jsonTrace struct {
	Domain  string     `json:"domain"`
	Steps   []jsonStep `json:"steps"`
	Verdict struct {
		Code        string `json:"code"`
		Severity    string `json:"severity"`
		FinalRule   string `json:"final_rule"`
		FinalTarget string `json:"final_target"`
		FinalClass  string `json:"final_class"`
		Uncertain   bool   `json:"uncertain"`
		Impact      string `json:"impact"`
	} `json:"verdict"`
}

func fixture(name string) string { return filepath.Join("..", "..", "testdata", name) }

func runCLI(t *testing.T, args ...string) (string, int) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(args, &out, &errOut)
	if errOut.Len() > 0 {
		t.Logf("stderr: %s", errOut.String())
	}
	return out.String(), code
}

func checkJSON(t *testing.T, file string, extra ...string) (jsonCheck, int) {
	t.Helper()
	args := append([]string{"check", "--format", "json"}, extra...)
	out, code := runCLI(t, append(args, file)...)
	var res jsonCheck
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("invalid JSON (%v):\n%s", err, out)
	}
	return res, code
}

func traceJSON(t *testing.T, file, domain string, extra ...string) (jsonTrace, int) {
	t.Helper()
	args := append([]string{"trace", "--format", "json"}, extra...)
	out, code := runCLI(t, append(args, file, domain)...)
	var res jsonTrace
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("invalid JSON (%v):\n%s", err, out)
	}
	return res, code
}

// lineOf returns the 1-based line of the first line whose trimmed content
// equals want (independent of the YAML parser under test).
func lineOf(t *testing.T, file, want string) int {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	for i, l := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		if strings.TrimSpace(l) == want {
			return i + 1
		}
	}
	t.Fatalf("%q not found in %s", want, file)
	return 0
}

func find(res jsonCheck, id string) []jsonFinding {
	var out []jsonFinding
	for _, f := range res.Findings {
		if f.ID == id {
			out = append(out, f)
		}
	}
	return out
}

func one(t *testing.T, res jsonCheck, id string) jsonFinding {
	t.Helper()
	fs := find(res, id)
	if len(fs) != 1 {
		t.Fatalf("want exactly one %s, got %d: %+v", id, len(fs), res.Findings)
	}
	return fs[0]
}

func hasLoc(f jsonFinding, role string, line int) bool {
	for _, l := range f.Locations {
		if l.Role == role && l.Line == line {
			return true
		}
	}
	return false
}

func noneAtOrAbove(t *testing.T, res jsonCheck, ids ...string) {
	t.Helper()
	for _, f := range res.Findings {
		for _, id := range ids {
			if f.ID == id {
				t.Errorf("unexpected %s: %+v", id, f)
			}
		}
	}
}

func TestAC1GeoIPWithoutNoResolve(t *testing.T) {
	file := fixture("ac1-geoip-without-no-resolve.yaml")
	res, code := checkJSON(t, file)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	f := one(t, res, "RULE-01")
	if f.Severity != "high" {
		t.Errorf("RULE-01 severity = %s, want high", f.Severity)
	}
	if !hasLoc(f, "trigger", lineOf(t, file, "- GEOIP,private,🎯 全球直连")) {
		t.Errorf("RULE-01 does not point at the GEOIP rule: %+v", f.Locations)
	}
	if !hasLoc(f, "resolver", lineOf(t, file, "- 8.8.8.8")) {
		t.Errorf("RULE-01 does not point at 8.8.8.8: %+v", f.Locations)
	}
	if f.Locations[0].Line != lineOf(t, file, "- GEOIP,private,🎯 全球直连") {
		t.Errorf("first location should be the trigger rule")
	}
	for _, l := range f.Locations {
		switch {
		case l.Role == "affected" && (l.Resolver == nil || l.Resolver.Level != "plain" || l.Resolver.Source != "nameserver"):
			t.Errorf("affected %s: resolver %+v, want plain via nameserver", l.Text, l.Resolver)
		case l.Role != "affected" && l.Resolver != nil:
			t.Errorf("%s location should not carry a resolver", l.Role)
		}
	}
	if strings.Contains(f.Message, "最差") {
		t.Errorf("uniform levels must not mention a worst case: %s", f.Message)
	}
	if d := one(t, res, "DNS-02"); d.Severity != "medium" {
		t.Errorf("DNS-02 severity = %s", d.Severity)
	}
}

func TestAC2GeoIPWithNoResolve(t *testing.T) {
	res, _ := checkJSON(t, fixture("ac2-geoip-with-no-resolve.yaml"))
	noneAtOrAbove(t, res, "RULE-01", "RULE-02", "RULE-03", "RULE-04")
	// GEOIP,private,...,no-resolve before domain rules is the correct
	// lan idiom, not a useless fallback.
	noneAtOrAbove(t, res, "RULE-05")
	// Only the rule finding disappears; the plain nameserver is still
	// reported on its own.
	if f := one(t, res, "DNS-02"); f.Severity != "medium" {
		t.Errorf("DNS-02 severity = %s", f.Severity)
	}
}

func TestAC3RecommendedConfig(t *testing.T) {
	res, code := checkJSON(t, fixture("ac3-recommended.yaml"))
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	for _, f := range res.Findings {
		switch f.Severity {
		case "error", "high", "medium":
			t.Errorf("unexpected %s %s: %s", f.Severity, f.ID, f.Message)
		}
	}
}

// TestAC3RecommendedConfigFromDoc runs the recommended config exactly as
// published in docs/Clash.Meta DNS 配置指南.md. The document omits proxies,
// so only the policies its rules name are appended.
//
// The guide is a local copy of a third-party article and is not in the
// repository (see .gitignore), so the test is skipped where it is absent,
// e.g. in CI. TestAC3RecommendedConfig covers the same case from testdata.
func TestAC3RecommendedConfigFromDoc(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "Clash.Meta DNS 配置指南.md"))
	if errors.Is(err, fs.ErrNotExist) {
		t.Skip("docs/Clash.Meta DNS 配置指南.md not present (local-only reference copy)")
	}
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ReplaceAll(string(doc), "\r\n", "\n")
	start := strings.Index(text, "```yaml\n")
	if start < 0 {
		t.Fatal("no yaml block in the guide")
	}
	body := text[start+len("```yaml\n"):]
	end := strings.Index(body, "\n```")
	if end < 0 {
		t.Fatal("unterminated yaml block in the guide")
	}
	body = body[:end+1]
	if !strings.Contains(body, "MATCH,PROXY") || !strings.Contains(body, "'tls://1.1.1.1#PROXY'") {
		t.Fatalf("unexpected yaml block:\n%s", body)
	}
	body += `proxies:
  - {name: jp-node, type: trojan, server: jp.example.com, port: 443, password: example}
proxy-groups:
  - {name: PROXY, type: select, proxies: [jp-node]}
  - {name: 国际流媒体, type: select, proxies: [PROXY, jp-node]}
`
	file := filepath.Join(t.TempDir(), "recommended.yaml")
	if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	res, code := checkJSON(t, file)
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	for _, f := range res.Findings {
		switch f.Severity {
		case "error", "high", "medium":
			t.Errorf("unexpected %s %s: %s", f.Severity, f.ID, f.Message)
		}
	}
	// The GEOIP rules sit after every domain rule and the resolvers are
	// proxied: the only resolution finding is the informational one.
	if f := one(t, res, "RULE-02"); f.Severity != "info" || !hasLoc(f, "trigger", lineOf(t, file, "- GEOIP,private,DIRECT")) {
		t.Errorf("RULE-02 = %+v", f)
	}
}

func TestAC4ClashVergeOverride(t *testing.T) {
	file := fixture("ac4-clash-verge-override.yaml")
	res, code := checkJSON(t, file)
	f := one(t, res, "DNS-02")
	if f.Severity != "medium" {
		t.Errorf("DNS-02 severity = %s, want medium", f.Severity)
	}
	if !hasLoc(f, "resolver", lineOf(t, file, "- '8.8.8.8'")) {
		t.Errorf("DNS-02 does not point at 8.8.8.8: %+v", f.Locations)
	}
	noneAtOrAbove(t, res, "RULE-01", "RULE-02", "RULE-03", "RULE-04")
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}

func TestAC5ClassicalIPFirst(t *testing.T) {
	file := fixture("ac5-classical-ip-first.yaml")
	res, _ := checkJSON(t, file)
	f := one(t, res, "RULE-03")
	if !hasLoc(f, "trigger", lineOf(t, file, "- RULE-SET,telegram,PROXY")) {
		t.Errorf("RULE-03 trigger location wrong: %+v", f.Locations)
	}
	if !hasLoc(f, "trigger-entry", lineOf(t, file, "- IP-CIDR,91.108.4.0/22")) {
		t.Errorf("RULE-03 entry location wrong: %+v", f.Locations)
	}
	if f.Severity != "medium" { // nameserver are CN encrypted → RULE-01 row
		t.Errorf("RULE-03 severity = %s, want medium", f.Severity)
	}

	res, _ = checkJSON(t, fixture("ac5-classical-ip-first-no-resolve.yaml"))
	noneAtOrAbove(t, res, "RULE-03")
}

func TestAC6LogicRules(t *testing.T) {
	file := fixture("ac6-and.yaml")
	res, _ := checkJSON(t, file)
	noneAtOrAbove(t, res, "RULE-01", "RULE-02")
	f := one(t, res, "RULE-04")
	if f.Severity != "medium" { // conditional → RULE-02 row, plain resolver
		t.Errorf("AND RULE-04 severity = %s, want medium", f.Severity)
	}
	if !strings.Contains(f.Message, "DOMAIN-SUFFIX,a.com") {
		t.Errorf("AND RULE-04 should name the a.com guard: %s", f.Message)
	}
	if !hasLoc(f, "trigger", lineOf(t, file, "- AND,((DOMAIN-SUFFIX,a.com),(IP-CIDR,1.0.0.0/8)),DIRECT")) {
		t.Errorf("AND RULE-04 location wrong: %+v", f.Locations)
	}

	// The AND rule only resolves domains under a.com.
	tr, _ := traceJSON(t, file, "www.a.com")
	if tr.Steps[0].Resolution == nil {
		t.Errorf("www.a.com should be resolved at the AND rule")
	}
	tr, _ = traceJSON(t, file, "www.google.com")
	if tr.Steps[0].Resolution != nil {
		t.Errorf("www.google.com must not be resolved at the AND rule")
	}

	file = fixture("ac6-or.yaml")
	res, _ = checkJSON(t, file)
	f = one(t, res, "RULE-04")
	if f.Severity != "high" { // always → RULE-01 row, plain resolver
		t.Errorf("OR RULE-04 severity = %s, want high", f.Severity)
	}
	if !hasLoc(f, "trigger", lineOf(t, file, "- OR,((IP-CIDR,1.0.0.0/8),(DOMAIN,b.com)),DIRECT")) {
		t.Errorf("OR RULE-04 location wrong: %+v", f.Locations)
	}
}

func TestAC7KeyTypo(t *testing.T) {
	file := fixture("ac7-key-typo.yaml")
	res, _ := checkJSON(t, file)
	f := one(t, res, "CFG-01")
	if !strings.Contains(f.Message, "nameserver-policy") || !strings.Contains(f.Fix, "nameserver-policy") {
		t.Errorf("CFG-01 should suggest nameserver-policy: %s / %s", f.Message, f.Fix)
	}
	if f.Locations[0].Line != lineOf(t, file, "nameserver-police:") {
		t.Errorf("CFG-01 line = %d", f.Locations[0].Line)
	}
}

func TestAC8LoadFailures(t *testing.T) {
	file := fixture("ac8-respect-rules.yaml")
	res, code := checkJSON(t, file)
	f := one(t, res, "DNS-06")
	if f.Severity != "error" || f.Locations[0].Line != lineOf(t, file, "respect-rules: true") {
		t.Errorf("DNS-06 = %+v", f)
	}
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}

	file = fixture("ac8-default-ns-domain.yaml")
	res, _ = checkJSON(t, file)
	f = one(t, res, "DNS-08")
	if f.Severity != "error" || f.Locations[0].Line != lineOf(t, file, "- dns.alidns.com") {
		t.Errorf("DNS-08 = %+v", f)
	}

	res, code = checkJSON(t, fixture("ac8-default-ns-tls-ip.yaml"))
	noneAtOrAbove(t, res, "DNS-08")
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
}

func TestAC9NoDNSSection(t *testing.T) {
	file := fixture("ac9-no-dns.yaml")
	res, code := checkJSON(t, file)
	one(t, res, "DNS-01")
	f := one(t, res, "RULE-01")
	if f.Severity != "high" {
		t.Errorf("RULE-01 severity = %s, want high (plain system DNS)", f.Severity)
	}
	if !hasLoc(f, "trigger", lineOf(t, file, "- GEOIP,CN,DIRECT")) {
		t.Errorf("RULE-01 location wrong: %+v", f.Locations)
	}
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}

	res, _ = checkJSON(t, fixture("ac9-no-dns-match-only.yaml"))
	one(t, res, "DNS-01")
	if f := one(t, res, "RULE-02"); f.Severity != "medium" {
		t.Errorf("RULE-02 severity = %s, want medium (plain system DNS)", f.Severity)
	}
}

func TestAC10Trace(t *testing.T) {
	file := fixture("ac1-geoip-without-no-resolve.yaml")
	geoipLine := lineOf(t, file, "- GEOIP,private,🎯 全球直连")

	// Text output, GeoSite.dat absent.
	out, code := runCLI(t, "trace", file, "www.youtube.com")
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	for _, want := range []string{"8.8.8.8", "明文", "https://doh.pub/dns-query", "加密·国内", "GeoSite.dat 不存在", "[未知]", "泄露等级：高"} {
		if !strings.Contains(out, want) {
			t.Errorf("trace output lacks %q:\n%s", want, out)
		}
	}

	tr, _ := traceJSON(t, file, "www.youtube.com")
	var resStep *jsonStep
	for i := range tr.Steps {
		if tr.Steps[i].Resolution != nil {
			resStep = &tr.Steps[i]
			break
		}
	}
	if resStep == nil || resStep.Line != geoipLine {
		t.Fatalf("resolution should happen at the GEOIP rule (line %d): %+v", geoipLine, tr.Steps)
	}
	grades := map[string]string{}
	for _, s := range resStep.Resolution.Servers {
		grades[s.Server] = s.Grade
	}
	if grades["8.8.8.8"] != "plain" || grades["https://doh.pub/dns-query"] != "enc-cn" {
		t.Errorf("resolver grades = %v", grades)
	}
	var geositeStep *jsonStep
	for i := range tr.Steps {
		if strings.HasPrefix(tr.Steps[i].Rule, "GEOSITE,") {
			geositeStep = &tr.Steps[i]
		}
	}
	if geositeStep == nil || geositeStep.Outcome != "unknown" || geositeStep.Reason != ruledata.ReasonGeoSiteMissing {
		t.Errorf("GEOSITE step = %+v", geositeStep)
	}
	if tr.Verdict.Code != "leak" || tr.Verdict.Severity != "high" || !tr.Verdict.Uncertain {
		t.Errorf("verdict = %+v", tr.Verdict)
	}

	// With a GeoSite.dat in --home, the GEOSITE rule is matched exactly.
	home := t.TempDir()
	dat := testutil.GeoSiteDat(map[string][]testutil.GeoDomain{
		"YOUTUBE": {{Type: testutil.GeoSuffix, Value: "youtube.com"}},
		"CN":      {{Type: testutil.GeoSuffix, Value: "baidu.com"}},
	})
	if err := testutil.WriteFile(filepath.Join(home, "GeoSite.dat"), dat); err != nil {
		t.Fatal(err)
	}
	tr, _ = traceJSON(t, file, "www.youtube.com", "--home", home)
	if tr.Verdict.FinalRule != "GEOSITE,youtube,🚀 默认代理" || tr.Verdict.Code != "leak" || tr.Verdict.Severity != "high" || tr.Verdict.Uncertain {
		t.Errorf("verdict with GeoSite.dat = %+v", tr.Verdict)
	}
}

func TestAC11JSON(t *testing.T) {
	res, _ := checkJSON(t, fixture("ac1-geoip-without-no-resolve.yaml"))
	if len(res.Findings) == 0 {
		t.Fatal("no findings")
	}
	valid := map[string]bool{"error": true, "high": true, "medium": true, "low": true, "info": true}
	for _, f := range res.Findings {
		if f.ID == "" || !valid[f.Severity] || f.Message == "" || f.Fix == "" || len(f.Locations) == 0 {
			t.Errorf("incomplete finding: %+v", f)
		}
		for _, l := range f.Locations {
			if l.File == "" || l.Line <= 0 {
				t.Errorf("incomplete location: %+v", l)
			}
		}
	}
	if res.Summary["high"] != 1 || res.Summary["medium"] != 1 {
		t.Errorf("summary = %v", res.Summary)
	}
}

func TestAC12Encrypted(t *testing.T) {
	file := fixture("ac12-encrypted.yaml")
	res, code := checkJSON(t, file)
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if f := one(t, res, "CFG-02"); f.Severity != "error" {
		t.Errorf("CFG-02 severity = %s", f.Severity)
	}
	if _, code := runCLI(t, "trace", file, "a.com"); code != 2 {
		t.Errorf("trace exit code = %d, want 2", code)
	}
}

func TestAC14Mrs(t *testing.T) {
	home := t.TempDir()
	src, err := os.ReadFile(fixture("ac14-mrs.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(home, "config.yaml")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(file, src, 0o644))

	google, err := testutil.DomainMrs([]string{"+.google.com", "+.youtube.com"})
	must(err)
	must(testutil.WriteFile(ruledata.CachePath(home, "https://example.com/rules/google.mrs"), google))
	tg, err := testutil.IPCIDRMrs([]string{"91.108.4.0/22", "149.154.160.0/20"})
	must(err)
	must(testutil.WriteFile(ruledata.CachePath(home, "https://example.com/rules/telegram-ip.mrs"), tg))
	local, err := testutil.DomainMrs([]string{"+.local-proxy.test"})
	must(err)
	must(testutil.WriteFile(filepath.Join(home, "ruleset", "local.mrs"), local))

	// ipcidr .mrs without no-resolve → always triggers.
	res, code := checkJSON(t, file)
	f := one(t, res, "RULE-01")
	if !hasLoc(f, "trigger", lineOf(t, file, "- RULE-SET,telegram_ip,PROXY")) ||
		!hasLoc(f, "affected", lineOf(t, file, "- RULE-SET,local_domain,PROXY")) {
		t.Errorf("RULE-01 locations = %+v", f.Locations)
	}
	if f.Severity != "high" || code != 1 {
		t.Errorf("RULE-01 severity = %s, exit = %d", f.Severity, code)
	}

	// domain .mrs (http cache): matched before any resolution.
	tr, _ := traceJSON(t, file, "www.google.com")
	if tr.Steps[0].Outcome != "match" || tr.Verdict.Code != "proxy" || tr.Verdict.Uncertain {
		t.Errorf("www.google.com trace = %+v", tr)
	}
	// domain .mrs (file path): matched after the ipcidr set resolved it.
	tr, _ = traceJSON(t, file, "a.local-proxy.test")
	if tr.Steps[0].Outcome != "no-match" || tr.Steps[1].Resolution == nil || tr.Steps[2].Outcome != "match" {
		t.Errorf("a.local-proxy.test steps = %+v", tr.Steps)
	}
	if tr.Verdict.Code != "leak" || tr.Verdict.Severity != "high" {
		t.Errorf("a.local-proxy.test verdict = %+v", tr.Verdict)
	}

	// Without the cache files the domain sets are unknown.
	tr, _ = traceJSON(t, fixture("ac14-mrs.yaml"), "www.google.com")
	if tr.Steps[0].Outcome != "unknown" || !tr.Verdict.Uncertain {
		t.Errorf("trace without cache = %+v", tr)
	}
}

func TestUsageAndArgs(t *testing.T) {
	if _, code := runCLI(t); code != 2 {
		t.Errorf("no args: exit %d", code)
	}
	if _, code := runCLI(t, "check"); code != 2 {
		t.Errorf("missing file: exit %d", code)
	}
	if _, code := runCLI(t, "trace", fixture("ac3-recommended.yaml"), " "); code != 2 {
		t.Errorf("empty domain: exit %d", code)
	}
	if _, code := runCLI(t, "check", "--format", "xml", fixture("ac3-recommended.yaml")); code != 2 {
		t.Errorf("bad format: exit %d", code)
	}
	if _, code := runCLI(t, "check", filepath.Join(t.TempDir(), "missing.yaml")); code != 2 {
		t.Errorf("missing file: exit %d", code)
	}
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("rules: [\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, code := runCLI(t, "check", bad); code != 2 {
		t.Errorf("invalid YAML: exit %d", code)
	}
	// Flags after positional arguments are accepted.
	if out, code := runCLI(t, "check", fixture("ac3-recommended.yaml"), "--format", "json"); code != 0 || !strings.HasPrefix(out, "{") {
		t.Errorf("flags after args: exit %d, out %q", code, out)
	}
}
