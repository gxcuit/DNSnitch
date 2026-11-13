package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"dnsnitch/internal/app"
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
	AutoFix   bool      `json:"auto_fix"`
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

// ---- fix (automatic repair, task 11-13-config-auto-repair) ----

type jsonEdit struct {
	ID     string `json:"id"`
	Line   int    `json:"line"`
	Path   string `json:"path"`
	Before string `json:"before"`
	After  string `json:"after"`
}

type jsonSkip struct {
	ID         string `json:"id"`
	Line       int    `json:"line"`
	Path       string `json:"path"`
	Reason     string `json:"reason"`
	ReasonText string `json:"reason_text"`
}

type jsonFix struct {
	File             string     `json:"file"`
	Output           string     `json:"output"`
	Written          bool       `json:"written"`
	NotWrittenReason string     `json:"not_written_reason"`
	Edits            []jsonEdit `json:"edits"`
	Skipped          []jsonSkip `json:"skipped"`
	Diff             []struct {
		OldStart int `json:"old_start"`
		OldLines int `json:"old_lines"`
		NewStart int `json:"new_start"`
		NewLines int `json:"new_lines"`
		Lines    []struct {
			Op   string `json:"op"`
			Text string `json:"text"`
		} `json:"lines"`
	} `json:"diff"`
	Before    map[string]int `json:"before"`
	After     map[string]int `json:"after"`
	Remaining []jsonFinding  `json:"remaining"`
}

// runCLIErr runs the CLI and returns stdout, stderr and the exit code.
func runCLIErr(args ...string) (string, string, int) {
	var out, errOut bytes.Buffer
	code := run(args, &out, &errOut)
	return out.String(), errOut.String(), code
}

func fixJSON(t *testing.T, args ...string) (jsonFix, int) {
	t.Helper()
	out, code := runCLI(t, append([]string{"fix", "--format", "json"}, args...)...)
	var res jsonFix
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("invalid JSON (%v):\n%s", err, out)
	}
	return res, code
}

func readFile(t *testing.T, file string) []byte {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// copyTo copies src into a new temporary directory as name.
func copyTo(t *testing.T, src, name string) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(dst, readFile(t, src), 0o644); err != nil {
		t.Fatal(err)
	}
	return dst
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func assertMissing(t *testing.T, file string) {
	t.Helper()
	if _, err := os.Stat(file); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("%s should not exist (err = %v)", file, err)
	}
}

// replaceEach applies old/new pairs to s; each old must occur exactly once.
func replaceEach(t *testing.T, s string, pairs ...string) string {
	t.Helper()
	for i := 0; i+1 < len(pairs); i += 2 {
		if n := strings.Count(s, pairs[i]); n != 1 {
			t.Fatalf("bad test: %q occurs %d times", pairs[i], n)
		}
		s = strings.Replace(s, pairs[i], pairs[i+1], 1)
	}
	return s
}

func edit(res jsonFix, id string, line int) *jsonEdit {
	for i, e := range res.Edits {
		if e.ID == id && e.Line == line {
			return &res.Edits[i]
		}
	}
	return nil
}

func remains(res jsonFix, id string) bool {
	for _, f := range res.Remaining {
		if f.ID == id {
			return true
		}
	}
	return false
}

var leakyExample = filepath.Join("..", "..", "examples", "leaky-config.yaml")

// AC1: --dry-run shows the GEOIP rule with ",no-resolve" and 8.8.8.8
// removed, the fixed text has neither finding, and nothing is written.
func TestFixAC1DryRun(t *testing.T) {
	file := fixture("ac1-geoip-without-no-resolve.yaml")
	orig := readFile(t, file)
	def := app.DefaultFixOutput(file)
	t.Cleanup(func() { os.Remove(def) }) // only matters if the test fails
	geoip, plain := lineOf(t, file, "- GEOIP,private,🎯 全球直连"), lineOf(t, file, "- 8.8.8.8")

	out, code := runCLI(t, "fix", file, "--dry-run")
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	for _, want := range []string{
		"RULE-01  " + file + ":" + strconv.Itoa(geoip),
		"DNS-02  " + file + ":" + strconv.Itoa(plain),
		"--- " + file + "\n+++ " + def + "\n",
		"\n-  - GEOIP,private,🎯 全球直连\n+  - GEOIP,private,🎯 全球直连,no-resolve\n",
		"\n-    - 8.8.8.8\n",
		"修复后：错误 0，高 0，中 0，低 0，提示 0",
		"未写入：--dry-run",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	assertMissing(t, def)

	res, code := fixJSON(t, "--dry-run", file)
	if code != 0 || res.Written || res.NotWrittenReason != "dry-run" || res.Output != def || res.File != file {
		t.Errorf("result = %+v, exit %d", res, code)
	}
	if e := edit(res, "RULE-01", geoip); e == nil || e.After != "  - GEOIP,private,🎯 全球直连,no-resolve" {
		t.Errorf("RULE-01 edit = %+v (all %+v)", e, res.Edits)
	}
	if e := edit(res, "DNS-02", plain); e == nil || e.Before != "    - 8.8.8.8" || e.After != "" {
		t.Errorf("DNS-02 edit = %+v (all %+v)", e, res.Edits)
	}
	if len(res.Edits) != 2 || len(res.Skipped) != 0 {
		t.Errorf("edits = %+v, skipped = %+v", res.Edits, res.Skipped)
	}
	if remains(res, "RULE-01") || remains(res, "DNS-02") {
		t.Errorf("remaining = %+v", res.Remaining)
	}
	if res.Before["high"] != 1 || res.Before["medium"] != 1 || res.After["high"] != 0 || res.After["medium"] != 0 {
		t.Errorf("before = %v, after = %v", res.Before, res.After)
	}
	assertMissing(t, def)
	if !bytes.Equal(readFile(t, file), orig) {
		t.Error("the config was modified")
	}

	// In a directory of its own nothing appears next to the config, also
	// with -o.
	cfg := copyTo(t, file, "config.yaml")
	other := filepath.Join(t.TempDir(), "out.yaml")
	if _, code := runCLI(t, "fix", "--dry-run", cfg); code != 0 {
		t.Errorf("exit code = %d", code)
	}
	if res, _ := fixJSON(t, cfg, "--dry-run", "-o", other); res.Output != other || res.Written {
		t.Errorf("-o with --dry-run: %+v", res)
	}
	if names := dirNames(t, filepath.Dir(cfg)); len(names) != 1 {
		t.Errorf("files after --dry-run: %v", names)
	}
	assertMissing(t, other)
}

// AC2: the fixed config is written to the -o path, checks clean, and the
// original is unchanged.
func TestFixAC2WritesNewFile(t *testing.T) {
	orig := readFile(t, leakyExample)
	want := replaceEach(t, string(orig),
		"  - GEOIP,private,DIRECT\n", "  - GEOIP,private,DIRECT,no-resolve\n",
		"    - 8.8.8.8\n", "")
	dst := filepath.Join(t.TempDir(), "out.yaml")
	out, code := runCLI(t, "fix", leakyExample, "-o", dst)
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out, "已写入："+dst) {
		t.Errorf("output does not name the written file:\n%s", out)
	}
	if got := string(readFile(t, dst)); got != want {
		t.Errorf("written file:\n%s\nwant:\n%s", got, want)
	}
	res, code := checkJSON(t, dst)
	if code != 0 {
		t.Errorf("check of the fixed file: exit %d, findings %+v", code, res.Findings)
	}
	if !bytes.Equal(readFile(t, leakyExample), orig) {
		t.Error("examples/leaky-config.yaml was modified")
	}

	// Without -o the file goes next to the config as <name>.fixed.yaml.
	cfg := copyTo(t, leakyExample, "config.yaml")
	res2, code := fixJSON(t, cfg)
	def := filepath.Join(filepath.Dir(cfg), "config.fixed.yaml")
	if code != 0 || !res2.Written || res2.NotWrittenReason != "" || res2.Output != def {
		t.Errorf("default output: %+v, exit %d", res2, code)
	}
	if got := string(readFile(t, def)); got != want {
		t.Errorf("default output content:\n%s", got)
	}
	// Remaining locations in the config refer to the fixed text, i.e. the
	// output file.
	for _, f := range res2.Remaining {
		for _, l := range f.Locations {
			if l.File == cfg {
				t.Errorf("remaining %s points at the original: %+v", f.ID, l)
			}
		}
	}
}

// AC3–AC7: rules, logic rules (two passes for the OR rule), a classical
// rule-set reference, DNS lists and a key typo are fixed in place; every
// other byte (comments, quotes, blank lines, CRLF, BOM) is unchanged.
func TestFixPreservesBytes(t *testing.T) {
	src := string(readFile(t, fixture("ac15-fix-mixed.yaml")))
	if strings.Contains(src, "\r") {
		t.Fatal("fixture must use LF; CRLF is generated below")
	}
	want := replaceEach(t, src,
		"'GEOIP,private,DIRECT'", "'GEOIP,private,DIRECT,no-resolve'",
		"(IP-CIDR,1.0.0.0/8)", "(IP-CIDR,1.0.0.0/8,no-resolve)",
		"(IP-CIDR,2.0.0.0/8)", "(IP-CIDR,2.0.0.0/8,no-resolve)",
		"(IP-CIDR,3.0.0.0/8)", "(IP-CIDR,3.0.0.0/8,no-resolve)",
		"  - RULE-SET,telegram,PROXY\n", "  - RULE-SET,telegram,PROXY,no-resolve\n",
		"    - 8.8.8.8                # 明文\n", "",
		"[tls://1.1.1.1#PROXY, 114.114.114.114]", "[tls://1.1.1.1#PROXY]",
		"    - 223.5.5.5\n", "    - https://223.5.5.5/dns-query\n",
		"  nameserver-police:", "  nameserver-policy:",
	)
	for _, v := range []struct{ name, bom, eol string }{{"lf", "", "\n"}, {"crlf+bom", "\ufeff", "\r\n"}} {
		t.Run(v.name, func(t *testing.T) {
			in := v.bom + strings.ReplaceAll(src, "\n", v.eol)
			exp := v.bom + strings.ReplaceAll(want, "\n", v.eol)
			dir := t.TempDir()
			cfg, dst := filepath.Join(dir, "config.yaml"), filepath.Join(dir, "out.yaml")
			if err := os.WriteFile(cfg, []byte(in), 0o644); err != nil {
				t.Fatal(err)
			}
			res, code := fixJSON(t, cfg, "-o", dst)
			if code != 1 { // the CFG-01 typo whose target key exists remains (medium)
				t.Errorf("exit code = %d, want 1", code)
			}
			if got := string(readFile(t, dst)); got != exp {
				t.Errorf("fixed bytes differ:\n%q\nwant:\n%q", got, exp)
			}
			if string(readFile(t, cfg)) != in {
				t.Error("the config was modified")
			}
			var ids []string
			for _, e := range res.Edits {
				ids = append(ids, e.ID)
			}
			if got := strings.Join(ids, " "); got != "RULE-01 RULE-04 RULE-04 RULE-03 DNS-02 DNS-02 DNS-09 CFG-01" {
				t.Errorf("edit IDs = %s", got)
			}
			if len(res.Skipped) != 1 || res.Skipped[0].ID != "CFG-01" || res.Skipped[0].Path != "dns.enhanced-mod" || res.Skipped[0].Reason != "key-exists" {
				t.Errorf("skipped = %+v", res.Skipped)
			}
			for _, id := range []string{"RULE-01", "RULE-03", "RULE-04", "DNS-02", "DNS-09"} {
				if remains(res, id) {
					t.Errorf("%s remains: %+v", id, res.Remaining)
				}
			}
			if !res.Written || res.Output != dst {
				t.Errorf("written = %v, output = %s", res.Written, res.Output)
			}
		})
	}
}

// AC8: anchors / aliases / merges and multi-line values are skipped with a
// reason; the other fixes are still applied.
func TestFixSkips(t *testing.T) {
	file := fixture("ac15-fix-skips.yaml")
	dst := filepath.Join(t.TempDir(), "out.yaml")
	res, code := fixJSON(t, file, "-o", dst)
	if code != 1 { // the skipped RULE-01 is still high
		t.Errorf("exit code = %d, want 1", code)
	}
	want := map[string]string{
		"DNS-02@dns.nameserver[0]":              "shared-node",
		"DNS-09@dns.proxy-server-nameserver[0]": "multiline",
		"RULE-01@rules[1]":                      "multiline",
	}
	if len(res.Skipped) != len(want) {
		t.Errorf("skipped = %+v", res.Skipped)
	}
	for _, s := range res.Skipped {
		if want[s.ID+"@"+s.Path] != s.Reason || s.ReasonText == "" || s.Line <= 0 {
			t.Errorf("skip %+v", s)
		}
	}
	if edit(res, "DNS-02", lineOf(t, file, "- 9.9.9.9")) == nil || edit(res, "RULE-01", lineOf(t, file, "- GEOIP,private,DIRECT")) == nil || len(res.Edits) != 2 {
		t.Errorf("edits = %+v", res.Edits)
	}
	if !res.Written {
		t.Error("the other fixes should be written")
	}

	out, _ := runCLI(t, "fix", "--dry-run", file)
	for _, want := range []string{"未自动修改（3 处）", "RULE-01  " + file + ":" + strconv.Itoa(lineOf(t, file, "- >-")) + "  rules[1]", "锚点", "多行"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

// AC9: an existing output needs --force; the config itself (any spelling)
// is never written; a verification failure writes nothing.
func TestFixOutputSafety(t *testing.T) {
	cfg := copyTo(t, leakyExample, "config.yaml")
	dir := filepath.Dir(cfg)
	orig := readFile(t, cfg)

	dst := filepath.Join(dir, "out.yaml")
	if err := os.WriteFile(dst, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code := runCLIErr("fix", cfg, "-o", dst)
	if code != 2 || stdout != "" || !strings.Contains(stderr, "--force") {
		t.Errorf("existing output: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if string(readFile(t, dst)) != "old" {
		t.Error("existing output overwritten without --force")
	}
	def := app.DefaultFixOutput(cfg)
	if err := os.WriteFile(def, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, code := runCLIErr("fix", cfg); code != 2 || string(readFile(t, def)) != "old" {
		t.Errorf("existing default output: exit %d", code)
	}
	if _, _, code := runCLIErr("fix", cfg, "-o", dst, "--force"); code != 0 || !strings.Contains(string(readFile(t, dst)), "GEOIP,private,DIRECT,no-resolve") {
		t.Errorf("--force: exit %d, content %q", code, readFile(t, dst))
	}

	sep := string(filepath.Separator)
	aliases := []string{cfg, dir + sep + "." + sep + "config.yaml"}
	upper := filepath.Join(dir, "CONFIG.YAML")
	if a, err := os.Stat(upper); err == nil {
		if b, err := os.Stat(cfg); err == nil && os.SameFile(a, b) {
			aliases = append(aliases, upper)
		}
	}
	if runtime.GOOS == "windows" && len(aliases) != 3 {
		t.Error("a case-different alias should exist on Windows")
	}
	for _, a := range aliases {
		for _, extra := range [][]string{nil, {"--force"}} {
			args := append([]string{"fix", cfg, "--output", a}, extra...)
			if _, stderr, code := runCLIErr(args...); code != 2 || !strings.Contains(stderr, "就是原配置文件") {
				t.Errorf("%v: exit %d, stderr %q", args, code, stderr)
			}
		}
	}
	if !bytes.Equal(readFile(t, cfg), orig) {
		t.Error("the config was modified")
	}

	// Verification failure. The real detection (a fixed text with a new
	// error finding) is tested in internal/app; here the outcome is injected.
	old := planFix
	planFix = func(file, home string) (app.FixOutcome, app.ErrorKind, error) {
		out, _, _ := app.PlanFix(file, home)
		return out, app.ErrVerify, errors.New("fixed config has a new DNS-06 finding")
	}
	t.Cleanup(func() { planFix = old })
	verify := filepath.Join(dir, "verify.yaml")
	stdout, stderr, code = runCLIErr("fix", cfg, "-o", verify, "--force")
	if code != 2 || stdout != "" || !strings.Contains(stderr, "没有通过校验") || !strings.Contains(stderr, "DNS-06") {
		t.Errorf("verify failure: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	assertMissing(t, verify)
	planFix = old

	if names := strings.Join(dirNames(t, dir), " "); names != "config.fixed.yaml config.yaml out.yaml" {
		t.Errorf("files left: %s", names)
	}
	if !bytes.Equal(readFile(t, cfg), orig) {
		t.Error("the config was modified")
	}
}

// AC10: fix JSON has every documented field; check JSON has auto_fix and
// the check text names the number of fixable findings.
func TestFixJSONFields(t *testing.T) {
	file := fixture("ac15-fix-skips.yaml")
	out, code := runCLI(t, "fix", "--format", "json", "--dry-run", file)
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("invalid JSON (%v):\n%s", err, out)
	}
	hasKeys := func(what string, v any, keys ...string) {
		t.Helper()
		obj, ok := v.(map[string]any)
		if !ok {
			t.Errorf("%s is not an object: %v", what, v)
			return
		}
		for _, k := range keys {
			if _, ok := obj[k]; !ok {
				t.Errorf("%s lacks %q: %v", what, k, obj)
			}
		}
	}
	first := func(key string) any {
		t.Helper()
		arr, ok := m[key].([]any)
		if !ok || len(arr) == 0 {
			t.Fatalf("%s is not a non-empty array: %v", key, m[key])
		}
		return arr[0]
	}
	hasKeys("result", m, "file", "output", "written", "not_written_reason", "edits", "skipped", "diff", "before", "after", "remaining")
	hasKeys("edits[0]", first("edits"), "id", "line", "path", "before", "after")
	hasKeys("skipped[0]", first("skipped"), "id", "line", "path", "reason", "reason_text")
	hunk := first("diff")
	hasKeys("diff[0]", hunk, "old_start", "old_lines", "new_start", "new_lines", "lines")
	if lines, ok := hunk.(map[string]any)["lines"].([]any); ok && len(lines) > 0 {
		hasKeys("diff[0].lines[0]", lines[0], "op", "text")
	} else {
		t.Errorf("diff[0].lines = %v", hunk)
	}
	for _, k := range []string{"before", "after"} {
		hasKeys(k, m[k], "error", "high", "medium", "low", "info")
	}
	hasKeys("remaining[0]", first("remaining"), "id", "severity", "message", "locations", "fix", "notes", "auto_fix")

	// Nothing to fix: no file, reason nothing-to-fix, empty arrays.
	cfg := copyTo(t, fixture("ac3-recommended.yaml"), "config.yaml")
	out, code = runCLI(t, "fix", "--format", "json", cfg)
	if code != 0 || !strings.Contains(out, `"edits": []`) || !strings.Contains(out, `"diff": []`) {
		t.Errorf("nothing to fix: exit %d\n%s", code, out)
	}
	var res jsonFix
	if err := json.Unmarshal([]byte(out), &res); err != nil || res.Written || res.NotWrittenReason != "nothing-to-fix" {
		t.Errorf("nothing to fix: %+v (%v)", res, err)
	}
	if names := dirNames(t, filepath.Dir(cfg)); len(names) != 1 {
		t.Errorf("files after nothing to fix: %v", names)
	}

	// check: every finding carries auto_fix.
	for name, fixable := range map[string]string{
		"ac1-geoip-without-no-resolve.yaml": "DNS-02 RULE-01",
		"ac3-recommended.yaml":              "",
		// Both typos are eligible; the one whose target exists is skipped by fix.
		"ac15-fix-mixed.yaml": "CFG-01 CFG-01 DNS-02 DNS-09 RULE-01",
	} {
		out, _ := runCLI(t, "check", "--format", "json", fixture(name))
		var raw struct {
			Findings []map[string]any `json:"findings"`
		}
		if err := json.Unmarshal([]byte(out), &raw); err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, f := range raw.Findings {
			v, ok := f["auto_fix"].(bool)
			if !ok {
				t.Errorf("%s: %s has no auto_fix", name, f["id"])
			}
			if v {
				got = append(got, f["id"].(string))
			}
		}
		sort.Strings(got)
		if strings.Join(got, " ") != fixable {
			t.Errorf("%s: auto_fix on %v, want %q", name, got, fixable)
		}
	}
	if out, _ := runCLI(t, "check", fixture("ac1-geoip-without-no-resolve.yaml")); !strings.HasSuffix(out, "汇总：错误 0，高 1，中 1，低 0，提示 0\n其中 2 项可用 dnsnitch fix 自动修复。\n") {
		t.Errorf("check text lacks the fix hint:\n%s", out)
	}
	if out, _ := runCLI(t, "check", fixture("ac3-recommended.yaml")); strings.Contains(out, "dnsnitch fix") {
		t.Errorf("no fixable finding, no hint:\n%s", out)
	}
}

func TestFixArgs(t *testing.T) {
	ac3 := fixture("ac3-recommended.yaml")
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("rules: [\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "x.yaml")
	for _, args := range [][]string{
		{"check", "--output", out, ac3},
		{"check", ac3, "-o", out},
		{"check", "--dry-run", ac3},
		{"check", "--force=false", ac3},
		{"trace", "--force", ac3, "a.com"},
		{"status", "--dry-run"},
		{"fix"},
		{"fix", ac3, "extra"},
		{"fix", "--format", "xml", ac3},
		{"fix", ac3, "-o"},
		{"fix", filepath.Join(t.TempDir(), "missing.yaml")},
		{"fix", bad},
	} {
		stdout, stderr, code := runCLIErr(args...)
		if code != 2 || stdout != "" || stderr == "" {
			t.Errorf("%v: exit %d, stdout %q, stderr %q", args, code, stdout, stderr)
		}
		if (args[0] != "fix") && !strings.Contains(stderr, "只能用于 fix") {
			t.Errorf("%v: stderr %q", args, stderr)
		}
	}
	assertMissing(t, out)

	// Encrypted: CFG-02 on stdout, exit 2, like check.
	res, code := func() (jsonCheck, int) {
		out, code := runCLI(t, "fix", "--format", "json", fixture("ac12-encrypted.yaml"))
		var res jsonCheck
		if err := json.Unmarshal([]byte(out), &res); err != nil {
			t.Fatalf("invalid JSON (%v):\n%s", err, out)
		}
		return res, code
	}()
	if code != 2 || len(res.Findings) != 1 || res.Findings[0].ID != "CFG-02" {
		t.Errorf("encrypted: exit %d, %+v", code, res)
	}

	// Flags before the positional argument, long --output.
	cfg := copyTo(t, leakyExample, "config.yaml")
	dst := filepath.Join(filepath.Dir(cfg), "o.yaml")
	if r, code := fixJSON(t, "--force", "--output", dst, "--home", filepath.Dir(cfg), cfg); code != 0 || !r.Written || r.Output != dst {
		t.Errorf("flags first: exit %d, %+v", code, r)
	}
}
