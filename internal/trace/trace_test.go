package trace

import (
	"path/filepath"
	"strings"
	"testing"

	"dnsnitch/internal/analyze"
	"dnsnitch/internal/config"
	"dnsnitch/internal/dnsserver"
	"dnsnitch/internal/model"
	"dnsnitch/internal/testutil"
)

const head = `proxies:
  - {name: hk, type: ss, server: a.example.com, port: 1, cipher: x, password: y}
proxy-groups:
  - {name: PROXY, type: select, proxies: [hk]}
`

func run(t *testing.T, yaml, domain string, geosite map[string][]testutil.GeoDomain) *Result {
	t.Helper()
	cfg, err := config.Parse("cfg.yaml", []byte(head+yaml))
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	if geosite != nil {
		if err := testutil.WriteFile(filepath.Join(home, "GeoSite.dat"), testutil.GeoSiteDat(geosite)); err != nil {
			t.Fatal(err)
		}
	}
	return Run(analyze.NewEnv(cfg, home), domain)
}

func TestLeakAndPolicy(t *testing.T) {
	yaml := `
dns:
  enable: true
  nameserver: ['https://1.1.1.1/dns-query#PROXY']
  nameserver-policy:
    'geosite:cn': 223.5.5.5
    '+.example.org': 'https://doh.pub/dns-query'
rules:
  - DOMAIN,direct.com,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,PROXY
`
	geo := map[string][]testutil.GeoDomain{"CN": {{Type: testutil.GeoSuffix, Value: "baidu.com"}}}

	r := run(t, yaml, "www.example.org", geo)
	if r.Verdict != VerdictLeak || r.Severity != model.Medium || r.ResolutionStep != 1 {
		t.Fatalf("result = %+v", r)
	}
	if sel := r.Resolution.Selection; sel.Source != dnsserver.SourcePolicy || sel.Policy.Key != "+.example.org" {
		t.Errorf("selection = %+v", sel)
	}

	r = run(t, yaml, "www.google.com", geo)
	if r.Verdict != VerdictRedundant || r.Severity != model.Info {
		t.Errorf("google = %+v", r)
	}

	r = run(t, yaml, "www.baidu.com", geo)
	if r.Resolution.Selection.Policy == nil || r.Resolution.Level != dnsserver.LevelPlain || r.Verdict != VerdictLeak {
		t.Errorf("baidu = %+v", r)
	}

	r = run(t, yaml, "direct.com", geo)
	if r.Verdict != VerdictDirect || r.Resolution != nil {
		t.Errorf("direct.com = %+v", r)
	}

	// Without GeoSite.dat the geosite policy key is uncertain.
	r = run(t, yaml, "www.google.com", nil)
	found := false
	for _, n := range r.Notes {
		if n.Key == "trace-policy-uncertain" {
			found = true
		}
	}
	if !found {
		t.Errorf("missing policy-uncertain note: %+v", r.Notes)
	}
}

func TestHostsPassAndSubRules(t *testing.T) {
	yaml := `
hosts:
  '+.internal.test': 10.0.0.1
dns: {enable: true, nameserver: [8.8.8.8]}
sub-rules:
  web:
    - DOMAIN-SUFFIX,skip.com,PASS
    - DOMAIN-SUFFIX,sub.com,PROXY
rules:
  - DOMAIN-SUFFIX,pass.com,PASS
  - SUB-RULE,(DOMAIN-KEYWORD,s),web
  - GEOIP,CN,DIRECT
  - MATCH,PROXY
`
	r := run(t, yaml, "a.internal.test", nil)
	if r.Hosts == nil || r.Verdict != VerdictHostsProxy || r.Resolution == nil || !r.Resolution.ViaHosts {
		t.Errorf("hosts = %+v", r)
	}

	r = run(t, yaml, "x.pass.com", nil)
	if r.Steps[0].Outcome != OutPass || r.Verdict != VerdictLeak || r.Severity != model.High {
		t.Errorf("pass = %+v", r)
	}

	r = run(t, yaml, "a.sub.com", nil)
	if r.FinalRule == nil || r.FinalRule.Raw != "DOMAIN-SUFFIX,sub.com,PROXY" || r.Verdict != VerdictProxy {
		t.Errorf("sub-rule = %+v", r)
	}
	if r.Steps[1].Depth != 0 || r.Steps[2].Depth != 1 || r.Steps[3].Depth != 1 {
		t.Errorf("sub-rule depth = %+v", r.Steps)
	}
}

func TestCircularSubRules(t *testing.T) {
	// mihomo refuses circular sub-rules; the trace must still terminate
	// quickly instead of re-entering the chain.
	var b strings.Builder
	b.WriteString("dns: {enable: true, nameserver: [8.8.8.8]}\nsub-rules:\n  loop:\n")
	for i := 0; i < 20; i++ {
		b.WriteString("    - SUB-RULE,(DOMAIN-SUFFIX,a.com),loop\n")
	}
	b.WriteString("    - IP-CIDR,1.0.0.0/8,PROXY\nrules:\n  - SUB-RULE,(DOMAIN-SUFFIX,a.com),loop\n  - MATCH,PROXY\n")
	r := run(t, b.String(), "www.a.com", nil)
	if r.Verdict != VerdictLeak || len(r.Steps) > 50 {
		t.Errorf("verdict = %s, %d steps", r.Verdict, len(r.Steps))
	}
}

func TestClassicalAndAssumptions(t *testing.T) {
	yaml := `
dns: {enable: false}
rule-providers:
  tg: {type: inline, behavior: classical, payload: ['DOMAIN,t.me', 'IP-CIDR,91.108.4.0/22', 'DOMAIN-SUFFIX,telegram.org']}
rules:
  - DST-PORT,22,DIRECT
  - RULE-SET,tg,PROXY
  - MATCH,DIRECT
`
	r := run(t, yaml, "t.me", nil)
	if r.Verdict != VerdictProxy || r.Resolution != nil {
		t.Errorf("t.me = %+v", r)
	}
	r = run(t, yaml, "web.telegram.org", nil)
	if r.Verdict != VerdictLeak || r.Severity != model.High || r.Resolution.Selection.Source != dnsserver.SourceSystem {
		t.Errorf("telegram.org = %+v", r)
	}
	notes := map[string]bool{}
	for _, n := range r.Notes {
		notes[n.Key] = true
	}
	if !notes["trace-conn-assumed"] {
		t.Errorf("notes = %v", notes)
	}
	r = run(t, yaml, "other.com", nil)
	notes = map[string]bool{}
	for _, n := range r.Notes {
		notes[n.Key] = true
	}
	if r.Verdict != VerdictResolvedDirect || r.FinalRule.Raw != "MATCH,DIRECT" || !notes["trace-ip-assumed"] {
		t.Errorf("other.com = %+v", r)
	}
}

func TestUnknownImpact(t *testing.T) {
	yaml := `
dns: {enable: true, nameserver: [8.8.8.8]}
rule-providers:
  d: {type: http, behavior: domain, url: 'https://e/d'}
rules:
  - RULE-SET,d,DIRECT
  - GEOIP,CN,DIRECT
  - GEOSITE,google,PROXY
  - MATCH,PROXY
`
	r := run(t, yaml, "www.google.com", nil)
	if !r.Uncertain || r.Impact != ImpactBeforeResolution || len(r.Unknowns) != 2 {
		t.Errorf("result = %+v", r)
	}
	if r.Steps[0].DataFile == "" {
		t.Errorf("missing data file for unknown rule-set")
	}
}
