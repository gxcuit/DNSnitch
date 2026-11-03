package analyze

import (
	"strings"
	"testing"

	"dnsleak/internal/config"
	"dnsleak/internal/model"
	"dnsleak/internal/ruleparse"
)

const head = `proxies:
  - {name: hk, type: ss, server: a.example.com, port: 1, cipher: x, password: y}
proxy-groups:
  - {name: PROXY, type: select, proxies: [hk]}
  - {name: AUTO, type: select, proxies: [hk, DIRECT]}
`

func env(t *testing.T, yaml string) *Env {
	t.Helper()
	cfg, err := config.Parse("cfg.yaml", []byte(head+yaml))
	if err != nil {
		t.Fatal(err)
	}
	return NewEnv(cfg, t.TempDir())
}

func rule(raw string) model.Rule { return ruleparse.Parse(raw, true) }

func ids(fs []model.Finding) map[string]model.Severity {
	m := map[string]model.Severity{}
	for _, f := range fs {
		if old, ok := m[f.ID]; !ok || f.Severity > old {
			m[f.ID] = f.Severity
		}
	}
	return m
}

func TestTriggerKinds(t *testing.T) {
	e := env(t, `
rule-providers:
  cls: {type: inline, behavior: classical, payload: ['DOMAIN,x.com', 'IP-CIDR,1.0.0.0/8', 'DOMAIN-SUFFIX,y.com']}
  clsnr: {type: inline, behavior: classical, payload: ['DOMAIN,x.com', 'IP-CIDR,1.0.0.0/8,no-resolve']}
  ip: {type: http, behavior: ipcidr, url: 'https://e/ip.yaml'}
  dom: {type: http, behavior: domain, url: 'https://e/d.yaml'}
  missing: {type: http, behavior: classical, url: 'https://e/c.yaml'}
  andset: {type: inline, behavior: classical, payload: ['AND,((DOMAIN,z.com),(GEOIP,US))']}
sub-rules:
  s1:
    - GEOIP,CN,DIRECT
`)
	tests := []struct {
		raw    string
		kind   Kind
		point  string
		except int
		guard  int
		after  int
		set    string
	}{
		{raw: "GEOIP,CN,DIRECT", kind: KindAlways, point: "GEOIP,CN,DIRECT"},
		{raw: "GEOIP,CN,DIRECT,no-resolve", kind: KindNone},
		{raw: "IP-CIDR,1.0.0.0/8,DIRECT,src", kind: KindNone},
		{raw: "SRC-IP-CIDR,1.0.0.0/8,DIRECT", kind: KindNone},
		{raw: "IP-ASN,13335,PROXY", kind: KindAlways, point: "IP-ASN,13335,PROXY"},
		{raw: "IP-SUFFIX,1.1.1.1/24,PROXY", kind: KindAlways, point: "IP-SUFFIX,1.1.1.1/24,PROXY"},
		{raw: "DOMAIN,a.com,PROXY", kind: KindNone},
		{raw: "PROCESS-NAME,curl,DIRECT", kind: KindNone},
		{raw: "RULE-SET,ip,DIRECT", kind: KindAlways, point: "RULE-SET,ip,DIRECT"},
		{raw: "RULE-SET,ip,DIRECT,no-resolve", kind: KindNone},
		{raw: "RULE-SET,dom,PROXY", kind: KindNone},
		{raw: "RULE-SET,cls,PROXY", kind: KindAlways, point: "IP-CIDR,1.0.0.0/8", except: 1, after: 1, set: "cls"},
		{raw: "RULE-SET,cls,PROXY,no-resolve", kind: KindNone},
		{raw: "RULE-SET,clsnr,PROXY", kind: KindNone},
		{raw: "RULE-SET,missing,PROXY", kind: KindUnknown},
		{raw: "RULE-SET,andset,PROXY", kind: KindConditional, point: "GEOIP,US", guard: 1, set: "andset"},
		// AC6
		{raw: "AND,((DOMAIN-SUFFIX,a.com),(IP-CIDR,1.0.0.0/8)),DIRECT", kind: KindConditional, point: "IP-CIDR,1.0.0.0/8", guard: 1},
		{raw: "OR,((IP-CIDR,1.0.0.0/8),(DOMAIN,b.com)),DIRECT", kind: KindAlways, point: "IP-CIDR,1.0.0.0/8", after: 1},
		{raw: "AND,((IP-CIDR,1.0.0.0/8),(DOMAIN,b.com)),DIRECT", kind: KindAlways, point: "IP-CIDR,1.0.0.0/8"},
		{raw: "OR,((DOMAIN,b.com),(IP-CIDR,1.0.0.0/8)),DIRECT", kind: KindAlways, point: "IP-CIDR,1.0.0.0/8", except: 1},
		{raw: "AND,((DOMAIN,b.com),(IP-CIDR,1.0.0.0/8,no-resolve)),DIRECT", kind: KindNone},
		{raw: "NOT,((GEOIP,CN)),PROXY", kind: KindAlways, point: "GEOIP,CN"},
		{raw: "SUB-RULE,(GEOIP,CN),s1", kind: KindAlways, point: "GEOIP,CN"},
		{raw: "SUB-RULE,(NETWORK,tcp),s1", kind: KindConditional, point: "GEOIP,CN,DIRECT", guard: 1},
	}
	for _, tt := range tests {
		tr := e.TriggerOf(rule(tt.raw))
		if tr.Kind != tt.kind {
			t.Errorf("%s: kind %d, want %d", tt.raw, tr.Kind, tt.kind)
			continue
		}
		if tt.point != "" && (tr.Point == nil || tr.Point.Raw != tt.point) {
			t.Errorf("%s: point %+v, want %s", tt.raw, tr.Point, tt.point)
		}
		if len(tr.Except) != tt.except || len(tr.Guard) != tt.guard || len(tr.After) != tt.after || tr.Set != tt.set {
			t.Errorf("%s: except=%d guard=%d after=%d set=%q", tt.raw, len(tr.Except), len(tr.Guard), len(tr.After), tr.Set)
		}
	}
	// the AND guard is the a.com condition
	tr := e.TriggerOf(rule("AND,((DOMAIN-SUFFIX,a.com),(IP-CIDR,1.0.0.0/8)),DIRECT"))
	if tr.Guard[0].Raw != "DOMAIN-SUFFIX,a.com" {
		t.Errorf("guard = %+v", tr.Guard)
	}
}

func TestRuleChain(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want map[string]model.Severity
		not  []string
	}{
		{
			name: "plain resolver, domain rules after trigger",
			yaml: "dns: {enable: true, nameserver: [8.8.8.8]}\nrules:\n  - GEOIP,CN,DIRECT\n  - GEOSITE,google,PROXY\n  - MATCH,DIRECT\n",
			want: map[string]model.Severity{"RULE-01": model.High, "RULE-06": model.Info, "DNS-02": model.Medium},
			not:  []string{"RULE-02"},
		},
		{
			name: "cn encrypted resolver, only MATCH proxy",
			yaml: "dns: {enable: true, nameserver: ['https://doh.pub/dns-query']}\nrules:\n  - GEOIP,CN,DIRECT\n  - MATCH,PROXY\n",
			want: map[string]model.Severity{"RULE-02": model.Low},
			not:  []string{"RULE-01", "RULE-06"},
		},
		{
			name: "foreign encrypted resolver",
			yaml: "dns: {enable: true, nameserver: ['https://1.1.1.1/dns-query']}\nrules:\n  - GEOIP,CN,DIRECT\n  - DOMAIN,a.com,PROXY\n  - MATCH,PROXY\n",
			want: map[string]model.Severity{"RULE-01": model.Low},
		},
		{
			name: "proxied resolver: redundant resolution only",
			yaml: "dns: {enable: true, nameserver: ['https://1.1.1.1/dns-query#PROXY']}\nrules:\n  - GEOIP,CN,DIRECT\n  - DOMAIN,a.com,PROXY\n",
			want: map[string]model.Severity{"RULE-01": model.Info, "RULE-06": model.Info},
		},
		{
			name: "respect-rules makes servers proxied",
			yaml: "dns: {enable: true, respect-rules: true, proxy-server-nameserver: ['https://223.5.5.5/dns-query'], nameserver: ['https://1.1.1.1/dns-query']}\nrules:\n  - GEOIP,CN,DIRECT\n  - DOMAIN,a.com,PROXY\n",
			want: map[string]model.Severity{"RULE-01": model.Info},
			not:  []string{"DNS-06"},
		},
		{
			name: "nameserver-policy maps the affected geosite to a plain server",
			yaml: "dns:\n  enable: true\n  nameserver: ['https://1.1.1.1/dns-query#PROXY']\n  nameserver-policy:\n    'geosite:google': 114.114.114.114\nrules:\n  - GEOIP,CN,DIRECT\n  - GEOSITE,google,PROXY\n",
			want: map[string]model.Severity{"RULE-01": model.High, "DNS-04": model.High},
		},
		{
			name: "domain-suffix covered by a policy wildcard",
			yaml: "dns:\n  enable: true\n  nameserver: ['https://1.1.1.1/dns-query#PROXY']\n  nameserver-policy:\n    '+.google.com': 'https://doh.pub/dns-query'\nrules:\n  - GEOIP,CN,DIRECT\n  - DOMAIN-SUFFIX,google.com,PROXY\n",
			want: map[string]model.Severity{"RULE-01": model.Medium, "DNS-04": model.Medium},
		},
		{
			name: "fallback is counted with nameserver",
			yaml: "dns: {enable: true, nameserver: ['https://1.1.1.1/dns-query#PROXY'], fallback: [8.8.4.4]}\nrules:\n  - GEOIP,CN,DIRECT\n  - DOMAIN,a.com,PROXY\n",
			want: map[string]model.Severity{"RULE-01": model.High, "DNS-05": model.Info, "DNS-02": model.Medium},
		},
		{
			name: "direct-nameserver is not used for rule matching",
			yaml: "dns: {enable: true, nameserver: ['https://1.1.1.1/dns-query#PROXY'], direct-nameserver: [114.114.114.114]}\nrules:\n  - GEOIP,CN,DIRECT\n  - DOMAIN,a.com,PROXY\n",
			want: map[string]model.Severity{"RULE-01": model.Info},
			not:  []string{"DNS-02"},
		},
		{
			name: "triggers after MATCH are unreachable",
			yaml: "dns: {enable: true, nameserver: [8.8.8.8]}\nrules:\n  - MATCH,PROXY\n  - GEOIP,CN,DIRECT\n",
			not:  []string{"RULE-01", "RULE-02"},
		},
		{
			name: "GEOIP no-resolve as fallback",
			yaml: "dns: {enable: true, nameserver: ['https://1.1.1.1/dns-query#PROXY']}\nrules:\n  - GEOSITE,cn,DIRECT\n  - GEOIP,CN,DIRECT,no-resolve\n  - MATCH,PROXY\n",
			want: map[string]model.Severity{"RULE-05": model.Info},
		},
		{
			name: "GEOIP lan no-resolve is fine",
			yaml: "dns: {enable: true, nameserver: ['https://1.1.1.1/dns-query#PROXY']}\nrules:\n  - GEOSITE,private,DIRECT\n  - GEOIP,lan,DIRECT,no-resolve\n  - GEOSITE,google,PROXY\n  - MATCH,PROXY\n",
			not:  []string{"RULE-05", "RULE-01", "RULE-02"},
		},
		{
			name: "GEOIP no-resolve after a resolving rule still works",
			yaml: "dns: {enable: true, nameserver: ['https://1.1.1.1/dns-query#PROXY']}\nrules:\n  - GEOIP,private,DIRECT\n  - GEOIP,CN,DIRECT,no-resolve\n  - MATCH,PROXY\n",
			not:  []string{"RULE-05"},
		},
		{
			name: "no MATCH defaults to DIRECT",
			yaml: "dns: {enable: true, nameserver: ['https://1.1.1.1/dns-query#PROXY']}\nrules:\n  - DOMAIN,a.com,PROXY\n",
			want: map[string]model.Severity{"RULE-06": model.Info},
		},
		{
			name: "unknown classical rule-set",
			yaml: "dns: {enable: true, nameserver: ['https://1.1.1.1/dns-query#PROXY']}\nrule-providers:\n  c: {type: http, behavior: classical, url: 'https://e/c'}\nrules:\n  - RULE-SET,c,PROXY\n  - MATCH,PROXY\n",
			want: map[string]model.Severity{"RULE-03": model.Info},
		},
		{
			name: "missing references",
			yaml: "proxy-groups-extra: 1\ndns: {enable: true, nameserver: ['https://1.1.1.1/dns-query#NOPE']}\nrules:\n  - RULE-SET,nope,PROXY\n  - DOMAIN,a.com,MISSING\n  - SUB-RULE,(NETWORK,tcp),nosub\n  - MATCH,PROXY\n",
			want: map[string]model.Severity{"CFG-03": model.Error, "DNS-07": model.Error, "CFG-01": model.Low},
		},
		{
			name: "plain proxy-server-nameserver",
			yaml: "dns: {enable: true, nameserver: ['https://1.1.1.1/dns-query#PROXY'], proxy-server-nameserver: [223.5.5.5]}\nrules:\n  - MATCH,PROXY\n",
			want: map[string]model.Severity{"DNS-09": model.Low},
		},
		{
			name: "empty default-nameserver",
			yaml: "dns: {enable: true, default-nameserver: [], nameserver: ['https://1.1.1.1/dns-query#PROXY']}\nrules:\n  - MATCH,PROXY\n",
			want: map[string]model.Severity{"DNS-08": model.Error},
		},
		{
			name: "dns disabled",
			yaml: "dns: {enable: false, nameserver: ['https://1.1.1.1/dns-query']}\nrules:\n  - GEOIP,CN,DIRECT\n  - MATCH,PROXY\n",
			want: map[string]model.Severity{"DNS-01": model.Low, "RULE-02": model.Medium},
		},
		{
			name: "builtin proxy geosite in policy",
			yaml: "dns:\n  enable: true\n  nameserver: ['https://1.1.1.1/dns-query#PROXY']\n  nameserver-policy:\n    'geosite:geolocation-!cn,cn': 223.5.5.5\nrules:\n  - MATCH,PROXY\n",
			want: map[string]model.Severity{"DNS-04": model.High},
		},
		{
			name: "classical set with trailing domain entries routed to proxy",
			yaml: "dns: {enable: true, nameserver: [8.8.8.8]}\nrule-providers:\n  tg: {type: inline, behavior: classical, payload: ['IP-CIDR,91.108.4.0/22', 'DOMAIN-SUFFIX,t.me']}\nrules:\n  - RULE-SET,tg,PROXY\n  - MATCH,DIRECT\n",
			want: map[string]model.Severity{"RULE-03": model.High},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ids(env(t, tt.yaml).Check())
			for id, sev := range tt.want {
				if s, ok := got[id]; !ok || s != sev {
					t.Errorf("%s: got %v (present=%v), want %v; all=%v", id, s, ok, sev, got)
				}
			}
			for _, id := range tt.not {
				if _, ok := got[id]; ok {
					t.Errorf("unexpected %s; all=%v", id, got)
				}
			}
		})
	}
}

func findingsByID(fs []model.Finding, id string) []model.Finding {
	var out []model.Finding
	for _, f := range fs {
		if f.ID == id {
			out = append(out, f)
		}
	}
	return out
}

func TestSubRuleChains(t *testing.T) {
	// A trigger inside a sub-rules chain followed by proxied domain rules
	// of the same chain: those domains are certainly resolved (RULE-01
	// row), besides the conditional effect on the main chain.
	e := env(t, `
dns: {enable: true, nameserver: [8.8.8.8]}
sub-rules:
  s:
    - GEOIP,CN,DIRECT
    - DOMAIN-SUFFIX,google.com,PROXY
rules:
  - SUB-RULE,(NETWORK,tcp),s
  - DOMAIN-SUFFIX,x.com,PROXY
  - MATCH,DIRECT
`)
	fs := e.Check()
	r01 := findingsByID(fs, "RULE-01")
	if len(r01) != 1 || r01[0].Severity != model.High || r01[0].Locations[0].Path != "sub-rules.s[0]" ||
		r01[0].Locations[1].Text != "DOMAIN-SUFFIX,google.com,PROXY" {
		t.Errorf("sub-chain RULE-01 = %+v", r01)
	}
	r04 := findingsByID(fs, "RULE-04")
	if len(r04) != 1 || r04[0].Severity != model.Medium || r04[0].Args["kind"] != "conditional" || r04[0].Notes[0].Key != "sub-rule-guard" {
		t.Errorf("main-chain RULE-04 = %+v", r04)
	}

	// A SUB-RULE after the main-chain trigger: proxied domain rules inside
	// its chain are reached with the host already resolved.
	e = env(t, `
dns: {enable: true, nameserver: [8.8.8.8]}
sub-rules:
  s:
    - DOMAIN-SUFFIX,google.com,PROXY
    - MATCH,DIRECT
rules:
  - GEOIP,CN,DIRECT
  - SUB-RULE,(NETWORK,tcp),s
  - MATCH,DIRECT
`)
	r01 = findingsByID(e.Check(), "RULE-01")
	if len(r01) != 1 || r01[0].Severity != model.High || r01[0].Locations[1].Path != "sub-rules.s[0]" {
		t.Errorf("RULE-01 via later SUB-RULE = %+v", r01)
	}

	// SUB-RULE whose condition triggers: its chain is affected, and a
	// proxied MATCH in the chain covers the condition's domains.
	e = env(t, `
dns: {enable: true, nameserver: ['https://doh.pub/dns-query']}
sub-rules:
  s:
    - MATCH,PROXY
rules:
  - SUB-RULE,(AND,((IP-CIDR,1.0.0.0/8),(DOMAIN-SUFFIX,a.com))),s
  - MATCH,DIRECT
`)
	r04 = findingsByID(e.Check(), "RULE-04")
	if len(r04) != 1 || r04[0].Severity != model.Low || r04[0].Args["scope"] != "unknown" || r04[0].Args["match"] != "MATCH,PROXY" {
		t.Errorf("RULE-04 with triggering condition = %+v", r04)
	}

	// Circular sub-rules (mihomo refuses them) must not hang the analysis.
	var b strings.Builder
	b.WriteString("dns: {enable: true, nameserver: [8.8.8.8]}\nsub-rules:\n  loop:\n")
	for i := 0; i < 20; i++ {
		b.WriteString("    - SUB-RULE,(NETWORK,tcp),loop\n")
	}
	b.WriteString("    - IP-CIDR,1.0.0.0/8,PROXY\n    - DOMAIN,a.com,PROXY\nrules:\n  - SUB-RULE,(NETWORK,tcp),loop\n  - MATCH,PROXY\n")
	if got := ids(env(t, b.String()).Check()); got["RULE-04"] != model.Medium || got["RULE-01"] != model.High {
		t.Errorf("circular sub-rules = %v", got)
	}
}

func TestMergedFindingLocations(t *testing.T) {
	e := env(t, "dns: {enable: true, nameserver: [8.8.8.8, 'https://doh.pub/dns-query']}\nrules:\n  - GEOIP,CN,DIRECT\n  - DOMAIN,a.com,AUTO\n  - MATCH,PROXY\n")
	var f *model.Finding
	fs := e.Check()
	for i := range fs {
		if fs[i].ID == "RULE-01" {
			f = &fs[i]
		}
	}
	if f == nil {
		t.Fatal("no RULE-01")
	}
	roles := []string{}
	for _, l := range f.Locations {
		roles = append(roles, l.Role+"@"+l.Text)
	}
	want := "trigger@GEOIP,CN,DIRECT affected@DOMAIN,a.com,AUTO affected@MATCH,PROXY resolver@8.8.8.8"
	if strings.Join(roles, " ") != want {
		t.Errorf("locations = %v", roles)
	}
	if f.Args["scope"] != "both" || f.Args["count"] != "1" {
		t.Errorf("args = %v", f.Args)
	}
	hasAssumption := false
	for _, n := range f.Notes {
		if n.Key == "group-assumed-proxy" && n.Args["group"] == "AUTO" {
			hasAssumption = true
		}
	}
	if !hasAssumption {
		t.Errorf("missing D7 assumption note: %+v", f.Notes)
	}
}

func TestSortFindings(t *testing.T) {
	fs := []model.Finding{
		{ID: "B", Severity: model.Low, Locations: []model.Location{{Line: 1}}},
		{ID: "A", Severity: model.High, Locations: []model.Location{{Line: 9}}},
		{ID: "C", Severity: model.High, Locations: []model.Location{{Line: 3}}},
		{ID: "D", Severity: model.Error},
	}
	SortFindings(fs)
	var got []string
	for _, f := range fs {
		got = append(got, f.ID)
	}
	if strings.Join(got, "") != "DCAB" {
		t.Errorf("order = %v", got)
	}
}

// TestPerLocationResolvers covers a merged finding whose affected rules
// reach different resolvers: each affected location carries its own
// resolver, all distinct resolvers are listed, and severity is the worst.
func TestPerLocationResolvers(t *testing.T) {
	e := env(t, `rule-providers:
  mixed:
    type: inline
    behavior: classical
    payload:
      - DOMAIN-SUFFIX,cn-site.com
      - IP-CIDR,10.0.0.0/8
dns:
  enable: true
  nameserver: [https://223.5.5.5/dns-query]
  nameserver-policy:
    "geosite:geolocation-!cn": 114.114.114.114
rules:
  - RULE-SET,mixed,DIRECT
  - DOMAIN-SUFFIX,google.com,PROXY
  - GEOSITE,geolocation-!cn,PROXY
  - MATCH,PROXY
`)
	fs := findingsByID(e.Check(), "RULE-03")
	if len(fs) != 1 {
		t.Fatalf("want one RULE-03, got %+v", fs)
	}
	f := fs[0]
	if f.Severity != model.High || f.Args["level"] != "plain" || f.Args["mixed"] != "true" {
		t.Errorf("severity=%v args=%v", f.Severity, f.Args)
	}
	type annot struct{ level, source, key string }
	want := map[string]annot{
		"DOMAIN-SUFFIX,google.com,PROXY": {"cn", model.ResolverNameserver, ""},
		"GEOSITE,geolocation-!cn,PROXY":  {"plain", model.ResolverPolicy, "geosite:geolocation-!cn"},
		"MATCH,PROXY":                    {"cn", model.ResolverNameserver, ""},
	}
	var resolvers []string
	for _, l := range f.Locations {
		switch l.Role {
		case model.RoleAffected:
			w, ok := want[l.Text]
			if !ok || l.Resolver == nil {
				t.Errorf("unexpected affected location %+v", l)
				continue
			}
			if got := (annot{l.Resolver.Level, l.Resolver.Source, l.Resolver.PolicyKey}); got != w {
				t.Errorf("%s: resolver %+v, want %+v", l.Text, got, w)
			}
			delete(want, l.Text)
		case model.RoleResolver:
			resolvers = append(resolvers, l.Text)
			if l.Resolver != nil {
				t.Errorf("resolver locations carry no annotation: %+v", l)
			}
		default:
			if l.Resolver != nil {
				t.Errorf("%s location should not carry a resolver: %+v", l.Role, l)
			}
		}
	}
	if len(want) != 0 {
		t.Errorf("missing affected locations: %v", want)
	}
	// Worst selection first, then the others; each server once.
	if strings.Join(resolvers, " ") != "114.114.114.114 https://223.5.5.5/dns-query" {
		t.Errorf("resolver locations = %v", resolvers)
	}
}

// TestUniformResolvers: when every affected location reaches the same
// level, the finding is not marked mixed.
func TestUniformResolvers(t *testing.T) {
	e := env(t, "dns: {enable: true, nameserver: [8.8.8.8, 'https://doh.pub/dns-query'], fallback: ['tls://1.1.1.1']}\nrules:\n  - GEOIP,CN,DIRECT\n  - DOMAIN,a.com,PROXY\n  - MATCH,PROXY\n")
	fs := findingsByID(e.Check(), "RULE-01")
	if len(fs) != 1 {
		t.Fatalf("want one RULE-01, got %+v", fs)
	}
	if fs[0].Args["mixed"] != "false" {
		t.Errorf("args = %v", fs[0].Args)
	}
	for _, l := range fs[0].Locations {
		if l.Role == model.RoleAffected && (l.Resolver == nil || l.Resolver.Level != "plain" || l.Resolver.Source != model.ResolverNameserverFallback) {
			t.Errorf("affected %s resolver = %+v", l.Text, l.Resolver)
		}
	}
}
