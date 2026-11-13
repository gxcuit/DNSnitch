package fix

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"dnsnitch/internal/model"
)

type fixCase struct {
	name  string
	in    string
	edits []string          // pairs old, new: want = in with each old (unique) replaced
	skips map[string]string // "ID@path" -> reason, exactly
	// gone lists finding IDs that must not remain after the fix.
	gone   []string
	passes int // -1: do not check
}

func TestBuild(t *testing.T) {
	for _, tc := range buildCases() {
		t.Run(tc.name, func(t *testing.T) { runCase(t, tc) })
	}
}

func buildCases() []fixCase {
	groups := head + "  - {name: \U0001F3AF 全球直连, type: select, proxies: [DIRECT]}\n"
	return []fixCase{
		{
			name: "crlf bom comments quotes blank lines",
			in: "\xef\xbb\xbf# 注释：中文\r\n" + strings.ReplaceAll(head, "\n", "\r\n") +
				"\r\n" +
				"rules:\r\n" +
				"  # comment before a rule\r\n" +
				"  - 'GEOIP,private,DIRECT'   # trailing comment\r\n" +
				"  - \"DOMAIN-SUFFIX,google.com,PROXY\"\r\n" +
				"\r\n" +
				"  - MATCH,PROXY\r\n" +
				"\r\n" +
				"dns:\r\n" +
				"  enable: true\r\n" +
				"  nameserver:\r\n" +
				"    - \"8.8.8.8\"  # google\r\n" +
				"\r\n" +
				"    - 'https://doh.pub/dns-query'\r\n" +
				"  fallback: ['tls://1.1.1.1', \"udp://9.9.9.9\"]   # keep me\r\n" +
				"  nameserver-police:\r\n" +
				"    \"+.lan\": system\r\n",
			edits: []string{
				"'GEOIP,private,DIRECT'", "'GEOIP,private,DIRECT,no-resolve'",
				"    - \"8.8.8.8\"  # google\r\n", "",
				"['tls://1.1.1.1', \"udp://9.9.9.9\"]", "['tls://1.1.1.1']",
				"  nameserver-police:", "  nameserver-policy:",
			},
			gone:   []string{"RULE-01", "DNS-02", "CFG-01"},
			passes: 1,
		},
		{
			name: "multibyte before the scalar on the same line",
			in: groups +
				"rules: ['GEOSITE,cn,\U0001F3AF 全球直连', 'GEOIP,private,\U0001F3AF 全球直连', 'MATCH,PROXY']\n" +
				"dns:\n" +
				"  enable: true\n" +
				"  nameserver: ['https://dns.alidns.com/dns-query#\U0001F3AF 全球直连', 8.8.8.8, tls://223.5.5.5]\n",
			edits: []string{
				"'GEOIP,private,\U0001F3AF 全球直连'", "'GEOIP,private,\U0001F3AF 全球直连,no-resolve'",
				"['https://dns.alidns.com/dns-query#\U0001F3AF 全球直连', 8.8.8.8, tls://223.5.5.5]", "['https://dns.alidns.com/dns-query#\U0001F3AF 全球直连', tls://223.5.5.5]",
			},
			gone:   []string{"RULE-02", "DNS-02"},
			passes: 1,
		},
		{
			name: "block rule after emoji target",
			in: groups +
				"rules:\n" +
				"  - GEOIP,private,\U0001F3AF 全球直连\n" +
				"  - GEOSITE,youtube,PROXY\n" +
				"  - MATCH,PROXY\n" +
				"dns: {enable: true, nameserver: [8.8.8.8, https://doh.pub/dns-query]}\n",
			edits: []string{
				"  - GEOIP,private,\U0001F3AF 全球直连\n", "  - GEOIP,private,\U0001F3AF 全球直连,no-resolve\n",
				"[8.8.8.8, https://doh.pub/dns-query]", "[https://doh.pub/dns-query]",
			},
			gone:   []string{"RULE-01", "DNS-02"},
			passes: 1,
		},
		{
			name: "AND with one IP sub-rule",
			in: head + "dns: {enable: true, nameserver: [https://doh.pub/dns-query]}\n" +
				"rules:\n" +
				"  - AND,((DOMAIN-SUFFIX,a.com),(IP-CIDR,1.0.0.0/8)),DIRECT\n" +
				"  - GEOSITE,google,PROXY\n" +
				"  - MATCH,PROXY\n",
			edits:  []string{"(IP-CIDR,1.0.0.0/8)", "(IP-CIDR,1.0.0.0/8,no-resolve)"},
			gone:   []string{"RULE-04"},
			passes: 1,
		},
		{
			name: "OR with two IP sub-rules over two passes",
			in: head + "dns: {enable: true, nameserver: [https://doh.pub/dns-query]}\n" +
				"rules:\n" +
				"  - OR,((IP-CIDR,1.0.0.0/8),(DOMAIN,b.com),( IP-CIDR6 , ::1/128 )),DIRECT\n" +
				"  - GEOSITE,google,PROXY\n" +
				"  - MATCH,PROXY\n",
			edits: []string{
				"(IP-CIDR,1.0.0.0/8)", "(IP-CIDR,1.0.0.0/8,no-resolve)",
				"( IP-CIDR6 , ::1/128 )", "( IP-CIDR6 , ::1/128 ,no-resolve)",
			},
			gone:   []string{"RULE-04"},
			passes: 2,
		},
		{
			name: "SUB-RULE condition and chain",
			in: head + "dns: {enable: true, nameserver: [https://doh.pub/dns-query]}\n" +
				"rules:\n" +
				"  - SUB-RULE,(IP-CIDR,1.0.0.0/8),s1\n" +
				"  - SUB-RULE,(DOMAIN-SUFFIX,a.com),s2\n" +
				"  - GEOSITE,google,PROXY\n" +
				"  - MATCH,PROXY\n" +
				"sub-rules:\n" +
				"  s1:\n" +
				"    - DOMAIN,x.com,PROXY\n" +
				"  s2:\n" +
				"    - GEOIP,CN,DIRECT\n" +
				"    - DOMAIN,y.a.com,PROXY\n",
			edits: []string{
				"SUB-RULE,(IP-CIDR,1.0.0.0/8),s1", "SUB-RULE,(IP-CIDR,1.0.0.0/8,no-resolve),s1",
				"    - GEOIP,CN,DIRECT\n", "    - GEOIP,CN,DIRECT,no-resolve\n",
			},
			gone:   []string{"RULE-01", "RULE-04"},
			passes: -1,
		},
		{
			// The SUB-RULE's RULE-04 is fixed by the chain's own RULE-03,
			// with no misleading skip.
			name: "SUB-RULE chain referencing a classical set",
			in: head + "dns: {enable: true, nameserver: [https://doh.pub/dns-query]}\n" +
				"rule-providers:\n" +
				"  cls: {type: inline, behavior: classical, payload: ['IP-CIDR,1.0.0.0/8', 'DOMAIN,x.com']}\n" +
				"rules:\n" +
				"  - SUB-RULE,(DOMAIN-SUFFIX,a.com),s1\n" +
				"  - GEOSITE,google,PROXY\n" +
				"  - MATCH,PROXY\n" +
				"sub-rules:\n" +
				"  s1:\n" +
				"    - RULE-SET,cls,DIRECT\n" +
				"    - DOMAIN,b.a.com,PROXY\n",
			edits:  []string{"    - RULE-SET,cls,DIRECT\n", "    - RULE-SET,cls,DIRECT,no-resolve\n"},
			gone:   []string{"RULE-03", "RULE-04"},
			passes: 1,
		},
		{
			name: "SUB-RULE chain referencing a classical set through an anchor",
			in: head + "dns: {enable: true, nameserver: [https://doh.pub/dns-query]}\n" +
				"rule-providers:\n" +
				"  cls: {type: inline, behavior: classical, payload: ['IP-CIDR,1.0.0.0/8', 'DOMAIN,x.com']}\n" +
				"rules:\n" +
				"  - SUB-RULE,(DOMAIN-SUFFIX,a.com),s1\n" +
				"  - GEOSITE,google,PROXY\n" +
				"  - MATCH,PROXY\n" +
				"sub-rules:\n" +
				"  s1:\n" +
				"    - &cls RULE-SET,cls,DIRECT\n" +
				"    - DOMAIN,b.a.com,PROXY\n",
			skips: map[string]string{
				"RULE-03@sub-rules.s1[0]": ReasonSharedNode,
				"RULE-04@rules[0]":        ReasonLayout,
			},
			passes: 0,
		},
		{
			name: "RULE-SET classical reference",
			in: head + "dns: {enable: true, nameserver: [https://doh.pub/dns-query]}\n" +
				"rule-providers:\n" +
				"  telegram: {type: inline, behavior: classical, payload: ['IP-CIDR,91.108.4.0/22', 'DOMAIN-SUFFIX,telegram.org']}\n" +
				"rules:\n" +
				"  - RULE-SET,telegram,PROXY\n" +
				"  - GEOSITE,google,PROXY\n" +
				"  - MATCH,PROXY\n",
			edits:  []string{"  - RULE-SET,telegram,PROXY\n", "  - RULE-SET,telegram,PROXY,no-resolve\n"},
			gone:   []string{"RULE-03"},
			passes: 1,
		},
		{
			name: "RULE-SET with unknown content is not fixed",
			in: head + "dns: {enable: true, nameserver: [https://doh.pub/dns-query]}\n" +
				"rule-providers:\n" +
				"  remote: {type: http, behavior: classical, url: 'https://example.com/r.yaml'}\n" +
				"rules:\n" +
				"  - RULE-SET,remote,PROXY\n" +
				"  - MATCH,PROXY\n",
			passes: 0,
		},
		{
			name: "logic rule referencing a classical set",
			in: head + "dns: {enable: true, nameserver: [https://doh.pub/dns-query]}\n" +
				"rule-providers:\n" +
				"  cls: {type: inline, behavior: classical, payload: ['DOMAIN,x.com', 'IP-CIDR,1.0.0.0/8']}\n" +
				"rules:\n" +
				"  - OR,((DOMAIN,a.com),(RULE-SET,cls)),DIRECT\n" +
				"  - GEOSITE,google,PROXY\n" +
				"  - MATCH,PROXY\n",
			edits:  []string{"(RULE-SET,cls)", "(RULE-SET,cls,no-resolve)"},
			gone:   []string{"RULE-04"},
			passes: 1,
		},
		{
			name: "block nameserver, some plaintext",
			in: head + "rules: [MATCH,PROXY]\n" +
				"dns:\n" +
				"  enable: true\n" +
				"  nameserver:\n" +
				"  - 8.8.8.8\n" +
				"  - https://doh.pub/dns-query\n" +
				"  - udp://1.1.1.1:53   # comment\n" +
				"  -   tcp://9.9.9.9\n",
			edits: []string{
				"  - 8.8.8.8\n", "",
				"  - udp://1.1.1.1:53   # comment\n", "",
				"  -   tcp://9.9.9.9\n", "",
			},
			gone:   []string{"DNS-02"},
			passes: 0,
		},
		{
			name: "block nameserver, all plaintext",
			in: head + "rules: [MATCH,PROXY]\n" +
				"dns:\n" +
				"  enable: true\n" +
				"  nameserver:\n" +
				"      - '8.8.8.8'   # first\n" +
				"      - 114.114.114.114\n" +
				"  fallback:\n" +
				"    - 9.9.9.9\n" +
				"    - udp://1.0.0.1  \n" +
				"  ipv6: true\n",
			edits: []string{
				"      - '8.8.8.8'   # first\n", "      - 'https://223.5.5.5/dns-query'   # first\n",
				"      - 114.114.114.114\n", "",
				"  fallback:\n", "  fallback: []\n",
				"    - 9.9.9.9\n", "",
				"    - udp://1.0.0.1  \n", "",
			},
			gone:   []string{"DNS-02"},
			passes: 0,
		},
		{
			name: "flow lists emptied",
			in: head + "rules: [MATCH,PROXY]\n" +
				"dns:\n" +
				"  enable: true\n" +
				"  nameserver: [ 8.8.8.8 , '114.114.114.114', ]\n" +
				"  fallback: [8.8.8.8]\n",
			edits: []string{
				"[ 8.8.8.8 , '114.114.114.114', ]", "[https://223.5.5.5/dns-query]",
				"  fallback: [8.8.8.8]\n", "  fallback: []\n",
			},
			gone:   []string{"DNS-02"},
			passes: 0,
		},
		{
			name: "scalar nameserver and DNS-09",
			in: head + "rules: [MATCH,PROXY]\n" +
				"dns:\n" +
				"  enable: true\n" +
				"  nameserver: 8.8.8.8 # only one\n" +
				"  proxy-server-nameserver:\n" +
				"    - 223.5.5.5\n" +
				"    - https://doh.pub/dns-query\n" +
				"    - tcp://119.29.29.29\n",
			edits: []string{
				"  nameserver: 8.8.8.8 # only one\n", "  nameserver: https://223.5.5.5/dns-query # only one\n",
				"    - 223.5.5.5\n", "",
				"    - tcp://119.29.29.29\n", "",
			},
			gone:   []string{"DNS-02", "DNS-09"},
			passes: 0,
		},
		{
			name: "DNS-09 flow emptied",
			in: head + "rules: [MATCH,PROXY]\n" +
				"dns:\n" +
				"  enable: true\n" +
				"  nameserver: [https://doh.pub/dns-query]\n" +
				"  proxy-server-nameserver: [223.5.5.5]\n",
			edits:  []string{"  proxy-server-nameserver: [223.5.5.5]\n", "  proxy-server-nameserver: [https://223.5.5.5/dns-query]\n"},
			gone:   []string{"DNS-09"},
			passes: 0,
		},
		{
			name: "CFG-01 rename and key-exists",
			in: head + "rules: [MATCH,PROXY]\n" +
				"mixed-prot: 7890\n" +
				"dns:\n" +
				"  enable: true\n" +
				"  nameserver: [https://doh.pub/dns-query]\n" +
				"  'enhanced-mod': fake-ip\n" +
				"  nameserver-policy: {}\n" +
				"  nameserver-polcy: {}\n",
			edits: []string{
				"mixed-prot:", "mixed-port:",
				"'enhanced-mod':", "'enhanced-mode':",
			},
			skips:  map[string]string{"CFG-01@dns.nameserver-polcy": ReasonKeyExists},
			passes: 1,
		},
		{
			name: "CFG-01 rename that breaks loading is undone",
			in: head + "rules: [MATCH,PROXY]\n" +
				"dns:\n" +
				"  enable: true\n" +
				"  respect-rule: true\n" +
				"  nameserver:\n" +
				"    - https://1.1.1.1/dns-query#PROXY\n" +
				"    - 8.8.8.8\n",
			edits:  []string{"    - 8.8.8.8\n", ""},
			skips:  map[string]string{"CFG-01@dns.respect-rule": ReasonRenameBreaksLoad},
			gone:   []string{"DNS-02"},
			passes: 0,
		},
		{
			name: "anchors, aliases and merges are shared",
			in: head +
				"base: &base\n" +
				"  enable: true\n" +
				"  nameserver:\n" +
				"    - 8.8.8.8\n" +
				"    - https://doh.pub/dns-query\n" +
				"geo: &geo GEOIP,CN,DIRECT\n" +
				"dns:\n" +
				"  <<: *base\n" +
				"rules:\n" +
				"  - SUB-RULE,(DOMAIN-SUFFIX,a.com),s1\n" +
				"  - &lan GEOIP,lan,DIRECT\n" +
				"  - GEOSITE,google,PROXY\n" +
				"  - MATCH,PROXY\n" +
				"sub-rules:\n" +
				"  s1:\n" +
				"    - *geo\n" +
				"    - DOMAIN,b.a.com,PROXY\n",
			skips: map[string]string{
				"DNS-02@dns.nameserver[0]": ReasonSharedNode,
				"RULE-04@rules[0]":         ReasonSharedNode,
				"RULE-01@rules[1]":         ReasonSharedNode,
				"RULE-01@sub-rules.s1[0]":  ReasonSharedNode,
			},
			passes: 0,
		},
		{
			name: "multi-line scalars and flow lists",
			in: head +
				"rules:\n" +
				"  - SUB-RULE,(DOMAIN-SUFFIX,a.com),s1\n" +
				"  - SUB-RULE,(DOMAIN-SUFFIX,b.com),s2\n" +
				"  - SUB-RULE,(DOMAIN-SUFFIX,c.com),s3\n" +
				"  - >-\n" +
				"    GEOIP,CN,DIRECT\n" +
				"  - GEOSITE,google,PROXY\n" +
				"  - MATCH,PROXY\n" +
				"sub-rules:\n" +
				"  s1:\n" +
				"    - |-\n" +
				"      GEOIP,US,DIRECT\n" +
				"    - DOMAIN,x.a.com,PROXY\n" +
				"  s2:\n" +
				"    - GEOIP,JP,\n" +
				"      DIRECT\n" +
				"    - DOMAIN,x.b.com,PROXY\n" +
				"  s3:\n" +
				"    - \"GEOIP,KR,\n" +
				"      DIRECT\"\n" +
				"    - DOMAIN,x.c.com,PROXY\n" +
				"dns:\n" +
				"  enable: true\n" +
				"  nameserver: [8.8.8.8,\n" +
				"    https://doh.pub/dns-query]\n",
			skips: map[string]string{
				"RULE-04@rules[0]":         ReasonMultiline,
				"RULE-04@rules[1]":         ReasonMultiline,
				"RULE-04@rules[2]":         ReasonMultiline,
				"RULE-01@rules[3]":         ReasonMultiline,
				"RULE-01@sub-rules.s1[0]":  ReasonMultiline,
				"RULE-01@sub-rules.s2[0]":  ReasonMultiline,
				"RULE-01@sub-rules.s3[0]":  ReasonMultiline,
				"DNS-02@dns.nameserver[0]": ReasonMultiline,
			},
			passes: 0,
		},
		{
			name: "existing upper-case NO-RESOLVE and escaped logic rule",
			in: head + "dns: {enable: true, nameserver: [https://doh.pub/dns-query]}\n" +
				"rules:\n" +
				"  - SUB-RULE,(DOMAIN-SUFFIX,a.com),s1\n" +
				"  - SUB-RULE,(DOMAIN-SUFFIX,c.com),s2\n" +
				"  - GEOIP,CN,DIRECT,NO-RESOLVE\n" +
				"  - GEOSITE,google,PROXY\n" +
				"  - MATCH,PROXY\n" +
				"sub-rules:\n" +
				"  s1:\n" +
				"    - \"AND,((DOMAIN,b.a.com),(IP-CIDR,1.0.0.0\\x2F8)),DIRECT\"\n" +
				"    - DOMAIN,a.com,PROXY\n" +
				"  s2:\n" +
				"    - \"GEOIP,\\x55S,DIRECT\"\n" +
				"    - DOMAIN,c.com,PROXY\n",
			edits: []string{"\"GEOIP,\\x55S,DIRECT\"", "\"GEOIP,\\x55S,DIRECT,no-resolve\""},
			skips: map[string]string{
				"RULE-04@rules[0]":        ReasonLayout,
				"RULE-01@rules[2]":        ReasonLayout,
				"RULE-04@sub-rules.s1[0]": ReasonLayout,
			},
			passes: 1,
		},
	}
}

func runCase(t *testing.T, tc fixCase) {
	t.Helper()
	want := tc.in
	for i := 0; i+1 < len(tc.edits); i += 2 {
		if n := strings.Count(want, tc.edits[i]); n != 1 {
			t.Fatalf("bad test: %q occurs %d times", tc.edits[i], n)
		}
		want = strings.Replace(want, tc.edits[i], tc.edits[i+1], 1)
	}
	check := realCheck("cfg.yaml", t.TempDir())
	before, err := check([]byte(tc.in))
	if err != nil {
		t.Fatal(err)
	}
	p, err := Build("cfg.yaml", []byte(tc.in), check)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if string(p.Fixed) != want {
		t.Errorf("fixed text mismatch\n--- got\n%s\n--- want\n%s\n--- diff\n%s", p.Fixed, want, Unified("want", "got", Diff([]byte(want), p.Fixed, 1)))
	}
	if !bytes.Equal(p.Original, []byte(tc.in)) {
		t.Error("Original changed")
	}
	if (len(p.Edits) == 0) != (string(p.Fixed) == tc.in) {
		t.Errorf("edits = %d but fixed changed = %v", len(p.Edits), string(p.Fixed) != tc.in)
	}
	if (len(p.Hunks) == 0) != (string(p.Fixed) == tc.in) {
		t.Errorf("hunks = %d", len(p.Hunks))
	}
	got := skipReasons(p)
	if len(got) != len(tc.skips) {
		t.Errorf("skips = %v, want %v", got, tc.skips)
	}
	for k, v := range tc.skips {
		if got[k] != v {
			t.Errorf("skip %s = %q, want %q (all: %v)", k, got[k], v, got)
		}
	}
	if tc.passes >= 0 && p.Passes != tc.passes {
		t.Errorf("passes = %d, want %d", p.Passes, tc.passes)
	}
	after, err := check(p.Fixed)
	if err != nil {
		t.Fatalf("fixed text does not load: %v", err)
	}
	for _, id := range tc.gone {
		if hasID(after, id) {
			t.Errorf("%s still reported after fix: %s", id, ids(after))
		}
	}
	if _, added := NewError(before, after); added {
		t.Errorf("new error findings: %s", ids(after))
	}
	assertEditLines(t, p)
	assertCovered(t, before, after, p)
}

// assertEditLines checks Before / After against the original and fixed text.
func assertEditLines(t *testing.T, p *Plan) {
	t.Helper()
	orig := newSource(p.Original, bomLen(p.Original))
	fixed := map[string]bool{}
	for i, l := range splitLines(p.Fixed) {
		l = trimEOL(l)
		if i == 0 {
			l = strings.TrimPrefix(l, bomText)
		}
		fixed[l] = true
	}
	for _, e := range p.Edits {
		if e.Before != orig.lineText(e.Line) {
			t.Errorf("edit %s line %d: Before = %q, original line = %q", e.ID, e.Line, e.Before, orig.lineText(e.Line))
		}
		if e.After != "" && !fixed[e.After] {
			t.Errorf("edit %s line %d: After %q is not a line of the result", e.ID, e.Line, e.After)
		}
		if e.Before == e.After {
			t.Errorf("edit %s line %d does not change the line", e.ID, e.Line)
		}
	}
}

// assertCovered checks that every fixable finding location of the original
// check is accounted for by an Edit or a Skip on the same line. The only
// exception is a SUB-RULE whose trigger point is a classical set referenced
// from its chain: the chain's own finding fixes it, and it is gone from
// after.
func assertCovered(t *testing.T, before, after []model.Finding, p *Plan) {
	t.Helper()
	viaChainFixed := func(f model.Finding) bool {
		loc, ok := primary(f)
		if f.ID != "RULE-04" || !ok || !strings.HasPrefix(strings.ToUpper(loc.Text), "SUB-RULE") {
			return false
		}
		return !reported(after, ref{id: f.ID, path: loc.Path})
	}
	has := func(id string, line int) bool {
		for _, e := range p.Edits {
			if e.ID == id && e.Line == line {
				return true
			}
		}
		for _, s := range p.Skips {
			if s.ID == id && s.Line == line {
				return true
			}
		}
		return false
	}
	for _, f := range before {
		if !Eligible(f) {
			continue
		}
		var lines []int
		if f.ID == "DNS-02" || f.ID == "DNS-09" {
			for _, l := range f.Locations {
				if l.Role == model.RoleResolver {
					lines = append(lines, l.Line)
				}
			}
		} else if loc, ok := primary(f); ok {
			lines = append(lines, loc.Line)
			if e, ok := role(f, model.RoleTriggerEntry); ok && f.ID == "RULE-04" && !has(f.ID, loc.Line) {
				lines[0] = e.Line
			}
		}
		for _, l := range lines {
			if !has(f.ID, l) && !viaChainFixed(f) {
				t.Errorf("finding %s at line %d has neither an edit nor a skip", f.ID, l)
			}
		}
	}
}

func TestEligible(t *testing.T) {
	tests := []struct {
		id   string
		sev  model.Severity
		args model.Args
		want bool
	}{
		{"RULE-01", model.High, model.Args{"kind": "always"}, true},
		{"RULE-02", model.Medium, model.Args{"kind": "always"}, true},
		{"RULE-01", model.High, model.Args{"kind": "conditional"}, false},
		{"RULE-03", model.High, model.Args{"kind": "always"}, true},
		{"RULE-03", model.Medium, model.Args{"kind": "conditional"}, true},
		{"RULE-03", model.High, model.Args{"kind": "unknown"}, false},
		{"RULE-04", model.Low, model.Args{"kind": "conditional"}, true},
		{"RULE-04", model.High, model.Args{"kind": "unknown"}, false},
		// Info-level resolution findings are not leaks (PRD R1.1).
		{"RULE-01", model.Info, model.Args{"kind": "always"}, false},
		{"RULE-02", model.Info, model.Args{"kind": "always"}, false},
		{"RULE-03", model.Info, model.Args{"kind": "always"}, false},
		{"RULE-04", model.Info, model.Args{"kind": "conditional"}, false},
		{"DNS-02", model.Medium, nil, true},
		{"DNS-09", model.Medium, nil, true},
		{"CFG-01", model.Medium, model.Args{"suggest": "dns"}, true},
		{"CFG-01", model.Low, model.Args{"suggest": "dns", "anchor": "true"}, false},
		{"CFG-01", model.Low, model.Args{"anchor": "true"}, false},
		{"CFG-01", model.Low, model.Args{}, false},
		{"RULE-05", model.Low, nil, false},
		{"DNS-06", model.Error, nil, false},
		{"CFG-03", model.Error, nil, false},
	}
	for _, tt := range tests {
		if got := Eligible(model.Finding{ID: tt.id, Severity: tt.sev, Args: tt.args}); got != tt.want {
			t.Errorf("Eligible(%s %v %v) = %v", tt.id, tt.sev, tt.args, got)
		}
	}
}

// Fixing one IP rule exposes the next one in the chain; the rule phase
// stops after MaxPasses and reports the rest.
func TestPassLimit(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(head + "dns: {enable: true, nameserver: [https://doh.pub/dns-query]}\nrules:\n")
	for i := 1; i <= MaxPasses+2; i++ {
		sb.WriteString("  - IP-CIDR," + string(rune('0'+i%10)) + "." + string(rune('0'+i/10)) + ".0.0/16,DIRECT\n")
	}
	sb.WriteString("  - GEOSITE,google,PROXY\n  - MATCH,PROXY\n")
	p := build(t, sb.String())
	if p.Passes != MaxPasses || len(p.Edits) != MaxPasses {
		t.Fatalf("passes = %d, edits = %d", p.Passes, len(p.Edits))
	}
	want := map[string]string{"RULE-01@rules[8]": ReasonPassLimit}
	if got := skipReasons(p); len(got) != 1 || got["RULE-01@rules[8]"] != want["RULE-01@rules[8]"] {
		t.Errorf("skips = %v", got)
	}
}

// A CheckFunc failing on an intermediate text undoes that pass.
func TestCheckFailureUndoesPass(t *testing.T) {
	in := head + "dns: {enable: true, nameserver: [https://doh.pub/dns-query]}\n" +
		"rules:\n  - GEOIP,CN,DIRECT\n  - GEOSITE,google,PROXY\n  - MATCH,PROXY\n"
	real := realCheck("cfg.yaml", t.TempDir())
	check := func(data []byte) ([]model.Finding, error) {
		if bytes.Contains(data, []byte("no-resolve")) {
			return nil, errors.New("boom")
		}
		return real(data)
	}
	p, err := Build("cfg.yaml", []byte(in), check)
	if err != nil {
		t.Fatal(err)
	}
	if string(p.Fixed) != in || len(p.Edits) != 0 || p.Passes != 0 {
		t.Errorf("fixed = %q, edits = %v", p.Fixed, p.Edits)
	}
	if got := skipReasons(p); got["RULE-01@rules[0]"] != ReasonLayout {
		t.Errorf("skips = %v", got)
	}
	if _, err := Build("cfg.yaml", []byte(in), func([]byte) ([]model.Finding, error) { return nil, errors.New("bad") }); err == nil {
		t.Error("Build should fail when the original does not load")
	}
}

// Locations outside the config (a rule-set file) are skipped as other-file.
func TestOtherFile(t *testing.T) {
	f := model.Finding{ID: "DNS-02", Severity: model.Medium, Locations: []model.Location{
		{File: "other.yaml", Line: 3, Path: "dns.nameserver[0]", Role: model.RoleResolver},
	}}
	g := model.Finding{ID: "RULE-01", Severity: model.High, Args: model.Args{"kind": "always"}, Locations: []model.Location{
		{File: "set.yaml", Line: 1, Path: "payload[0]", Role: model.RoleTrigger},
	}}
	in := []byte("dns:\n  nameserver: [8.8.8.8]\n")
	p, err := Build("cfg.yaml", in, func([]byte) ([]model.Finding, error) { return []model.Finding{f, g}, nil })
	if err != nil {
		t.Fatal(err)
	}
	got := skipReasons(p)
	if got["DNS-02@dns.nameserver[0]"] != ReasonOtherFile || got["RULE-01@payload[0]"] != ReasonOtherFile || len(p.Edits) != 0 {
		t.Errorf("skips = %v, edits = %v", got, p.Edits)
	}
}

// Rule and DNS edits keep line numbers of the original file even when
// lines before them are deleted.
func TestEditLinesRefertoOriginal(t *testing.T) {
	in := head +
		"dns:\n" +
		"  enable: true\n" +
		"  nameserver:\n" +
		"    - 8.8.8.8\n" +
		"    - 9.9.9.9\n" +
		"    - https://doh.pub/dns-query\n" +
		"rules:\n" +
		"  - GEOIP,CN,DIRECT\n" +
		"  - GEOSITE,google,PROXY\n" +
		"  - MATCH,PROXY\n"
	p := build(t, in)
	lines := strings.Split(in, "\n")
	for _, e := range p.Edits {
		if lines[e.Line-1] != e.Before {
			t.Errorf("edit %s line %d: before %q, line is %q", e.ID, e.Line, e.Before, lines[e.Line-1])
		}
	}
	if len(p.Edits) != 3 || p.Edits[2].ID != "RULE-01" || p.Edits[2].After != "  - GEOIP,CN,DIRECT,no-resolve" {
		t.Errorf("edits = %+v", p.Edits)
	}
}

func TestRealFixtures(t *testing.T) {
	for _, tc := range []struct {
		file  string
		edits int
		gone  []string
	}{
		{"ac1-geoip-without-no-resolve.yaml", 2, []string{"RULE-01", "DNS-02"}},
		{"ac4-clash-verge-override.yaml", 1, []string{"DNS-02"}},
		{"ac5-classical-ip-first.yaml", 1, []string{"RULE-03"}},
		{"ac6-and.yaml", 2, []string{"RULE-04", "DNS-02"}},
		{"ac6-or.yaml", 2, []string{"RULE-04", "DNS-02"}},
		{"ac7-key-typo.yaml", 1, []string{"CFG-01"}},
		// only info-level RULE-02 (proxied resolvers): nothing to fix (PRD R1.1)
		{"ac3-recommended.yaml", 0, nil},
	} {
		file := fixture(tc.file)
		p := buildFile(t, file)
		if len(p.Edits) != tc.edits {
			t.Errorf("%s: %d edits: %+v", tc.file, len(p.Edits), p.Edits)
		}
		after, err := realCheck(file, fixture(""))(p.Fixed)
		if err != nil {
			t.Fatalf("%s: %v", tc.file, err)
		}
		for _, id := range tc.gone {
			if hasID(after, id) {
				t.Errorf("%s: %s remains", tc.file, id)
			}
		}
	}
}
