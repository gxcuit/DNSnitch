package ruleparse

import (
	"reflect"
	"testing"

	"dnsnitch/internal/model"
)

func TestParse(t *testing.T) {
	tests := []struct {
		raw        string
		needTarget bool
		typ        string
		payload    string
		target     string
		params     []string
		noResolve  bool
		src        bool
		subs       int
		wantErr    bool
	}{
		{raw: "DOMAIN,a.com,PROXY", needTarget: true, typ: "DOMAIN", payload: "a.com", target: "PROXY"},
		{raw: "domain-suffix, a.com , PROXY", needTarget: true, typ: "DOMAIN-SUFFIX", payload: "a.com", target: "PROXY"},
		{raw: "DOMAIN-KEYWORD,goo,PROXY", needTarget: true, typ: "DOMAIN-KEYWORD", payload: "goo", target: "PROXY"},
		{raw: "DOMAIN-WILDCARD,*.a.com,PROXY", needTarget: true, typ: "DOMAIN-WILDCARD", payload: "*.a.com", target: "PROXY"},
		{raw: "DOMAIN-REGEX,^a{1,3}\\.com$,PROXY", needTarget: true, typ: "DOMAIN-REGEX", payload: "^a{1,3}\\.com$", target: "PROXY"},
		{raw: "GEOSITE,geolocation-!cn,PROXY", needTarget: true, typ: "GEOSITE", payload: "geolocation-!cn", target: "PROXY"},
		{raw: "GEOIP,CN,DIRECT", needTarget: true, typ: "GEOIP", payload: "CN", target: "DIRECT"},
		{raw: "GEOIP,CN,DIRECT,no-resolve", needTarget: true, typ: "GEOIP", payload: "CN", target: "DIRECT", params: []string{"no-resolve"}, noResolve: true},
		{raw: "IP-CIDR,1.0.0.0/8,DIRECT,src", needTarget: true, typ: "IP-CIDR", payload: "1.0.0.0/8", target: "DIRECT", params: []string{"src"}, noResolve: true, src: true},
		{raw: "IP-CIDR6,::1/128,DIRECT", needTarget: true, typ: "IP-CIDR6", payload: "::1/128", target: "DIRECT"},
		{raw: "IP-ASN,13335,PROXY", needTarget: true, typ: "IP-ASN", payload: "13335", target: "PROXY"},
		{raw: "IP-SUFFIX,8.8.8.8/24,PROXY", needTarget: true, typ: "IP-SUFFIX", payload: "8.8.8.8/24", target: "PROXY"},
		{raw: "SRC-IP-CIDR,192.168.1.0/24,DIRECT", needTarget: true, typ: "SRC-IP-CIDR", payload: "192.168.1.0/24", target: "DIRECT", noResolve: true, src: true},
		{raw: "SRC-GEOIP,cn,DIRECT", needTarget: true, typ: "SRC-GEOIP", payload: "cn", target: "DIRECT", noResolve: true, src: true},
		{raw: "DST-PORT,443,PROXY", needTarget: true, typ: "DST-PORT", payload: "443", target: "PROXY"},
		{raw: "PROCESS-NAME,curl,DIRECT", needTarget: true, typ: "PROCESS-NAME", payload: "curl", target: "DIRECT"},
		{raw: "NETWORK,udp,REJECT", needTarget: true, typ: "NETWORK", payload: "udp", target: "REJECT"},
		{raw: "RULE-SET,cn_ip,DIRECT,no-resolve", needTarget: true, typ: "RULE-SET", payload: "cn_ip", target: "DIRECT", params: []string{"no-resolve"}, noResolve: true},
		{raw: "MATCH,PROXY", needTarget: true, typ: "MATCH", target: "PROXY"},
		{raw: "AND,((DOMAIN-SUFFIX,a.com),(IP-CIDR,1.0.0.0/8)),DIRECT", needTarget: true, typ: "AND", payload: "((DOMAIN-SUFFIX,a.com),(IP-CIDR,1.0.0.0/8))", target: "DIRECT", subs: 2},
		{raw: "OR,((AND,((DOMAIN,a),(DOMAIN,b))),(NETWORK,udp)),PROXY", needTarget: true, typ: "OR", target: "PROXY", payload: "((AND,((DOMAIN,a),(DOMAIN,b))),(NETWORK,udp))", subs: 2},
		{raw: "NOT,((DOMAIN,a.com)),PROXY", needTarget: true, typ: "NOT", payload: "((DOMAIN,a.com))", target: "PROXY", subs: 1},
		{raw: "SUB-RULE,(NETWORK,tcp),sub1", needTarget: true, typ: "SUB-RULE", payload: "(NETWORK,tcp)", target: "sub1", subs: 1},
		// classical entries: no target, everything after the payload is a param
		{raw: "IP-CIDR,1.0.0.0/8,no-resolve", typ: "IP-CIDR", payload: "1.0.0.0/8", params: []string{"no-resolve"}, noResolve: true},
		{raw: "DOMAIN-SUFFIX,telegram.org", typ: "DOMAIN-SUFFIX", payload: "telegram.org"},
		// errors
		{raw: "FOO,bar,PROXY", needTarget: true, typ: "FOO", payload: "bar", target: "PROXY", wantErr: true},
		{raw: "GEOIP", needTarget: true, typ: "GEOIP", wantErr: true},
		{raw: "NOT,((DOMAIN,a),(DOMAIN,b)),PROXY", needTarget: true, typ: "NOT", payload: "((DOMAIN,a),(DOMAIN,b))", target: "PROXY", wantErr: true},
		// mihomo accepts "(DOMAIN,a)" as an AND payload with zero sub-rules
		{raw: "AND,(DOMAIN,a),PROXY", needTarget: true, typ: "AND", payload: "(DOMAIN,a)", target: "PROXY"},
		{raw: "AND,((DOMAIN,a),(MATCH,x)),PROXY", needTarget: true, typ: "AND", payload: "((DOMAIN,a),(MATCH,x))", target: "PROXY", wantErr: true},
	}
	for _, tt := range tests {
		r := Parse(tt.raw, tt.needTarget)
		if (r.Err != "") != tt.wantErr {
			t.Errorf("%q: err = %q, wantErr %v", tt.raw, r.Err, tt.wantErr)
		}
		if r.Type != tt.typ || r.Payload != tt.payload || r.Target != tt.target {
			t.Errorf("%q: got (%s|%s|%s), want (%s|%s|%s)", tt.raw, r.Type, r.Payload, r.Target, tt.typ, tt.payload, tt.target)
		}
		if tt.wantErr {
			continue
		}
		if !reflect.DeepEqual(r.Params, tt.params) {
			t.Errorf("%q: params = %v, want %v", tt.raw, r.Params, tt.params)
		}
		if r.NoResolve != tt.noResolve || r.Src != tt.src {
			t.Errorf("%q: noResolve=%v src=%v", tt.raw, r.NoResolve, r.Src)
		}
		if len(r.Subs) != tt.subs {
			t.Errorf("%q: %d subs, want %d", tt.raw, len(r.Subs), tt.subs)
		}
	}
}

func TestLogicSubRules(t *testing.T) {
	r := Parse("AND,((DOMAIN-SUFFIX,a.com),(IP-CIDR,1.0.0.0/8,no-resolve)),DIRECT", true)
	if r.Subs[0].Type != "DOMAIN-SUFFIX" || r.Subs[0].Payload != "a.com" || r.Subs[0].Target != "" {
		t.Errorf("sub 0 = %+v", r.Subs[0])
	}
	if r.Subs[1].Type != "IP-CIDR" || !r.Subs[1].NoResolve {
		t.Errorf("sub 1 = %+v", r.Subs[1])
	}
	nested := Parse("OR,((AND,((DOMAIN,a),(DOMAIN,b))),(NETWORK,udp)),PROXY", true)
	if nested.Subs[0].Type != "AND" || len(nested.Subs[0].Subs) != 2 || nested.Subs[1].Type != "NETWORK" {
		t.Errorf("nested = %+v", nested.Subs)
	}
}

func TestParseClassical(t *testing.T) {
	for _, raw := range []string{"MATCH,DIRECT", "RULE-SET,x", "SUB-RULE,(NETWORK,tcp),x"} {
		if r := ParseClassical(raw); r.Err == "" {
			t.Errorf("%q should be rejected in a classical rule-set", raw)
		}
	}
}

func TestTypeSets(t *testing.T) {
	resolving := []string{"GEOIP", "IP-ASN", "IP-CIDR", "IP-CIDR6", "IP-SUFFIX"}
	for _, tp := range resolving {
		if !IsResolvingIPType(tp) {
			t.Errorf("%s should resolve", tp)
		}
	}
	for _, tp := range []string{"SRC-GEOIP", "SRC-IP-CIDR", "DOMAIN", "GEOSITE", "PROCESS-NAME", "DST-PORT", "MATCH", "RULE-SET"} {
		if IsResolvingIPType(tp) {
			t.Errorf("%s should not resolve", tp)
		}
	}
	for _, tp := range []string{"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "DOMAIN-WILDCARD", "GEOSITE"} {
		if !IsDomainType(tp) {
			t.Errorf("%s should be a domain type", tp)
		}
	}
}

// spanSub returns the sub-rule reached by the index path.
func spanSub(t *testing.T, r model.Rule, path ...int) model.Rule {
	t.Helper()
	for _, i := range path {
		if i >= len(r.Subs) {
			t.Fatalf("%q: no sub-rule at %v", r.Raw, path)
		}
		r = r.Subs[i]
	}
	return r
}

func TestSubRuleSpans(t *testing.T) {
	tests := []struct {
		name   string
		raw    string
		target bool
		path   []int
		want   string // raw[Span[0]:Span[1]]
		sub    string // the sub-rule's own Raw
	}{
		{"and first", "AND,((DOMAIN-SUFFIX,a.com),(IP-CIDR,1.0.0.0/8)),DIRECT", true, []int{0}, "DOMAIN-SUFFIX,a.com", "DOMAIN-SUFFIX,a.com"},
		{"and second", "AND,((DOMAIN-SUFFIX,a.com),(IP-CIDR,1.0.0.0/8)),DIRECT", true, []int{1}, "IP-CIDR,1.0.0.0/8", "IP-CIDR,1.0.0.0/8"},
		{"or", "OR,((IP-CIDR,1.0.0.0/8),(IP-CIDR,2.0.0.0/8),(DOMAIN,b.com)),DIRECT", true, []int{1}, "IP-CIDR,2.0.0.0/8", "IP-CIDR,2.0.0.0/8"},
		{"not", "NOT,((GEOIP,CN)),PROXY", true, []int{0}, "GEOIP,CN", "GEOIP,CN"},
		{"sub-rule condition", "SUB-RULE,(IP-CIDR,1.0.0.0/8),sub1", true, []int{0}, "IP-CIDR,1.0.0.0/8", "IP-CIDR,1.0.0.0/8"},
		{"sub-rule logic condition", "SUB-RULE,(AND,((NETWORK,tcp),(GEOIP,US))),sub1", true, []int{0}, "AND,((NETWORK,tcp),(GEOIP,US))", "AND,((NETWORK,tcp),(GEOIP,US))"},
		{"sub-rule nested", "SUB-RULE,(AND,((NETWORK,tcp),(GEOIP,US))),sub1", true, []int{0, 1}, "GEOIP,US", "GEOIP,US"},
		{"nested and in or", "OR,((AND,((DOMAIN,a),(IP-CIDR,1.0.0.0/8))),(NETWORK,udp)),PROXY", true, []int{0, 1}, "IP-CIDR,1.0.0.0/8", "IP-CIDR,1.0.0.0/8"},
		{"nested second group", "OR,((NETWORK,udp),(AND,((DOMAIN,a),(NOT,((IP-CIDR,1.0.0.0/8)))))),PROXY", true, []int{1, 1, 0}, "IP-CIDR,1.0.0.0/8", "IP-CIDR,1.0.0.0/8"},
		{"spaces", "AND, ((DOMAIN-SUFFIX, a.com), (IP-CIDR, 1.0.0.0/8)) , DIRECT", true, []int{1}, "IP-CIDR, 1.0.0.0/8", "IP-CIDR,1.0.0.0/8"},
		{"spaces nested", "OR , ( (AND, ((DOMAIN,a) , (IP-CIDR , 1.0.0.0/8 ))), (NETWORK,udp)),PROXY", true, []int{0, 1}, "IP-CIDR , 1.0.0.0/8 ", "IP-CIDR,1.0.0.0/8 "},
		{"multibyte before", "AND,((DOMAIN,例子.com),(GEOIP,CN)),🎯 全球直连", true, []int{1}, "GEOIP,CN", "GEOIP,CN"},
		{"classical entry", "AND,((DOMAIN,a),(IP-CIDR,1.0.0.0/8))", false, []int{1}, "IP-CIDR,1.0.0.0/8", "IP-CIDR,1.0.0.0/8"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Parse(tt.raw, tt.target)
			if r.Err != "" {
				t.Fatalf("parse error %q", r.Err)
			}
			if r.Span != [2]int{} {
				t.Errorf("top-level span = %v, want zero", r.Span)
			}
			sub := spanSub(t, r, tt.path...)
			if got := tt.raw[sub.Span[0]:sub.Span[1]]; got != tt.want {
				t.Errorf("raw[span] = %q, want %q", got, tt.want)
			}
			if sub.Raw != tt.sub {
				t.Errorf("sub.Raw = %q, want %q", sub.Raw, tt.sub)
			}
			if tt.raw[sub.Span[0]-1] != '(' || tt.raw[sub.Span[1]] != ')' {
				t.Errorf("span %v is not delimited by parentheses in %q", sub.Span, tt.raw)
			}
		})
	}
}

// Inserting ",no-resolve" at a sub-rule's Span end turns exactly that
// sub-rule into a non-resolving one.
func TestSubRuleSpanInsert(t *testing.T) {
	raw := "OR,((IP-CIDR,1.0.0.0/8),(AND,((DOMAIN,a),(IP-CIDR, 2.0.0.0/8 ))),(DOMAIN,b.com)),DIRECT"
	r := Parse(raw, true)
	end := r.Subs[1].Subs[1].Span[1]
	fixed := raw[:end] + ",no-resolve" + raw[end:]
	f := Parse(fixed, true)
	if f.Err != "" {
		t.Fatalf("parse %q: %s", fixed, f.Err)
	}
	if f.Subs[0].NoResolve || !f.Subs[1].Subs[1].NoResolve || f.Subs[1].Subs[1].Payload != "2.0.0.0/8" {
		t.Errorf("after insert: %+v", f.Subs)
	}
}

// FuzzParseSpans: Parse never panics and every sub-rule span lies inside
// the raw text, delimited by parentheses.
func FuzzParseSpans(f *testing.F) {
	for _, s := range []string{
		"AND,((DOMAIN-SUFFIX,a.com),(IP-CIDR,1.0.0.0/8)),DIRECT",
		"OR , ( (AND, ((DOMAIN,a) , (IP-CIDR , 1.0.0.0/8 ))), (NETWORK,udp)),PROXY",
		"SUB-RULE,(AND,((NETWORK,tcp),(GEOIP,US))),sub1",
		"NOT,((GEOIP,CN)),PROXY",
		"SUB-RULE,x)(y,z",
	} {
		f.Add(s, true)
		f.Add(s, false)
	}
	f.Fuzz(func(t *testing.T, raw string, needTarget bool) {
		r := Parse(raw, needTarget)
		if r.Err != "" {
			return
		}
		var walk func(subs []model.Rule)
		walk = func(subs []model.Rule) {
			for _, s := range subs {
				a, b := s.Span[0], s.Span[1]
				if a < 1 || a > b || b >= len(raw) || raw[a-1] != '(' || raw[b] != ')' {
					t.Fatalf("%q: bad span %v for %q", raw, s.Span, s.Raw)
				}
				walk(s.Subs)
			}
		}
		walk(r.Subs)
	})
}
