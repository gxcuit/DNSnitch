package ruleparse

import (
	"reflect"
	"testing"
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
