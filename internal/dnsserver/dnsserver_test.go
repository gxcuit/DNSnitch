package dnsserver

import (
	"testing"

	"dnsnitch/internal/model"
)

func TestParse(t *testing.T) {
	tests := []struct {
		raw     string
		scheme  string
		host    string
		proxy   string
		grade   model.Grade
		region  model.Region
		invalid bool
	}{
		{"8.8.8.8", "udp", "8.8.8.8", "", model.GradePlain, model.RegionForeign, false},
		{"2001:4860:4860::8888", "udp", "2001:4860:4860::8888", "", model.GradePlain, model.RegionForeign, false},
		{"[2400:3200::1]:53", "udp", "2400:3200::1", "", model.GradePlain, model.RegionCN, false},
		{"dns.google", "udp", "dns.google", "", model.GradePlain, model.RegionForeign, false},
		{"8.8.8.8#PROXY", "udp", "8.8.8.8", "PROXY", model.GradePlain, model.RegionForeign, false},
		{"tcp://114.114.114.114", "tcp", "114.114.114.114", "", model.GradePlain, model.RegionCN, false},
		{"tls://223.5.5.5", "tls", "223.5.5.5", "", model.GradeEncrypted, model.RegionCN, false},
		{"tls://223.5.5.5:853", "tls", "223.5.5.5", "", model.GradeEncrypted, model.RegionCN, false},
		{"https://doh.pub/dns-query", "https", "doh.pub", "", model.GradeEncrypted, model.RegionCN, false},
		{"https://1.1.1.1/dns-query#PROXY&h3=true", "https", "1.1.1.1", "PROXY", model.GradeEncrypted, model.RegionForeign, false},
		{"https://223.5.5.5/dns-query#h3=true", "https", "223.5.5.5", "", model.GradeEncrypted, model.RegionCN, false},
		{"quic://dns.adguard-dns.com", "quic", "dns.adguard-dns.com", "", model.GradeEncrypted, model.RegionForeign, false},
		{"https://dns.example.net/dns-query", "https", "dns.example.net", "", model.GradeEncrypted, model.RegionUnknown, false},
		{"http://1.1.1.1/dns-query", "http", "1.1.1.1", "", model.GradePlain, model.RegionForeign, false},
		{"system", "system", "", "", model.GradePlain, model.RegionUnknown, false},
		{"dhcp://system", "system", "", "", model.GradePlain, model.RegionUnknown, false},
		{"dhcp://en0", "dhcp", "en0", "", model.GradePlain, model.RegionUnknown, false},
		{"rcode://success", "rcode", "success", "", model.GradeSafe, model.RegionUnknown, false},
		{"ts://my-tailscale", "ts", "my-tailscale", "", model.GradeViaProxy, model.RegionUnknown, false},
		{"foo://1.1.1.1", "foo", "1.1.1.1", "", model.GradePlain, model.RegionForeign, true},
	}
	for _, tt := range tests {
		s := Parse(tt.raw, model.Location{})
		if s.Scheme != tt.scheme || s.Host != tt.host || s.ProxyName != tt.proxy || s.Grade != tt.grade || s.Region != tt.region || s.Invalid != tt.invalid {
			t.Errorf("%q: got scheme=%s host=%s proxy=%s grade=%d region=%d invalid=%v", tt.raw, s.Scheme, s.Host, s.ProxyName, s.Grade, s.Region, s.Invalid)
		}
	}
}

func lookup(name string) (model.PolicyClass, bool) {
	switch name {
	case "PROXY":
		return model.PolicyProxy, true
	case "DIRECT", "直连组":
		return model.PolicyDirect, true
	case "REJECT":
		return model.PolicyReject, true
	}
	return 0, false
}

func TestGrade(t *testing.T) {
	tests := []struct {
		raw          string
		respect      bool
		apply        bool
		grade        model.Grade
		missing      bool
		viaRules     bool
		wantCodeText string
	}{
		{"https://1.1.1.1/dns-query#PROXY", false, true, model.GradeViaProxy, false, false, "proxy"},
		{"8.8.8.8#PROXY", false, true, model.GradeViaProxy, false, false, "proxy"},
		{"8.8.8.8#直连组", false, true, model.GradePlain, false, false, "plain"},
		{"8.8.8.8#NOPE", false, true, model.GradePlain, true, false, "plain"},
		{"tls://1.1.1.1#REJECT", false, true, model.GradeSafe, false, false, "safe"},
		{"https://1.1.1.1/dns-query", true, true, model.GradeViaProxy, false, true, "rules"},
		{"https://1.1.1.1/dns-query", true, false, model.GradeEncrypted, false, false, "enc-foreign"},
		{"8.8.8.8#RULES", false, true, model.GradeViaProxy, false, true, "rules"},
		{"system", true, true, model.GradePlain, false, false, "plain"},
		{"https://doh.pub/dns-query", false, true, model.GradeEncrypted, false, false, "enc-cn"},
	}
	for _, tt := range tests {
		s := Parse(tt.raw, model.Location{})
		Grade(&s, tt.respect, tt.apply, lookup)
		if s.Grade != tt.grade || s.ProxyMissing != tt.missing || s.ViaRules != tt.viaRules || ServerCode(s) != tt.wantCodeText {
			t.Errorf("%q respect=%v apply=%v: grade=%d missing=%v viaRules=%v code=%s", tt.raw, tt.respect, tt.apply, s.Grade, s.ProxyMissing, s.ViaRules, ServerCode(s))
		}
	}
}

func servers(raws ...string) []model.DNSServer {
	var out []model.DNSServer
	for _, r := range raws {
		s := Parse(r, model.Location{})
		Grade(&s, false, true, lookup)
		out = append(out, s)
	}
	return out
}

func TestWorst(t *testing.T) {
	tests := []struct {
		raws     []string
		level    Level
		culprits int
	}{
		{[]string{"8.8.8.8", "https://doh.pub/dns-query"}, LevelPlain, 1},
		{[]string{"https://doh.pub/dns-query", "https://1.1.1.1/dns-query"}, LevelCN, 1},
		{[]string{"https://dns.example.net/dns-query", "https://1.1.1.1/dns-query"}, LevelForeign, 2},
		{[]string{"https://1.1.1.1/dns-query#PROXY", "rcode://success"}, LevelSafe, 2},
		{nil, LevelSafe, 0},
	}
	for _, tt := range tests {
		l, c := Worst(servers(tt.raws...))
		if l != tt.level || len(c) != tt.culprits {
			t.Errorf("%v: level=%d culprits=%d", tt.raws, l, len(c))
		}
	}
}

func TestIsPureIP(t *testing.T) {
	for raw, want := range map[string]bool{
		"223.5.5.5":                   true,
		"tls://223.5.5.5":             true,
		"https://223.5.5.5/dns-query": true,
		"system":                      true,
		"2400:3200::1":                true,
		"dns.alidns.com":              false,
		"https://dns.alidns.com/x":    false,
		"dhcp://en0":                  false,
		"rcode://success":             false,
	} {
		if got := IsPureIP(Parse(raw, model.Location{})); got != want {
			t.Errorf("IsPureIP(%q) = %v", raw, got)
		}
	}
}

func TestSelect(t *testing.T) {
	d := &model.DNSConfig{
		Enable:     true,
		Nameserver: model.DNSList{Servers: servers("8.8.8.8")},
		Fallback:   model.DNSList{Servers: servers("tls://1.1.1.1")},
		NameserverPolicy: []model.PolicyEntry{
			{Key: "geosite:cn", Subkeys: []string{"geosite:cn"}, Servers: servers("https://doh.pub/dns-query")},
			{Key: "+.lan", Subkeys: []string{"+.lan"}, Servers: servers("system")},
		},
		FallbackFilter: model.FallbackFilter{Domain: []string{"+.google.com"}},
	}
	// policy hit (second entry), first entry unknown
	sel := Select(d, func(sk string) model.Tri {
		if sk == "geosite:cn" {
			return model.Unknown
		}
		if sk == "+.lan" {
			return model.Yes
		}
		return model.No
	}, nil)
	if sel.Source != SourcePolicy || sel.Policy.Key != "+.lan" || len(sel.Uncertain) != 1 {
		t.Errorf("policy selection = %+v", sel)
	}
	// fallback-filter hit
	sel = Select(d, func(string) model.Tri { return model.No }, func(kind, v string) model.Tri {
		if kind == "domain" && v == "+.google.com" {
			return model.Yes
		}
		return model.No
	})
	if sel.Source != SourceFallbackOnly || len(sel.Servers) != 1 || sel.Servers[0].Raw != "tls://1.1.1.1" {
		t.Errorf("fallback selection = %+v", sel)
	}
	// default = nameserver ∪ fallback
	sel = Select(d, nil, nil)
	if sel.Source != SourceDefault || len(sel.Servers) != 2 {
		t.Errorf("default selection = %+v", sel)
	}
	// dns disabled → system
	d.Enable = false
	sel = Select(d, nil, nil)
	if sel.Source != SourceSystem || sel.Servers[0].Grade != model.GradePlain {
		t.Errorf("system selection = %+v", sel)
	}
}
