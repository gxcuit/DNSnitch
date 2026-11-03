package config

import (
	"errors"
	"reflect"
	"testing"
)

const sample = `# comment
proxies:
  - &node {name: hk, type: ss, server: a.example.com, port: 1, cipher: x, password: y}
proxy-groups:
  - name: PROXY
    type: select
    proxies: [hk, DIRECT]
dns-base: &dnsbase
  enable: true
  nameserver:
    - 8.8.8.8
dns:
  <<: *dnsbase
  respect-rules: true
  nameserver-police:
    "+.lan": system
  nameserver-policy:
    "geosite:cn,private": https://doh.pub/dns-query
    "+.a.com,+.b.com":
      - tls://223.5.5.5
  fallback-filter:
    domain: ['+.google.com']
    geoipp: true
rules:
  - GEOIP,CN,DIRECT
  - MATCH,PROXY
sub-rules:
  sub1:
    - DOMAIN,a.com,DIRECT
`

func TestParseSample(t *testing.T) {
	cfg, err := Parse("cfg.yaml", []byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Proxies) != 1 || cfg.Proxies[0].Name != "hk" || cfg.Proxies[0].Loc.Line != 3 {
		t.Errorf("proxies = %+v", cfg.Proxies)
	}
	if g := cfg.ProxyGroups[0]; g.Name != "PROXY" || len(g.Members) != 2 || g.Members[1].Name != "DIRECT" {
		t.Errorf("group = %+v", g)
	}
	d := cfg.DNS
	// enable and nameserver come from the merge key
	if !d.Present || !d.Enable || !d.RespectRules {
		t.Errorf("dns flags = %+v", d)
	}
	if len(d.Nameserver.Servers) != 1 || d.Nameserver.Servers[0].Raw != "8.8.8.8" || d.Nameserver.Servers[0].Loc.Line != 11 {
		t.Errorf("nameserver = %+v", d.Nameserver)
	}
	if len(d.NameserverPolicy) != 2 {
		t.Fatalf("policy = %+v", d.NameserverPolicy)
	}
	if !reflect.DeepEqual(d.NameserverPolicy[0].Subkeys, []string{"geosite:cn", "geosite:private"}) {
		t.Errorf("subkeys = %v", d.NameserverPolicy[0].Subkeys)
	}
	if p := d.NameserverPolicy[1]; !reflect.DeepEqual(p.Subkeys, []string{"+.a.com", "+.b.com"}) || p.Servers[0].Loc.Line != 20 {
		t.Errorf("policy[1] = %+v", p)
	}
	if !reflect.DeepEqual(d.FallbackFilter.Domain, []string{"+.google.com"}) {
		t.Errorf("fallback-filter = %+v", d.FallbackFilter)
	}
	if len(cfg.Rules) != 2 || cfg.Rules[0].Loc.Line != 25 || cfg.Rules[0].Loc.Path != "rules[0]" || cfg.Rules[1].Type != "MATCH" {
		t.Errorf("rules = %+v", cfg.Rules)
	}
	if len(cfg.SubRules["sub1"]) != 1 {
		t.Errorf("sub-rules = %+v", cfg.SubRules)
	}

	unknown := map[string]string{}
	for _, k := range cfg.UnknownKeys {
		unknown[k.Section+"/"+k.Key] = Suggest(k.Key, map[string][]string{"": topLevelKeys, "dns": dnsKeys, "dns.fallback-filter": fallbackFilterKeys}[k.Section])
	}
	want := map[string]string{
		"/dns-base":                  "",
		"dns/nameserver-police":      "nameserver-policy",
		"dns.fallback-filter/geoipp": "geoip",
	}
	if !reflect.DeepEqual(unknown, want) {
		t.Errorf("unknown keys = %v", unknown)
	}
}

func TestDefaults(t *testing.T) {
	cfg, err := Parse("c.yaml", []byte("rules:\n  - MATCH,DIRECT\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DNS.Present || cfg.DNS.Enable {
		t.Errorf("missing dns should be disabled: %+v", cfg.DNS)
	}
	cfg, err = Parse("c.yaml", []byte("dns:\n  enable: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.DNS.Nameserver.Servers) != 2 || cfg.DNS.Nameserver.Present {
		t.Errorf("default nameserver = %+v", cfg.DNS.Nameserver)
	}
	if cfg.DNS.DefaultNameserver.Present || len(cfg.DNS.DefaultNameserver.Servers) != 4 {
		t.Errorf("default default-nameserver = %+v", cfg.DNS.DefaultNameserver)
	}
	// empty file
	if _, err := Parse("e.yaml", nil); err != nil {
		t.Errorf("empty file: %v", err)
	}
}

func TestCRLFAndBOM(t *testing.T) {
	data := []byte("\xef\xbb\xbfdns:\r\n  enable: true\r\n  nameserver:\r\n    - 8.8.8.8\r\n")
	cfg, err := Parse("c.yaml", data)
	if err != nil {
		t.Fatal(err)
	}
	if s := cfg.DNS.Nameserver.Servers; len(s) != 1 || s[0].Loc.Line != 4 {
		t.Errorf("nameserver = %+v", s)
	}
}

func TestEncrypted(t *testing.T) {
	for _, data := range []string{
		"age-encryption.org/v1\n-> X25519 abc\n--- def\n\x00\x01",
		"\n-----BEGIN AGE ENCRYPTED FILE-----\nYWdl\n-----END AGE ENCRYPTED FILE-----\n",
	} {
		if _, err := Parse("x.yaml", []byte(data)); !errors.Is(err, ErrEncrypted) {
			t.Errorf("want ErrEncrypted, got %v", err)
		}
	}
}

func TestParseErrors(t *testing.T) {
	var pe *ParseError
	if _, err := Parse("x.yaml", []byte("rules: [\n")); !errors.As(err, &pe) {
		t.Errorf("want ParseError, got %v", err)
	}
	if _, err := Parse("x.yaml", []byte("- a\n- b\n")); !errors.As(err, &pe) {
		t.Errorf("want ParseError for non-mapping root, got %v", err)
	}
	// mihomo's yaml.Unmarshal rejects duplicate keys at any level.
	for _, data := range []string{
		"dns:\n  enable: true\ndns:\n  enable: false\n",
		"dns:\n  enable: true\n  enable: false\n",
	} {
		if _, err := Parse("x.yaml", []byte(data)); !errors.As(err, &pe) {
			t.Errorf("want ParseError for duplicate keys in %q, got %v", data, err)
		}
	}
}

func TestArmorHeaderOnlyAtStart(t *testing.T) {
	// mihomo only treats the armor header at the start as encryption.
	data := "rules:\n  - MATCH,DIRECT\n# -----BEGIN AGE ENCRYPTED FILE-----\n"
	if _, err := Parse("x.yaml", []byte(data)); err != nil {
		t.Errorf("plain config with header text in a comment: %v", err)
	}
}

func TestAnchorKeys(t *testing.T) {
	cfg, err := Parse("x.yaml", []byte("p: &p {type: ss}\nproxy-group: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, k := range cfg.UnknownKeys {
		got[k.Key] = k.Anchor
	}
	if !got["p"] || got["proxy-group"] {
		t.Errorf("anchor flags = %v", got)
	}
}

func TestSuggest(t *testing.T) {
	for key, want := range map[string]string{
		"nameserver-police": "nameserver-policy",
		"Nameserver":        "nameserver",
		"respect-rule":      "respect-rules",
		"totally-unrelated": "",
	} {
		if got := Suggest(key, dnsKeys); got != want {
			t.Errorf("Suggest(%q) = %q, want %q", key, got, want)
		}
	}
	for key, want := range map[string]string{
		"dsn":         "dns", // transposition
		"mixed-prot":  "mixed-port",
		"u":           "", // too short to be a typo of "tun"
		"pr":          "", // ... or of "port"
		"proxy-group": "proxy-groups",
	} {
		if got := Suggest(key, topLevelKeys); got != want {
			t.Errorf("Suggest(%q) = %q, want %q", key, got, want)
		}
	}
}
