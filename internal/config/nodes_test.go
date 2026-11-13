package config

import (
	"errors"
	"strings"
	"testing"
)

const nodesSample = `base: &base
  enable: true
  nameserver:
    - 8.8.8.8
shared: &shared [1.1.1.1]
dns:
  <<: *base
  fallback: *shared
  proxy-server-nameserver: 223.5.5.5
  default-nameserver:
    - 223.5.5.5
    - &one tls://1.0.0.1
rules:
  - GEOIP,CN,DIRECT
  - 'MATCH,PROXY'
sub-rules:
  a:
    b: [x]
  a.b:
    - DOMAIN,a.com,DIRECT
  "x[1]":
    - DOMAIN,b.com,DIRECT
dns-copy:
  list: [*one]
`

func TestFind(t *testing.T) {
	d, err := Nodes([]byte(nodesSample))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		path      string
		value     string // Node.Value for scalars
		keyValue  string // Key.Value, "" when Key must be nil
		line, col int
		alias     bool
		merge     bool
		anchored  bool
	}{
		{path: "rules[0]", value: "GEOIP,CN,DIRECT", line: 14, col: 5},
		{path: "rules[1]", value: "MATCH,PROXY", line: 15, col: 5},
		{path: "sub-rules.a.b[0]", value: "DOMAIN,a.com,DIRECT", line: 20, col: 7},
		{path: "sub-rules.a.b", keyValue: "a.b", line: 19, col: 3},
		{path: "sub-rules.x[1][0]", value: "DOMAIN,b.com,DIRECT", line: 22, col: 7},
		{path: "dns.nameserver[0]", value: "8.8.8.8", line: 4, col: 7, merge: true, anchored: true},
		{path: "dns.enable", value: "true", keyValue: "enable", line: 2, col: 11, merge: true, anchored: true},
		{path: "dns.fallback[0]", value: "1.1.1.1", line: 5, col: 18, alias: true, anchored: true},
		{path: "dns.proxy-server-nameserver[0]", value: "223.5.5.5", keyValue: "proxy-server-nameserver", line: 9, col: 28},
		{path: "dns.default-nameserver[0]", value: "223.5.5.5", line: 11, col: 7},
		{path: "dns.default-nameserver[1]", value: "tls://1.0.0.1", line: 12, col: 7, anchored: true},
		{path: "dns-copy.list[0]", value: "tls://1.0.0.1", line: 12, col: 7, alias: true, anchored: true},
		{path: "dns", keyValue: "dns", line: 6, col: 1},
	}
	for _, tt := range tests {
		tg, err := d.Find(tt.path)
		if err != nil {
			t.Errorf("%s: %v", tt.path, err)
			continue
		}
		if tt.value != "" && tg.Node.Value != tt.value {
			t.Errorf("%s: value %q, want %q", tt.path, tg.Node.Value, tt.value)
		}
		n := tg.Node
		if tt.keyValue != "" {
			if tg.Key == nil || tg.Key.Value != tt.keyValue {
				t.Errorf("%s: key = %+v, want %q", tt.path, tg.Key, tt.keyValue)
				continue
			}
			if tt.value == "" {
				n = tg.Key
			}
		}
		if n.Line != tt.line || n.Column != tt.col {
			t.Errorf("%s: at %d:%d, want %d:%d", tt.path, n.Line, n.Column, tt.line, tt.col)
		}
		if tg.ViaAlias != tt.alias || tg.ViaMerge != tt.merge || tg.Anchored != tt.anchored {
			t.Errorf("%s: alias=%v merge=%v anchored=%v, want %v %v %v", tt.path, tg.ViaAlias, tg.ViaMerge, tg.Anchored, tt.alias, tt.merge, tt.anchored)
		}
		if tg.Shared() != (tt.alias || tt.merge || tt.anchored) {
			t.Errorf("%s: Shared() = %v", tt.path, tg.Shared())
		}
	}

	for _, p := range []string{"", "nope", "rules[9]", "rules[x]", "rules.0", "dns.nameserver[1]", "sub-rules.a.c", "dns.proxy-server-nameserver[1]"} {
		if _, err := d.Find(p); !errors.Is(err, ErrNotFound) {
			t.Errorf("Find(%q) err = %v, want ErrNotFound", p, err)
		}
	}
}

func TestFindParentAndHasKey(t *testing.T) {
	d, err := Nodes([]byte(nodesSample))
	if err != nil {
		t.Fatal(err)
	}
	tg, err := d.Find("dns.nameserver")
	if err != nil {
		t.Fatal(err)
	}
	base, _ := d.Find("base")
	if tg.Parent != base.Node {
		t.Error("merged pair: Parent should be the merge source mapping")
	}
	dns, _ := d.Find("dns")
	if !HasKey(dns.Node, "enable") || !HasKey(dns.Node, "fallback") || HasKey(dns.Node, "nameserver-policy") {
		t.Error("HasKey should count explicit and merged keys only")
	}
	item, _ := d.Find("rules[1]")
	rules, _ := d.Find("rules")
	if item.Parent != rules.Node || item.Key != nil {
		t.Error("sequence item: Parent should be the sequence, Key nil")
	}
}

func TestListValues(t *testing.T) {
	d, err := Nodes([]byte(nodesSample + "lists:\n  empty: ~\n  mixed: [a, [b], *one]\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ path, want string }{
		{"dns.nameserver", "8.8.8.8"},
		{"dns.fallback", "1.1.1.1"},                  // alias to a sequence
		{"dns.proxy-server-nameserver", "223.5.5.5"}, // scalar = one-element list
		{"dns.default-nameserver", "223.5.5.5|tls://1.0.0.1"},
		{"lists.empty", ""},
		{"lists.mixed", "a|\x00|tls://1.0.0.1"},
	} {
		tg, err := d.Find(tt.path)
		if err != nil {
			t.Fatalf("%s: %v", tt.path, err)
		}
		if got := strings.Join(ListValues(tg.Node), "|"); got != tt.want {
			t.Errorf("ListValues(%s) = %q, want %q", tt.path, got, tt.want)
		}
	}
	if got := ListValues(nil); got == nil || len(got) != 0 {
		t.Errorf("ListValues(nil) = %#v, want empty non-nil", got)
	}
}

func TestNodesBOMAndErrors(t *testing.T) {
	d, err := Nodes(append([]byte{0xef, 0xbb, 0xbf}, "a: 1\n"...))
	if err != nil || d.BOM != 3 {
		t.Fatalf("BOM = %d, err = %v", d.BOM, err)
	}
	if tg, err := d.Find("a"); err != nil || tg.Key.Line != 1 || tg.Key.Column != 1 {
		t.Errorf("after BOM: %+v %v", tg, err)
	}
	if d, err := Nodes([]byte("a: 1\n")); err != nil || d.BOM != 0 {
		t.Errorf("no BOM: %v %v", d, err)
	}
	var pe *ParseError
	if _, err := Nodes([]byte("a: [1, 2\n")); !errors.As(err, &pe) {
		t.Errorf("bad yaml: %v", err)
	}
	if _, err := Nodes([]byte("age-encryption.org/v1\n")); !errors.Is(err, ErrEncrypted) {
		t.Errorf("encrypted: %v", err)
	}
	empty, err := Nodes(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := empty.Find("a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("empty doc: %v", err)
	}
}
