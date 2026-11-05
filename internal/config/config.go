// Package config reads a mihomo YAML config into model.Config, keeping line
// numbers for every analysed element.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"dnsnitch/internal/dnsserver"
	"dnsnitch/internal/model"
	"dnsnitch/internal/ruleparse"
)

// ErrEncrypted is returned for age-encrypted configs (CFG-02).
var ErrEncrypted = errors.New("config file is age encrypted")

// ParseError wraps a YAML syntax / structure error.
type ParseError struct{ Err error }

func (e *ParseError) Error() string { return "parse config: " + e.Err.Error() }
func (e *ParseError) Unwrap() error { return e.Err }

// Load reads and parses the config file at path.
func Load(path string) (*model.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(path, data)
}

// IsEncrypted reports whether data looks like an age-encrypted file
// (binary or ASCII-armored).
func IsEncrypted(data []byte) bool {
	// mihomo (component/age DecryptBytes) only recognizes the armor header
	// at the start of the file; the binary header is accepted here too so
	// that such files are reported as encrypted instead of as bad YAML.
	trimmed := bytes.TrimLeft(bytes.TrimPrefix(data, utf8BOM), " \t\r\n")
	return bytes.HasPrefix(trimmed, []byte("age-encryption.org/v1")) ||
		bytes.HasPrefix(trimmed, []byte("-----BEGIN AGE ENCRYPTED FILE-----"))
}

var utf8BOM = []byte{0xef, 0xbb, 0xbf}

// Defaults from mihomo config.DefaultRawConfig (research §5).
var (
	defaultNameservers        = []string{"https://doh.pub/dns-query", "tls://223.5.5.5:853"}
	defaultDefaultNameservers = []string{"114.114.114.114", "223.5.5.5", "8.8.8.8", "1.0.0.1"}
)

// Parse parses config data; file is used in locations.
func Parse(file string, data []byte) (*model.Config, error) {
	if IsEncrypted(data) {
		return nil, ErrEncrypted
	}
	data = bytes.TrimPrefix(data, utf8BOM)

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, &ParseError{err}
	}
	// Decoding into Go values applies the checks mihomo's yaml.Unmarshal
	// into RawConfig applies too (e.g. duplicate mapping keys), which
	// decoding into a Node skips.
	var probe any
	if err := yaml.Unmarshal(data, &probe); err != nil {
		return nil, &ParseError{err}
	}
	var root *yaml.Node
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		root = resolve(doc.Content[0])
	}
	if root != nil && root.Kind == yaml.ScalarNode && root.Tag == "!!null" {
		root = nil
	}
	if root != nil && root.Kind != yaml.MappingNode {
		return nil, &ParseError{fmt.Errorf("top level of the config must be a mapping")}
	}

	p := &parser{file: file, cfg: &model.Config{File: file, SubRules: map[string][]model.Rule{}}}
	p.parseRoot(root)
	return p.cfg, nil
}

type parser struct {
	file string
	cfg  *model.Config
}

func (p *parser) loc(n *yaml.Node, path, text string) model.Location {
	line := 0
	if n != nil {
		line = n.Line
	}
	return model.Location{File: p.file, Line: line, Path: path, Text: text}
}

func (p *parser) checkKeys(n *yaml.Node, section, prefix string, valid []string) {
	for _, pr := range pairs(n) {
		k := pr.key.Value
		if contains(valid, k) {
			continue
		}
		p.cfg.UnknownKeys = append(p.cfg.UnknownKeys, model.UnknownKey{
			Section: section, Key: k, Loc: p.loc(pr.key, prefix+k, k),
			Anchor: pr.val != nil && pr.val.Anchor != "",
		})
	}
}

func (p *parser) parseRoot(root *yaml.Node) {
	p.checkKeys(root, "", "", topLevelKeys)

	_, proxies := get(root, "proxies")
	for i, it := range items(proxies) {
		_, name := get(it, "name")
		if n := scalar(name); n != "" {
			p.cfg.Proxies = append(p.cfg.Proxies, model.NameRef{Name: n, Loc: p.loc(it, fmt.Sprintf("proxies[%d]", i), n)})
		}
	}

	_, groups := get(root, "proxy-groups")
	for i, it := range items(groups) {
		p.cfg.ProxyGroups = append(p.cfg.ProxyGroups, p.parseGroup(it, i))
	}

	_, pp := get(root, "proxy-providers")
	for _, pr := range pairs(pp) {
		p.cfg.ProxyProviders = append(p.cfg.ProxyProviders, model.NameRef{Name: pr.key.Value, Loc: p.loc(pr.key, "proxy-providers."+pr.key.Value, pr.key.Value)})
	}

	_, rp := get(root, "rule-providers")
	for _, pr := range pairs(rp) {
		p.cfg.RuleProviders = append(p.cfg.RuleProviders, p.parseRuleProvider(pr.key, resolve(pr.val)))
	}

	rulesKey, rules := get(root, "rules")
	p.cfg.RulesLoc = p.loc(rulesKey, "rules", "")
	p.cfg.Rules = p.parseRuleList(rules, "rules")

	_, sub := get(root, "sub-rules")
	for _, pr := range pairs(sub) {
		name := pr.key.Value
		p.cfg.SubRules[name] = p.parseRuleList(pr.val, "sub-rules."+name)
	}

	_, hosts := get(root, "hosts")
	for _, pr := range pairs(hosts) {
		p.cfg.Hosts = append(p.cfg.Hosts, model.HostEntry{Pattern: pr.key.Value, Loc: p.loc(pr.key, "hosts."+pr.key.Value, pr.key.Value)})
	}

	dnsKey, dns := get(root, "dns")
	p.parseDNS(dnsKey, dns)
}

func (p *parser) parseGroup(n *yaml.Node, idx int) model.ProxyGroup {
	_, name := get(n, "name")
	_, tp := get(n, "type")
	g := model.ProxyGroup{Name: scalar(name), Type: scalar(tp)}
	g.Loc = p.loc(n, fmt.Sprintf("proxy-groups[%d]", idx), g.Name)
	_, members := get(n, "proxies")
	for j, m := range items(members) {
		v := scalar(m)
		g.Members = append(g.Members, model.NameRef{Name: v, Loc: p.loc(m, fmt.Sprintf("proxy-groups[%d].proxies[%d]", idx, j), v)})
	}
	_, use := get(n, "use")
	for _, u := range items(use) {
		g.Use = append(g.Use, scalar(u))
	}
	for _, k := range []string{"include-all", "include-all-proxies", "include-all-providers"} {
		if _, v := get(n, k); boolean(v, false) {
			g.IncludeAll = true
		}
	}
	return g
}

func (p *parser) parseRuleProvider(key, n *yaml.Node) model.RuleProvider {
	rp := model.RuleProvider{Name: key.Value, Loc: p.loc(key, "rule-providers."+key.Value, key.Value)}
	str := func(k string) string {
		_, v := get(n, k)
		return scalar(v)
	}
	rp.Type = strings.ToLower(str("type"))
	rp.Behavior = strings.ToLower(str("behavior"))
	rp.Format = strings.ToLower(str("format"))
	if rp.Format == "" {
		rp.Format = "yaml"
	}
	rp.Path = str("path")
	rp.URL = str("url")
	if _, payload := get(n, "payload"); payload != nil {
		rp.HasPayload = true
		for i, it := range items(payload) {
			v := scalar(it)
			rp.Payload = append(rp.Payload, v)
			rp.PayloadLocs = append(rp.PayloadLocs, p.loc(it, fmt.Sprintf("rule-providers.%s.payload[%d]", rp.Name, i), v))
		}
	}
	return rp
}

func (p *parser) parseRuleList(n *yaml.Node, path string) []model.Rule {
	var out []model.Rule
	for i, it := range items(n) {
		if it.Kind != yaml.ScalarNode {
			continue
		}
		r := ruleparse.Parse(it.Value, true)
		r.Index = i
		r = ruleparse.WithLoc(r, p.loc(it, fmt.Sprintf("%s[%d]", path, i), it.Value))
		out = append(out, r)
	}
	return out
}

func (p *parser) serverList(keyNode, n *yaml.Node, path string) model.DNSList {
	l := model.DNSList{Present: keyNode != nil, Loc: p.loc(keyNode, path, "")}
	for i, it := range items(n) {
		v := scalar(it)
		l.Servers = append(l.Servers, dnsserver.Parse(v, p.loc(it, fmt.Sprintf("%s[%d]", path, i), v)))
	}
	return l
}

func (p *parser) defaultList(values []string, at model.Location, path string) []model.DNSServer {
	var out []model.DNSServer
	for _, v := range values {
		loc := at
		loc.Path, loc.Text = path, v
		out = append(out, dnsserver.Parse(v, loc))
	}
	return out
}

func (p *parser) parseDNS(key, n *yaml.Node) {
	d := &p.cfg.DNS
	if key == nil {
		d.Loc = model.Location{File: p.file, Path: "dns"}
		return
	}
	d.Present = true
	d.Loc = p.loc(key, "dns", "dns")
	p.checkKeys(n, "dns", "dns.", dnsKeys)

	if k, v := get(n, "enable"); k != nil {
		d.Enable = boolean(v, false)
		d.EnableLoc = p.loc(k, "dns.enable", "enable: "+scalar(v))
	}
	if k, v := get(n, "respect-rules"); k != nil {
		d.RespectRules = boolean(v, false)
		d.RespectRulesLoc = p.loc(k, "dns.respect-rules", "respect-rules: "+scalar(v))
	}
	_, lazy := get(n, "fallback-lazy-query")
	d.FallbackLazyQuery = boolean(lazy, false)

	list := func(name string) model.DNSList {
		k, v := get(n, name)
		return p.serverList(k, v, "dns."+name)
	}
	d.Nameserver = list("nameserver")
	if !d.Nameserver.Present {
		d.Nameserver.Servers = p.defaultList(defaultNameservers, d.Loc, "dns.nameserver")
	}
	d.Fallback = list("fallback")
	d.DefaultNameserver = list("default-nameserver")
	if !d.DefaultNameserver.Present {
		d.DefaultNameserver.Servers = p.defaultList(defaultDefaultNameservers, d.Loc, "dns.default-nameserver")
	}
	d.ProxyServerNameserver = list("proxy-server-nameserver")
	d.DirectNameserver = list("direct-nameserver")

	_, pol := get(n, "nameserver-policy")
	d.NameserverPolicy = p.parsePolicy(pol, "dns.nameserver-policy")
	_, ppol := get(n, "proxy-server-nameserver-policy")
	d.ProxyServerNameserverPolicy = p.parsePolicy(ppol, "dns.proxy-server-nameserver-policy")

	ffKey, ff := get(n, "fallback-filter")
	if ffKey != nil {
		p.checkKeys(ff, "dns.fallback-filter", "dns.fallback-filter.", fallbackFilterKeys)
		d.FallbackFilter.Loc = p.loc(ffKey, "dns.fallback-filter", "fallback-filter")
		_, dom := get(ff, "domain")
		for _, it := range items(dom) {
			d.FallbackFilter.Domain = append(d.FallbackFilter.Domain, scalar(it))
		}
		_, gs := get(ff, "geosite")
		for _, it := range items(gs) {
			d.FallbackFilter.Geosite = append(d.FallbackFilter.Geosite, scalar(it))
		}
	}
}

func (p *parser) parsePolicy(n *yaml.Node, path string) []model.PolicyEntry {
	var out []model.PolicyEntry
	for _, pr := range pairs(n) {
		k := pr.key.Value
		e := model.PolicyEntry{Key: k, Subkeys: SplitPolicyKey(k), Loc: p.loc(pr.key, path+"."+k, k)}
		for i, it := range items(pr.val) {
			v := scalar(it)
			e.Servers = append(e.Servers, dnsserver.Parse(v, p.loc(it, fmt.Sprintf("%s.%s[%d]", path, k, i), v)))
		}
		out = append(out, e)
	}
	return out
}

// SplitPolicyKey splits a nameserver-policy key the way
// config.parseNameServerPolicy does. Prefixes are normalized to lower case.
func SplitPolicyKey(k string) []string {
	lower := strings.ToLower(k)
	for _, prefix := range []string{"geosite:", "rule-set:"} {
		if strings.HasPrefix(lower, prefix) {
			rest := k[len(prefix):]
			var out []string
			for _, s := range strings.Split(rest, ",") {
				out = append(out, prefix+strings.TrimSpace(s))
			}
			return out
		}
	}
	var out []string
	for _, s := range strings.Split(k, ",") {
		out = append(out, strings.TrimSpace(s))
	}
	return out
}
