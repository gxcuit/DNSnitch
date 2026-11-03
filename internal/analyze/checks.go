package analyze

import (
	"sort"
	"strings"

	"dnsleak/internal/config"
	"dnsleak/internal/dnsserver"
	"dnsleak/internal/model"
	"dnsleak/internal/ruledata"
)

// Valid key lists for suggestions, by section.
var sectionKeys = map[string][]string{}

func init() {
	sectionKeys[""] = config.TopLevelKeys()
	sectionKeys["dns"] = config.DNSKeys()
	sectionKeys["dns.fallback-filter"] = config.FallbackFilterKeys()
}

// checkUnknownKeys implements CFG-01. A key with a close valid spelling is
// most likely a typo that silently disables a setting (medium); other
// unknown keys are low.
func (e *Env) checkUnknownKeys() []model.Finding {
	var out []model.Finding
	for _, k := range e.Cfg.UnknownKeys {
		f := model.Finding{
			ID: "CFG-01", Severity: model.Low,
			Args:      model.Args{"key": k.Key, "section": k.Section},
			Locations: []model.Location{k.Loc.WithRole(model.RoleConfig)},
		}
		if k.Anchor {
			// A key defining a YAML anchor is a helper for later aliases.
			f.Args["anchor"] = "true"
		} else if s := config.Suggest(k.Key, sectionKeys[k.Section]); s != "" {
			f.Args["suggest"] = s
			f.Severity = model.Medium
		}
		out = append(out, f)
	}
	return out
}

// checkMissingRefs implements CFG-03: rule targets, sub-rule names,
// rule-set names and proxy-group members that do not exist.
func (e *Env) checkMissingRefs() []model.Finding {
	var out []model.Finding
	missing := func(kind, name string, loc model.Location) {
		out = append(out, model.Finding{
			ID: "CFG-03", Severity: model.Error,
			Args:      model.Args{"kind": kind, "name": name},
			Locations: []model.Location{loc.WithRole(model.RoleConfig)},
		})
	}
	var checkRuleSets func(r model.Rule)
	checkRuleSets = func(r model.Rule) {
		if r.Type == "RULE-SET" && e.Cfg.RuleProvider(r.Payload) == nil {
			missing("rule-set", r.Payload, r.Loc)
		}
		for _, s := range r.Subs {
			checkRuleSets(s)
		}
	}
	checkList := func(rules []model.Rule) {
		for _, r := range rules {
			if r.Err != "" {
				continue
			}
			checkRuleSets(r)
			if r.Type == "SUB-RULE" {
				if _, ok := e.Cfg.SubRules[r.Target]; !ok {
					missing("sub-rule", r.Target, r.Loc)
				}
				continue
			}
			if r.Target != "" && !e.Pol.Exists(r.Target) {
				missing("rule-target", r.Target, r.Loc)
			}
		}
	}
	checkList(e.Cfg.Rules)
	for _, name := range sortedKeys(e.Cfg.SubRules) {
		checkList(e.Cfg.SubRules[name])
	}
	for _, g := range e.Cfg.ProxyGroups {
		for _, m := range g.Members {
			if !e.Pol.Exists(m.Name) {
				missing("group-member", m.Name, m.Loc)
			}
		}
	}
	return out
}

func (e *Env) checkDNS() []model.Finding {
	var out []model.Finding
	d := &e.Cfg.DNS

	// DNS-01
	if !d.Enable {
		kind, loc := "missing", d.Loc
		if d.Present {
			kind = "disabled"
			if d.EnableLoc.Line > 0 {
				loc = d.EnableLoc
			}
		}
		out = append(out, model.Finding{
			ID: "DNS-01", Severity: model.Low,
			Args:      model.Args{"kind": kind},
			Locations: []model.Location{loc.WithRole(model.RoleConfig)},
		})
	}

	if d.Enable {
		// DNS-02
		var plain []model.DNSServer
		for _, s := range dnsserver.DefaultServers(d) {
			if s.Grade == model.GradePlain {
				plain = append(plain, s)
			}
		}
		if len(plain) > 0 {
			out = append(out, model.Finding{
				ID: "DNS-02", Severity: model.Medium,
				Args:      model.Args{"servers": joinRaw(plain)},
				Locations: serverLocs(plain, model.RoleResolver),
			})
		}
		// DNS-04
		out = append(out, e.checkPolicyProxySets()...)
		// DNS-05
		if len(d.Fallback.Servers) > 0 {
			out = append(out, model.Finding{
				ID: "DNS-05", Severity: model.Info,
				Args:      model.Args{"lazy": boolStr(d.FallbackLazyQuery)},
				Locations: []model.Location{d.Fallback.Loc.WithRole(model.RoleConfig)},
			})
		}
	}

	if d.Present {
		// DNS-06
		if d.RespectRules && len(d.ProxyServerNameserver.Servers) == 0 {
			out = append(out, model.Finding{
				ID: "DNS-06", Severity: model.Error,
				Locations: []model.Location{d.RespectRulesLoc.WithRole(model.RoleConfig)},
			})
		}
		// DNS-08
		if d.DefaultNameserver.Present {
			if len(d.DefaultNameserver.Servers) == 0 {
				out = append(out, model.Finding{
					ID: "DNS-08", Severity: model.Error,
					Args:      model.Args{"kind": "empty"},
					Locations: []model.Location{d.DefaultNameserver.Loc.WithRole(model.RoleConfig)},
				})
			}
			for _, s := range d.DefaultNameserver.Servers {
				if !dnsserver.IsPureIP(s) {
					out = append(out, model.Finding{
						ID: "DNS-08", Severity: model.Error,
						Args:      model.Args{"kind": "not-ip", "server": s.Raw},
						Locations: serverLocs([]model.DNSServer{s}, model.RoleConfig),
					})
				}
			}
		}
	}

	// DNS-07
	for _, s := range allServers(d) {
		if s.ProxyMissing {
			out = append(out, model.Finding{
				ID: "DNS-07", Severity: model.Error,
				Args:      model.Args{"server": s.Raw, "name": s.ProxyName},
				Locations: serverLocs([]model.DNSServer{s}, model.RoleConfig),
			})
		}
	}

	// DNS-09
	var plainPS []model.DNSServer
	for _, s := range d.ProxyServerNameserver.Servers {
		if s.Grade == model.GradePlain {
			plainPS = append(plainPS, s)
		}
	}
	if len(plainPS) > 0 && d.Present {
		out = append(out, model.Finding{
			ID: "DNS-09", Severity: model.Low,
			Args:      model.Args{"servers": joinRaw(plainPS)},
			Locations: serverLocs(plainPS, model.RoleResolver),
		})
	}
	return out
}

// checkPolicyProxySets implements DNS-04.
func (e *Env) checkPolicyProxySets() []model.Finding {
	var out []model.Finding
	for i := range e.Cfg.DNS.NameserverPolicy {
		entry := &e.Cfg.DNS.NameserverPolicy[i]
		level, culprits := dnsserver.Worst(entry.Servers)
		if level != dnsserver.LevelPlain && level != dnsserver.LevelCN {
			continue
		}
		for _, sk := range entry.Subkeys {
			isProxy, related, builtin := e.proxyDomainSet(sk)
			if !isProxy {
				continue
			}
			sev := model.Medium
			if level == dnsserver.LevelPlain {
				sev = model.High
			}
			f := model.Finding{
				ID: "DNS-04", Severity: sev,
				Args: model.Args{"key": sk, "level": level.Code()},
			}
			f.Locations = append(f.Locations, entry.Loc.WithRole(model.RoleConfig))
			f.Locations = append(f.Locations, serverLocs(culprits, model.RoleResolver)...)
			for _, r := range related {
				f.Locations = append(f.Locations, r.Loc.WithRole(model.RoleRelated))
			}
			if builtin {
				f.Notes = append(f.Notes, model.Note{Key: "proxy-set-builtin", Args: model.Args{"key": sk}})
			}
			out = append(out, f)
		}
	}
	return out
}

// proxyDomainSet decides whether a nameserver-policy subkey denotes domains
// that should be proxied: the rules route it to a proxy, or (when the rules
// do not mention it) it is a well-known non-CN geosite list.
func (e *Env) proxyDomainSet(sk string) (isProxy bool, related []model.Rule, builtin bool) {
	lower := strings.ToLower(sk)
	referenced := false
	for _, r := range e.Cfg.Rules {
		if r.Err != "" || r.Type == "SUB-RULE" {
			continue
		}
		var hit bool
		switch {
		case strings.HasPrefix(lower, "geosite:"):
			hit = r.Type == "GEOSITE" && strings.EqualFold(r.Payload, sk[len("geosite:"):])
		case strings.HasPrefix(lower, "rule-set:"):
			hit = r.Type == "RULE-SET" && r.Payload == sk[len("rule-set:"):]
		default:
			hit = (r.Type == "DOMAIN" || r.Type == "DOMAIN-SUFFIX") && ruledata.PatternMatch(sk, r.Payload)
		}
		if !hit {
			continue
		}
		referenced = true
		if ok, _ := e.proxyTarget(r.Target); ok {
			related = append(related, r)
		}
	}
	if len(related) > 0 {
		return true, related, false
	}
	if !referenced && strings.HasPrefix(lower, "geosite:") && knownProxyGeosite(lower[len("geosite:"):]) {
		return true, nil, true
	}
	return false, nil, false
}

// knownProxyGeosite reports well-known lists of domains outside mainland
// China ("geolocation-!cn", "category-*-!cn", "gfw", ...).
func knownProxyGeosite(name string) bool {
	parts := strings.Split(name, "@")
	for _, a := range parts[1:] {
		if a == "cn" {
			return false
		}
	}
	base := parts[0]
	switch base {
	case "gfw", "greatfire", "geolocation-!cn", "tld-!cn":
		return true
	}
	return strings.HasSuffix(base, "-!cn")
}

func allServers(d *model.DNSConfig) []model.DNSServer {
	var out []model.DNSServer
	for _, l := range []model.DNSList{d.Nameserver, d.Fallback, d.DefaultNameserver, d.ProxyServerNameserver, d.DirectNameserver} {
		if l.Present {
			out = append(out, l.Servers...)
		}
	}
	for _, p := range [][]model.PolicyEntry{d.NameserverPolicy, d.ProxyServerNameserverPolicy} {
		for _, e := range p {
			out = append(out, e.Servers...)
		}
	}
	return out
}

func serverLocs(servers []model.DNSServer, role string) []model.Location {
	out := make([]model.Location, 0, len(servers))
	for _, s := range servers {
		loc := s.Loc
		loc.Text = s.Raw
		out = append(out, loc.WithRole(role))
	}
	return out
}

func joinRaw(servers []model.DNSServer) string {
	parts := make([]string, 0, len(servers))
	for _, s := range servers {
		parts = append(parts, s.Raw)
	}
	return strings.Join(parts, ", ")
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
