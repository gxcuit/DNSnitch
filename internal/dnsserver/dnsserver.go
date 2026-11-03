// Package dnsserver parses DNS server addresses the way mihomo's
// config.parseNameServer does, grades them, and selects the servers that
// receive a query during rule matching (research §2–§3).
package dnsserver

import (
	"net/netip"
	"net/url"
	"strings"

	"dnsleak/internal/model"
)

// Parse parses one server string. It fills Raw, Scheme, Host, ProxyName,
// Invalid and Region, and sets the syntactic grade. Proxy-dependent grading
// is done by Grade.
func Parse(raw string, loc model.Location) model.DNSServer {
	s := model.DNSServer{Raw: raw, Loc: loc}
	server := strings.TrimSpace(raw)

	// parsePureDNSServer
	switch {
	case server == "system":
		server = "system://"
	default:
		if ip, err := netip.ParseAddr(server); err == nil {
			if ip.Is4() {
				server = "udp://" + server
			} else {
				server = "udp://[" + server + "]"
			}
		} else if !strings.Contains(server, "://") {
			server = "udp://" + server
		}
	}

	u, err := url.Parse(server)
	if err != nil {
		s.Invalid = true
		s.Scheme = "udp"
		s.Grade = model.GradePlain
		return s
	}
	for _, part := range strings.Split(u.Fragment, "&") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 1 {
			s.ProxyName = kv[0]
		}
	}
	s.Scheme = strings.ToLower(u.Scheme)
	s.Host = strings.ToLower(u.Hostname())

	switch s.Scheme {
	case "udp", "tcp", "http":
		s.Grade = model.GradePlain
	case "tls", "https", "quic":
		s.Grade = model.GradeEncrypted
	case "system":
		s.Grade = model.GradePlain
	case "dhcp":
		s.Grade = model.GradePlain
		s.Host = strings.TrimPrefix(server, "dhcp://")
		if s.Host == "system" {
			s.Scheme, s.Host = "system", ""
		}
	case "ts", "tailscale", "et", "easytier":
		s.Grade = model.GradeViaProxy
	case "rcode":
		s.Grade = model.GradeSafe
	default:
		s.Invalid = true
		s.Grade = model.GradePlain
	}
	s.Region = regionOf(s.Host)
	return s
}

// ProxyLookup classifies a policy name; ok is false if the name does not
// exist.
type ProxyLookup func(name string) (class model.PolicyClass, ok bool)

// respectRulesName is the proxy name mihomo uses for respect-rules
// (tunnel.DnsRespectRules).
const respectRulesName = "RULES"

// networkSchemes are the schemes whose connection can be routed through a
// proxy via #name or respect-rules.
func networkScheme(scheme string) bool {
	switch scheme {
	case "udp", "tcp", "http", "tls", "https", "quic":
		return true
	}
	return false
}

// Grade applies #name and respect-rules to a parsed server.
// applyRespect is true for nameserver / fallback / nameserver-policy.
func Grade(s *model.DNSServer, respectRules, applyRespect bool, lookup ProxyLookup) {
	if !networkScheme(s.Scheme) || s.Invalid {
		return
	}
	switch {
	case s.ProxyName == respectRulesName:
		s.Grade, s.ViaRules = model.GradeViaProxy, true
	case s.ProxyName != "":
		class, ok := lookup(s.ProxyName)
		if !ok {
			s.ProxyMissing = true
			return
		}
		switch class {
		case model.PolicyProxy:
			s.Grade = model.GradeViaProxy
		case model.PolicyReject:
			s.Grade = model.GradeSafe
		}
	case respectRules && applyRespect:
		s.Grade, s.ViaRules = model.GradeViaProxy, true
	}
}

// GradeConfig grades every server list of the dns section in place.
func GradeConfig(d *model.DNSConfig, lookup ProxyLookup) {
	grade := func(list []model.DNSServer, apply bool) {
		for i := range list {
			Grade(&list[i], d.RespectRules, apply, lookup)
		}
	}
	grade(d.Nameserver.Servers, true)
	grade(d.Fallback.Servers, true)
	for i := range d.NameserverPolicy {
		grade(d.NameserverPolicy[i].Servers, true)
	}
	grade(d.DefaultNameserver.Servers, false)
	grade(d.ProxyServerNameserver.Servers, false)
	grade(d.DirectNameserver.Servers, false)
	for i := range d.ProxyServerNameserverPolicy {
		grade(d.ProxyServerNameserverPolicy[i].Servers, false)
	}
}

// Level is the column of the PRD R5 risk matrix.
type Level int

const (
	LevelSafe    Level = iota // all via proxy or safe
	LevelForeign              // worst is foreign / unknown encrypted
	LevelCN                   // worst is CN encrypted
	LevelPlain                // contains plain text
)

// Code returns a language-neutral code for the level.
func (l Level) Code() string {
	switch l {
	case LevelPlain:
		return "plain"
	case LevelCN:
		return "cn"
	case LevelForeign:
		return "foreign"
	default:
		return "safe"
	}
}

// LevelOf returns the matrix column of one server.
func LevelOf(s model.DNSServer) Level {
	switch s.Grade {
	case model.GradePlain:
		return LevelPlain
	case model.GradeEncrypted:
		if s.Region == model.RegionCN {
			return LevelCN
		}
		return LevelForeign
	default:
		return LevelSafe
	}
}

// ServerCode is a language-neutral code describing one server's grade,
// e.g. "plain", "enc-cn", "enc-foreign", "enc-unknown", "proxy", "safe".
func ServerCode(s model.DNSServer) string {
	switch s.Grade {
	case model.GradePlain:
		return "plain"
	case model.GradeEncrypted:
		switch s.Region {
		case model.RegionCN:
			return "enc-cn"
		case model.RegionForeign:
			return "enc-foreign"
		}
		return "enc-unknown"
	case model.GradeViaProxy:
		if s.ViaRules {
			return "rules"
		}
		return "proxy"
	default:
		return "safe"
	}
}

// Worst returns the worst level in servers and the servers at that level.
func Worst(servers []model.DNSServer) (Level, []model.DNSServer) {
	worst := LevelSafe
	for _, s := range servers {
		if l := LevelOf(s); l > worst {
			worst = l
		}
	}
	var culprits []model.DNSServer
	for _, s := range servers {
		if LevelOf(s) == worst {
			culprits = append(culprits, s)
		}
	}
	return worst, culprits
}

// Source tells where the selected servers come from.
type Source int

const (
	SourceSystem       Source = iota // dns disabled → system resolver
	SourcePolicy                     // nameserver-policy entry
	SourceFallbackOnly               // fallback-filter domain / geosite
	SourceDefault                    // nameserver ∪ fallback
)

// Code returns a language-neutral code.
func (s Source) Code() string {
	switch s {
	case SourceSystem:
		return "system"
	case SourcePolicy:
		return "policy"
	case SourceFallbackOnly:
		return "fallback-only"
	default:
		return "default"
	}
}

// Selection is the result of Select.
type Selection struct {
	Source    Source
	Servers   []model.DNSServer
	Policy    *model.PolicyEntry
	Subkey    string
	Uncertain []string // policy subkeys / filters whose match was unknown and assumed false
}

// SystemServer is the synthetic server used when mihomo DNS is disabled.
func SystemServer(d *model.DNSConfig) model.DNSServer {
	loc := d.Loc
	if d.Present && d.EnableLoc.Line > 0 {
		loc = d.EnableLoc
	}
	return model.DNSServer{Raw: "system", Scheme: "system", Grade: model.GradePlain, Loc: loc}
}

// DefaultServers returns nameserver ∪ fallback.
func DefaultServers(d *model.DNSConfig) []model.DNSServer {
	out := append([]model.DNSServer{}, d.Nameserver.Servers...)
	return append(out, d.Fallback.Servers...)
}

// Select returns the servers that receive a query for a domain during rule
// matching (research §2.1). policyMatch is called with each
// nameserver-policy subkey in order; filterMatch with ("domain", pattern) /
// ("geosite", name) of fallback-filter. Either may be nil, meaning "never
// matches" (used for the "unknown domain" case).
func Select(d *model.DNSConfig, policyMatch func(subkey string) model.Tri, filterMatch func(kind, value string) model.Tri) Selection {
	var sel Selection
	if !d.Enable {
		sel.Source = SourceSystem
		sel.Servers = []model.DNSServer{SystemServer(d)}
		return sel
	}
	if policyMatch != nil {
		for i := range d.NameserverPolicy {
			e := &d.NameserverPolicy[i]
			for _, sk := range e.Subkeys {
				switch policyMatch(sk) {
				case model.Yes:
					sel.Source, sel.Servers, sel.Policy, sel.Subkey = SourcePolicy, e.Servers, e, sk
					return sel
				case model.Unknown:
					sel.Uncertain = append(sel.Uncertain, sk)
				}
			}
		}
	}
	if filterMatch != nil && len(d.Fallback.Servers) > 0 {
		ff := d.FallbackFilter
		check := func(kind string, values []string) bool {
			for _, v := range values {
				switch filterMatch(kind, v) {
				case model.Yes:
					return true
				case model.Unknown:
					sel.Uncertain = append(sel.Uncertain, "fallback-filter."+kind+":"+v)
				}
			}
			return false
		}
		if check("domain", ff.Domain) || check("geosite", ff.Geosite) {
			sel.Source, sel.Servers = SourceFallbackOnly, d.Fallback.Servers
			return sel
		}
	}
	sel.Source = SourceDefault
	sel.Servers = DefaultServers(d)
	return sel
}

// IsPureIP reports whether a default-nameserver entry is acceptable to
// mihomo (research §5: an IP, possibly with an encrypted scheme, or system).
func IsPureIP(s model.DNSServer) bool {
	if s.Invalid {
		return false
	}
	if s.Scheme == "system" {
		return true
	}
	_, err := netip.ParseAddr(s.Host)
	return err == nil
}
