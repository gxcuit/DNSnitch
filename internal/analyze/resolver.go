package analyze

import (
	"strings"

	"dnsleak/internal/dnsserver"
	"dnsleak/internal/model"
	"dnsleak/internal/ruledata"
)

// probeLabel is prepended to a DOMAIN-SUFFIX payload to test whether a
// domain pattern covers its subdomains as well.
const probeLabel = "dnsleak-probe."

// coversRule reports whether a domain pattern (nameserver-policy /
// fallback-filter key) statically covers every domain of a DOMAIN /
// DOMAIN-SUFFIX rule.
func coversRule(pattern string, r model.Rule) bool {
	switch r.Type {
	case "DOMAIN":
		return ruledata.PatternMatch(pattern, r.Payload)
	case "DOMAIN-SUFFIX":
		return ruledata.PatternMatch(pattern, r.Payload) && ruledata.PatternMatch(pattern, probeLabel+r.Payload)
	}
	return false
}

// staticPolicyMatch maps a nameserver-policy subkey to a rule by name
// (design §9.3 step 2): geosite:x ↔ GEOSITE,x; rule-set:x ↔ RULE-SET,x;
// domain pattern ↔ DOMAIN / DOMAIN-SUFFIX it covers.
func staticPolicyMatch(r model.Rule) func(string) model.Tri {
	return func(sk string) model.Tri {
		lower := strings.ToLower(sk)
		switch {
		case strings.HasPrefix(lower, "geosite:"):
			if r.Type == "GEOSITE" && strings.EqualFold(sk[len("geosite:"):], r.Payload) {
				return model.Yes
			}
		case strings.HasPrefix(lower, "rule-set:"):
			if r.Type == "RULE-SET" && sk[len("rule-set:"):] == r.Payload {
				return model.Yes
			}
		default:
			if coversRule(sk, r) {
				return model.Yes
			}
		}
		return model.No
	}
}

func staticFilterMatch(r model.Rule) func(kind, value string) model.Tri {
	return func(kind, value string) model.Tri {
		switch kind {
		case "geosite":
			if r.Type == "GEOSITE" && strings.EqualFold(value, r.Payload) {
				return model.Yes
			}
		case "domain":
			if coversRule(value, r) {
				return model.Yes
			}
		}
		return model.No
	}
}

// selectForRule returns the resolver servers for the domains of a rule.
func (e *Env) selectForRule(r model.Rule) dnsserver.Selection {
	return dnsserver.Select(&e.Cfg.DNS, staticPolicyMatch(r), staticFilterMatch(r))
}

// selectForUnknown returns the resolver for domains no rule covers
// (design §9.3 step 4).
func (e *Env) selectForUnknown() dnsserver.Selection {
	return dnsserver.Select(&e.Cfg.DNS, nil, nil)
}
