package ruledata

import (
	"regexp"
	"strings"
	"sync"

	"github.com/metacubex/mihomo/component/trie"

	"dnsnitch/internal/model"
)

// MatchDomainRule evaluates a host-name rule (DOMAIN, DOMAIN-SUFFIX,
// DOMAIN-KEYWORD, DOMAIN-REGEX, DOMAIN-WILDCARD) against domain with the
// semantics of rules/common. GEOSITE is handled by Store.MatchGeoSite.
func MatchDomainRule(r model.Rule, domain string) model.Tri {
	domain = strings.ToLower(domain)
	p := strings.ToLower(r.Payload)
	var ok bool
	switch r.Type {
	case "DOMAIN":
		ok = domain == p
	case "DOMAIN-SUFFIX":
		ok = domain == p || strings.HasSuffix(domain, "."+p)
	case "DOMAIN-KEYWORD":
		ok = strings.Contains(domain, p)
	case "DOMAIN-WILDCARD":
		ok = wildcardMatch(p, domain)
	case "DOMAIN-REGEX":
		// mihomo uses regexp2 (.NET syntax); patterns Go cannot compile
		// are reported as unknown.
		re, err := compileRegex(r.Payload)
		if err != nil {
			return model.Unknown
		}
		ok = re.MatchString(domain)
	default:
		return model.Unknown
	}
	if ok {
		return model.Yes
	}
	return model.No
}

var regexCache sync.Map

func compileRegex(s string) (*regexp.Regexp, error) {
	if v, ok := regexCache.Load(s); ok {
		return v.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(s)
	if err != nil {
		return nil, err
	}
	regexCache.Store(s, re)
	return re, nil
}

// wildcardMatch implements component/wildcard.Match: '*' matches any
// sequence, '?' any single byte.
func wildcardMatch(pattern, s string) bool {
	if pattern == "" {
		return s == ""
	}
	pi, si, star, mark := 0, 0, -1, 0
	for si < len(s) {
		switch {
		case pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == s[si]):
			pi++
			si++
		case pi < len(pattern) && pattern[pi] == '*':
			star, mark = pi, si
			pi++
		case star != -1:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

var patternCache sync.Map

// PatternMatch matches a Clash domain pattern ("+.a.com", ".a.com",
// "*.a.com", "a.com") as used by hosts, nameserver-policy and
// fallback-filter keys, reusing mihomo's trie semantics.
func PatternMatch(pattern, domain string) bool {
	var set *trie.DomainSet
	if v, ok := patternCache.Load(pattern); ok {
		set = v.(*trie.DomainSet)
	} else {
		var b trie.DomainSetBuilder
		if b.Insert(pattern) != nil {
			return false
		}
		set = b.Build()
		patternCache.Store(pattern, set)
	}
	return set.Has(strings.ToLower(domain))
}
