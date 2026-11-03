// Package ruleparse parses mihomo rule strings following
// rules/common/base.go ParseRulePayload and rules/logic/logic.go.
package ruleparse

import (
	"errors"
	"sort"
	"strings"

	"dnsleak/internal/model"
)

// knownTypes is the rule type set of rules/parser.go.
var knownTypes = map[string]bool{
	"DOMAIN": true, "DOMAIN-SUFFIX": true, "DOMAIN-KEYWORD": true, "DOMAIN-REGEX": true,
	"DOMAIN-WILDCARD": true, "GEOSITE": true, "GEOIP": true, "SRC-GEOIP": true,
	"IP-ASN": true, "SRC-IP-ASN": true, "IP-CIDR": true, "IP-CIDR6": true,
	"SRC-IP-CIDR": true, "IP-SUFFIX": true, "SRC-IP-SUFFIX": true, "SRC-PORT": true,
	"DST-PORT": true, "IN-PORT": true, "DSCP": true, "PROCESS-NAME": true,
	"PROCESS-PATH": true, "PROCESS-NAME-REGEX": true, "PROCESS-PATH-REGEX": true,
	"PROCESS-NAME-WILDCARD": true, "PROCESS-PATH-WILDCARD": true, "NETWORK": true,
	"UID": true, "IN-TYPE": true, "IN-USER": true, "IN-NAME": true, "REMATCH-NAME": true,
	"SUB-RULE": true, "AND": true, "OR": true, "NOT": true, "RULE-SET": true, "MATCH": true,
}

// IP rule types that call helper.ResolveIP() unless no-resolve / src.
var resolvingTypes = map[string]bool{
	"GEOIP": true, "IP-ASN": true, "IP-CIDR": true, "IP-CIDR6": true, "IP-SUFFIX": true,
}

// Types that only look at the destination host name.
var domainTypes = map[string]bool{
	"DOMAIN": true, "DOMAIN-SUFFIX": true, "DOMAIN-KEYWORD": true, "DOMAIN-REGEX": true,
	"DOMAIN-WILDCARD": true, "GEOSITE": true,
}

// IsResolvingIPType reports whether the rule type resolves the host when it
// is evaluated without no-resolve.
func IsResolvingIPType(tp string) bool { return resolvingTypes[tp] }

// IsDomainType reports whether the rule type matches on the host name only.
func IsDomainType(tp string) bool { return domainTypes[tp] }

// IsLogicType reports whether the rule is AND / OR / NOT / SUB-RULE.
func IsLogicType(tp string) bool {
	switch tp {
	case "AND", "OR", "NOT", "SUB-RULE":
		return true
	}
	return false
}

// Parse parses a rule line. needTarget is true for entries of rules /
// sub-rules and false for classical rule-set entries and logic sub-rules.
// Errors are recorded in Rule.Err; Parse never fails.
func Parse(raw string, needTarget bool) model.Rule {
	r := model.Rule{Raw: raw}
	items := strings.Split(raw, ",")
	for i := range items {
		items[i] = strings.Trim(items[i], " ")
	}
	r.Type = strings.ToUpper(items[0])
	if len(items) > 1 {
		switch r.Type {
		case "MATCH":
			r.Target = items[1]
		case "NOT", "OR", "AND", "SUB-RULE", "DOMAIN-REGEX", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX":
			if needTarget {
				l := len(items)
				r.Target = items[l-1]
				items = items[:l-1]
			}
			r.Payload = strings.Join(items[1:], ",")
		default:
			r.Payload = items[1]
			if len(items) > 2 {
				if needTarget {
					r.Target = items[2]
					if len(items) > 3 {
						r.Params = items[3:]
					}
				} else {
					r.Params = items[2:]
				}
			}
		}
	}

	switch {
	case r.Type == "":
		r.Err = "empty rule"
		return r
	case !knownTypes[r.Type]:
		r.Err = "unsupported rule type: " + r.Type
		return r
	case r.Type != "MATCH" && r.Payload == "":
		r.Err = "missing subsequent parameters: " + r.Type
		return r
	}

	r.Src = contains(r.Params, "src")
	r.NoResolve = r.Src || contains(r.Params, "no-resolve")
	if strings.HasPrefix(r.Type, "SRC-") {
		r.Src, r.NoResolve = true, true
	}

	var err error
	switch r.Type {
	case "AND", "OR", "NOT":
		r.Subs, err = parseLogicPayload(r.Payload)
		if err == nil && r.Type == "NOT" && len(r.Subs) != 1 {
			err = errors.New("not rule must contain one rule")
		}
	case "SUB-RULE":
		r.Subs, err = parseLogicPayload("(" + r.Payload + ")")
		if err == nil && len(r.Subs) != 1 {
			err = errors.New("sub-rule must contain one rule")
		}
	}
	if err != nil {
		r.Err = err.Error()
	}
	return r
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

type span struct{ start, end int }

// parseLogicPayload mirrors logic.parsePayload: the payload must be
// "(...)", top-level parenthesised groups become sub-rules.
func parseLogicPayload(payload string) ([]model.Rule, error) {
	if !strings.HasPrefix(payload, "(") || !strings.HasSuffix(payload, ")") {
		return nil, errors.New("payload format error")
	}
	var stack []int
	var all []span
	for i, c := range payload {
		switch c {
		case '(':
			stack = append(stack, i)
		case ')':
			if len(stack) == 0 {
				return nil, errors.New("missing '('")
			}
			start := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			all = append(all, span{start, i})
		}
	}
	if len(stack) != 0 {
		return nil, errors.New("missing ')'")
	}
	sort.Slice(all, func(i, j int) bool { return all[i].start < all[j].start })

	var top []span
	for _, rr := range all {
		if rr.start == 0 && rr.end == len(payload)-1 {
			continue
		}
		inside := false
		for _, t := range top {
			if t.start < rr.start && t.end > rr.end {
				inside = true
				break
			}
		}
		if !inside {
			top = append(top, rr)
		}
	}

	subs := make([]model.Rule, 0, len(top))
	for i, t := range top {
		sub := Parse(payload[t.start+1:t.end], false)
		switch sub.Type {
		case "MATCH", "SUB-RULE":
			return nil, errors.New("unsupported rule type on logic rule: " + sub.Type)
		}
		if sub.Err != "" {
			return nil, errors.New(sub.Err)
		}
		sub.Index = i
		subs = append(subs, sub)
	}
	return subs, nil
}

// ParseClassical parses a classical rule-set entry.
func ParseClassical(raw string) model.Rule {
	r := Parse(raw, false)
	switch r.Type {
	case "MATCH", "RULE-SET", "SUB-RULE":
		r.Err = "unsupported rule type on classical rule-set: " + r.Type
	}
	return r
}

// WithLoc sets loc on r and, recursively, on its logic sub-rules.
func WithLoc(r model.Rule, loc model.Location) model.Rule {
	r.Loc = loc
	for i := range r.Subs {
		r.Subs[i] = WithLoc(r.Subs[i], loc)
	}
	return r
}
