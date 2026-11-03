package analyze

import (
	"strings"

	"dnsleak/internal/model"
	"dnsleak/internal/ruleparse"
)

// Kind of resolution trigger (design §9.1).
type Kind int

const (
	KindNone        Kind = iota
	KindAlways           // every domain reaching the rule (minus Except) is resolved
	KindConditional      // only domains satisfying Guard are resolved
	KindUnknown          // rule-set content unavailable
)

// Trigger describes whether evaluating a rule resolves the host.
type Trigger struct {
	Kind Kind
	// Point is the innermost rule that calls ResolveIP (an IP rule or an
	// ipcidr RULE-SET); nil for KindNone / KindUnknown.
	Point *model.Rule
	// Set is the classical rule-set containing Point, if any.
	Set string
	// Except are entries evaluated before Point whose match returns early
	// (classical rule-set / OR).
	Except []model.Rule
	// After are host-name entries after Point in the same classical set /
	// OR rule: they are only reached after resolution.
	After []model.Rule
	// Guard are AND sub-rules that must match before Point is evaluated.
	Guard []model.Rule
	// UnknownSet / UnknownReason describe a KindUnknown result.
	UnknownSet    string
	UnknownReason string
}

const maxDepth = 16

// TriggerOf classifies a top-level rule.
func (e *Env) TriggerOf(r model.Rule) Trigger {
	return e.trigger(r, false, 0)
}

func (e *Env) trigger(r model.Rule, inheritedNoResolve bool, depth int) Trigger {
	if r.Err != "" || depth > maxDepth {
		return Trigger{}
	}
	noResolve := r.NoResolve || inheritedNoResolve
	switch {
	case ruleparse.IsResolvingIPType(r.Type):
		if noResolve {
			return Trigger{}
		}
		rr := r
		return Trigger{Kind: KindAlways, Point: &rr}
	case r.Type == "RULE-SET":
		return e.ruleSetTrigger(r, noResolve, depth)
	case r.Type == "AND":
		return e.andTrigger(r.Subs, noResolve, depth)
	case r.Type == "OR":
		return e.seqTrigger(r.Subs, noResolve, depth)
	case r.Type == "NOT":
		if len(r.Subs) == 1 {
			return e.trigger(r.Subs[0], noResolve, depth+1)
		}
	case r.Type == "SUB-RULE":
		if len(r.Subs) != 1 {
			return Trigger{}
		}
		if t := e.trigger(r.Subs[0], noResolve, depth+1); t.Kind != KindNone {
			return t
		}
		// Only hosts satisfying the condition enter the sub-rule chain; a
		// trigger there resolves them before they may fall back to the
		// main chain (logic.go matchSubRules returns false when nothing in
		// the chain matches).
		t := e.chainTrigger(r.Target, depth+1)
		switch t.Kind {
		case KindAlways, KindConditional:
			t.Kind = KindConditional
			t.Guard = append([]model.Rule{r.Subs[0]}, t.Guard...)
			return t
		case KindUnknown:
			return t
		}
	}
	return Trigger{}
}

// chainTrigger returns the first non-None trigger of the named sub-rules
// chain; rules after MATCH are unreachable. Results are memoized, and
// circular references (rejected by mihomo at load time) are cut so that
// a broken config cannot make the analysis loop or explode.
func (e *Env) chainTrigger(name string, depth int) Trigger {
	if t, ok := e.subTrig[name]; ok {
		return t
	}
	if e.subBusy[name] {
		return Trigger{}
	}
	e.subBusy[name] = true
	defer delete(e.subBusy, name)
	var res Trigger
	for _, sr := range e.Cfg.SubRules[name] {
		if sr.Type == "MATCH" {
			break
		}
		if t := e.trigger(sr, false, depth); t.Kind != KindNone {
			res = t
			break
		}
	}
	e.subTrig[name] = res
	return res
}

func (e *Env) ruleSetTrigger(r model.Rule, noResolve bool, depth int) Trigger {
	if noResolve {
		// rule_set.go: no-resolve / src clears ResolveIP for the whole set.
		return Trigger{}
	}
	p := e.Store.Provider(r.Payload)
	if p.Def == nil {
		return Trigger{Kind: KindUnknown, UnknownSet: r.Payload, UnknownReason: p.Reason}
	}
	switch p.Def.Behavior {
	case "ipcidr":
		rr := r
		return Trigger{Kind: KindAlways, Point: &rr}
	case "domain":
		return Trigger{}
	case "classical":
		if !p.Loaded {
			return Trigger{Kind: KindUnknown, UnknownSet: r.Payload, UnknownReason: p.Reason}
		}
		t := e.seqTrigger(p.Rules, false, depth+1)
		if t.Kind == KindAlways || t.Kind == KindConditional {
			if t.Set == "" {
				t.Set = r.Payload
			}
		}
		return t
	}
	return Trigger{Kind: KindUnknown, UnknownSet: r.Payload, UnknownReason: p.Reason}
}

// seqTrigger handles classical rule-sets and OR: entries are evaluated in
// order and the first match returns.
func (e *Env) seqTrigger(items []model.Rule, noResolve bool, depth int) Trigger {
	var except []model.Rule
	var first *Trigger
	for i, it := range items {
		t := e.trigger(it, noResolve, depth+1)
		switch t.Kind {
		case KindNone:
			except = append(except, it)
		case KindAlways:
			t.Except = append(append([]model.Rule{}, except...), t.Except...)
			for _, after := range items[i+1:] {
				if e.IsHostRule(after) {
					t.After = append(t.After, after)
				}
			}
			return t
		default:
			if first == nil {
				tt := t
				first = &tt
			}
			except = append(except, it)
		}
	}
	if first != nil {
		return *first
	}
	return Trigger{}
}

// andTrigger handles AND: evaluation stops at the first non-matching
// sub-rule, so sub-rules before the trigger point act as a guard.
func (e *Env) andTrigger(items []model.Rule, noResolve bool, depth int) Trigger {
	var guard []model.Rule
	for _, it := range items {
		t := e.trigger(it, noResolve, depth+1)
		switch t.Kind {
		case KindNone:
			guard = append(guard, it)
		case KindAlways:
			if len(guard) == 0 {
				return t
			}
			t.Kind = KindConditional
			t.Guard = guard
			return t
		case KindConditional:
			t.Guard = append(append([]model.Rule{}, guard...), t.Guard...)
			return t
		default:
			return t
		}
	}
	return Trigger{}
}

// IsHostRule reports whether a rule matches on the host name only:
// DOMAIN*, GEOSITE, domain / classical RULE-SET, or a logic rule made only
// of such rules (design §9.2 step 2).
func (e *Env) IsHostRule(r model.Rule) bool {
	return e.isHostRule(r, 0)
}

func (e *Env) isHostRule(r model.Rule, depth int) bool {
	if r.Err != "" || depth > maxDepth {
		return false
	}
	switch {
	case ruleparse.IsDomainType(r.Type):
		return true
	case r.Type == "RULE-SET":
		p := e.Store.Provider(r.Payload)
		if p.Def == nil {
			return false
		}
		switch p.Def.Behavior {
		case "domain":
			return true
		case "classical":
			if !p.Loaded {
				return true // content unknown: assume it holds domains
			}
			for _, sr := range p.Rules {
				if e.isHostRule(sr, depth+1) {
					return true
				}
			}
		}
		return false
	case r.Type == "AND" || r.Type == "OR" || r.Type == "NOT":
		if len(r.Subs) == 0 {
			return false
		}
		for _, s := range r.Subs {
			if !e.isHostRule(s, depth+1) {
				return false
			}
		}
		return true
	}
	return false
}

// shapeID returns the finding ID family for a trigger rule.
func (e *Env) shapeID(r model.Rule) string {
	switch {
	case ruleparse.IsLogicType(r.Type):
		return "RULE-04"
	case r.Type == "RULE-SET":
		if p := e.Store.Provider(r.Payload); p.Def != nil && p.Def.Behavior == "classical" {
			return "RULE-03"
		}
	}
	return ""
}

func rawList(rules []model.Rule, max int) string {
	var parts []string
	for i, r := range rules {
		if i == max {
			parts = append(parts, "…")
			break
		}
		parts = append(parts, r.Raw)
	}
	return strings.Join(parts, " | ")
}
