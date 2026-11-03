// Package trace simulates rule matching for one domain (design §10).
package trace

import (
	"strings"

	"dnsleak/internal/analyze"
	"dnsleak/internal/dnsserver"
	"dnsleak/internal/model"
	"dnsleak/internal/ruledata"
	"dnsleak/internal/ruleparse"
)

// Outcome of one step.
const (
	OutMatch    = "match"
	OutNoMatch  = "no-match"
	OutUnknown  = "unknown"
	OutAssumed  = "assumed-no-match" // IP / connection condition, assumed not to match
	OutPass     = "pass"             // matched, but the policy is PASS
	OutHostsHit = "hosts"
)

// Reason codes attached to steps (besides ruledata reason codes).
const (
	ReasonIPAssumed  = "ip-assumed"  // IP rule after resolution: result unknowable statically
	ReasonNoResolve  = "no-resolve"  // IP rule with no-resolve and no IP yet
	ReasonConnInfo   = "conn-info"   // depends on process / port / network ...
	ReasonRegex      = "regex"       // regex Go cannot compile
	ReasonDepthLimit = "depth-limit" // nesting too deep
)

// Resolution describes the local DNS query triggered during matching.
type Resolution struct {
	ViaHosts  bool
	Selection dnsserver.Selection
	Level     dnsserver.Level
}

// Step is one rule evaluation.
type Step struct {
	Depth      int // 0 for top-level rules, 1+ inside sub-rules
	Rule       model.Rule
	Outcome    string
	Reason     string // reason code for unknown / assumed outcomes
	Name       string // rule-set / geosite name the reason refers to
	DataFile   string // local file that was looked up, for unknown rule-sets
	Target     string
	Class      string // policy class code of Target when matched / unknown
	Resolution *Resolution
}

// Unknown is a step whose result could not be determined.
type Unknown struct {
	StepIndex int
	Rule      model.Rule
	Reason    string
	Name      string
	Class     string // class the rule would route to
}

// Verdict codes.
const (
	VerdictLeak           = "leak"            // resolved locally, then proxied
	VerdictRedundant      = "redundant"       // resolved via proxy / safe servers, then proxied
	VerdictProxy          = "proxy"           // proxied without local resolution
	VerdictDirect         = "direct"          // direct; resolution is expected
	VerdictReject         = "reject"          // rejected
	VerdictHostsProxy     = "hosts-proxy"     // hosts answered, no query, proxied
	VerdictResolvedDirect = "resolved-direct" // resolved during matching, then direct
)

// Result of a trace.
type Result struct {
	Domain      string
	Hosts       *model.HostEntry
	Steps       []Step
	Resolution  *Resolution
	FinalRule   *model.Rule // nil = no rule matched (mihomo uses DIRECT)
	FinalTarget string
	FinalClass  string
	Verdict     string
	Severity    model.Severity
	Uncertain   bool
	Unknowns    []Unknown
	// ResolutionStep is the index of the step that triggered resolution, or -1.
	ResolutionStep int
	// Impact tells how missing data affects the verdict (see impact codes).
	Impact string
	Notes  []model.Note
}

type tracer struct {
	env      *analyze.Env
	domain   string
	resolved bool
	res      *Resolution
	viaHosts bool
	assumed  map[string]bool
	subStack map[string]bool // sub-rules chains being walked
	steps    []Step
	unknowns []Unknown
}

// Run traces domain through the rules of env.
func Run(env *analyze.Env, domain string) *Result {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	t := &tracer{env: env, domain: domain, assumed: map[string]bool{}, subStack: map[string]bool{}}
	r := &Result{Domain: domain}

	for i := range env.Cfg.Hosts {
		h := &env.Cfg.Hosts[i]
		if ruledata.PatternMatch(h.Pattern, domain) {
			r.Hosts = h
			t.viaHosts = true
			break
		}
	}

	final, matched := t.walk(env.Cfg.Rules, 0)
	r.Steps, r.Unknowns, r.Resolution = t.steps, t.unknowns, t.res
	if matched {
		rr := final
		r.FinalRule = &rr
		r.FinalTarget = final.Target
	} else {
		r.FinalTarget = "DIRECT"
	}
	res := env.Pol.Classify(r.FinalTarget)
	r.FinalClass = res.Class.String()
	if res.Assumed {
		r.Notes = append(r.Notes, model.Note{Key: "group-assumed-proxy", Args: model.Args{"group": res.Group}})
	}
	r.Uncertain = len(r.Unknowns) > 0
	r.ResolutionStep = -1
	for i, s := range r.Steps {
		if s.Resolution != nil {
			r.ResolutionStep = i
			break
		}
	}
	r.Impact = impact(r)

	switch {
	case res.Class == model.PolicyReject:
		r.Verdict = VerdictReject
	case res.Class == model.PolicyProxy && t.resolved && !t.viaHosts:
		r.Severity = analyze.MatrixSeverity(analyze.RowResolved, t.res.Level)
		r.Verdict = VerdictLeak
		if t.res.Level == dnsserver.LevelSafe {
			r.Verdict = VerdictRedundant
		}
	case res.Class == model.PolicyProxy && t.viaHosts:
		r.Verdict = VerdictHostsProxy
	case res.Class == model.PolicyProxy:
		r.Verdict = VerdictProxy
	case t.resolved:
		r.Verdict = VerdictResolvedDirect
	default:
		r.Verdict = VerdictDirect
	}

	if t.assumed[ReasonIPAssumed] {
		r.Notes = append(r.Notes, model.Note{Key: "trace-ip-assumed"})
	}
	if t.assumed[ReasonConnInfo] {
		r.Notes = append(r.Notes, model.Note{Key: "trace-conn-assumed"})
	}
	if t.res != nil && len(t.res.Selection.Uncertain) > 0 {
		r.Notes = append(r.Notes, model.Note{Key: "trace-policy-uncertain", Args: model.Args{"keys": strings.Join(t.res.Selection.Uncertain, ", ")}})
	}
	if t.res != nil && !t.viaHosts && t.res.Selection.Source == dnsserver.SourceDefault && len(env.Cfg.DNS.Fallback.Servers) > 0 {
		r.Notes = append(r.Notes, model.Note{Key: "fallback-included", Args: model.Args{"lazy": boolStr(env.Cfg.DNS.FallbackLazyQuery)}})
	}
	r.Notes = append(r.Notes, model.Note{Key: "system-proxy-scope"})
	return r
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// walk evaluates a rule list; it returns the matched rule (non-PASS).
func (t *tracer) walk(rules []model.Rule, depth int) (model.Rule, bool) {
	if depth > 8 {
		return model.Rule{}, false
	}
	for _, r := range rules {
		wasResolved := t.resolved
		step := Step{Depth: depth, Rule: r, Target: r.Target}

		if r.Type == "SUB-RULE" && r.Err == "" && len(r.Subs) == 1 {
			tri, why, name := t.eval(r.Subs[0], false, 0)
			t.fill(&step, tri, why, name, wasResolved)
			step.Class = ""
			t.steps = append(t.steps, step)
			switch tri {
			case model.Yes:
				if t.subStack[r.Target] {
					// Circular sub-rules (mihomo refuses to load them): stop.
					continue
				}
				t.subStack[r.Target] = true
				final, ok := t.walk(t.env.Cfg.SubRules[r.Target], depth+1)
				delete(t.subStack, r.Target)
				if ok {
					return final, true
				}
			case model.Unknown:
				t.unknowns = append(t.unknowns, Unknown{StepIndex: len(t.steps) - 1, Rule: r, Reason: why, Name: name, Class: "sub-rule"})
			}
			continue
		}

		tri, why, name := t.eval(r, false, 0)
		t.fill(&step, tri, why, name, wasResolved)
		if tri == model.Unknown && r.Type == "RULE-SET" && name == r.Payload {
			step.DataFile = t.env.Store.Provider(name).Source
		}
		if tri == model.Yes || tri == model.Unknown {
			step.Class = t.env.Pol.Classify(r.Target).Class.String()
		}
		if tri == model.Yes && step.Class == model.PolicyPass.String() {
			step.Outcome = OutPass
		}
		t.steps = append(t.steps, step)
		switch {
		case step.Outcome == OutPass:
			continue
		case tri == model.Yes:
			return r, true
		case tri == model.Unknown:
			t.unknowns = append(t.unknowns, Unknown{StepIndex: len(t.steps) - 1, Rule: r, Reason: why, Name: name, Class: step.Class})
		}
	}
	return model.Rule{}, false
}

func (t *tracer) fill(step *Step, tri model.Tri, why, name string, wasResolved bool) {
	switch tri {
	case model.Yes:
		step.Outcome = OutMatch
	case model.Unknown:
		step.Outcome = OutUnknown
	default:
		step.Outcome = OutNoMatch
		if why == ReasonIPAssumed || why == ReasonConnInfo {
			step.Outcome = OutAssumed
		}
	}
	step.Reason, step.Name = why, name
	if t.resolved && !wasResolved {
		step.Resolution = t.res
	}
}

// resolve records the first local resolution (tunnel.go ResolveIP helper).
func (t *tracer) resolve() {
	if t.resolved {
		return
	}
	t.resolved = true
	if t.viaHosts {
		t.res = &Resolution{ViaHosts: true}
		return
	}
	sel := dnsserver.Select(&t.env.Cfg.DNS, t.policyMatch, t.filterMatch)
	level, _ := dnsserver.Worst(sel.Servers)
	t.res = &Resolution{Selection: sel, Level: level}
}

func (t *tracer) policyMatch(sk string) model.Tri {
	lower := strings.ToLower(sk)
	switch {
	case strings.HasPrefix(lower, "geosite:"):
		tri, _ := t.env.Store.MatchGeoSite(sk[len("geosite:"):], t.domain)
		return tri
	case strings.HasPrefix(lower, "rule-set:"):
		return t.env.Store.Provider(sk[len("rule-set:"):]).MatchDomain(t.domain)
	}
	if ruledata.PatternMatch(sk, t.domain) {
		return model.Yes
	}
	return model.No
}

func (t *tracer) filterMatch(kind, value string) model.Tri {
	if kind == "geosite" {
		tri, _ := t.env.Store.MatchGeoSite(value, t.domain)
		return tri
	}
	if ruledata.PatternMatch(value, t.domain) {
		return model.Yes
	}
	return model.No
}

// eval evaluates one rule for the domain. It returns the result, a reason
// code for Unknown / assumed results, and the rule-set / geosite name the
// reason refers to.
func (t *tracer) eval(r model.Rule, noResolve bool, depth int) (model.Tri, string, string) {
	if r.Err != "" {
		return model.No, "", ""
	}
	if depth > 16 {
		return model.Unknown, ReasonDepthLimit, ""
	}
	noResolve = noResolve || r.NoResolve
	switch {
	case r.Type == "MATCH":
		return model.Yes, "", ""
	case r.Type == "GEOSITE":
		tri, why := t.env.Store.MatchGeoSite(r.Payload, t.domain)
		return tri, why, r.Payload
	case ruleparse.IsDomainType(r.Type):
		tri := ruledata.MatchDomainRule(r, t.domain)
		if tri == model.Unknown {
			return tri, ReasonRegex, ""
		}
		return tri, "", ""
	case ruleparse.IsResolvingIPType(r.Type):
		return t.ipRule(noResolve || r.Src)
	case r.Type == "RULE-SET":
		return t.ruleSet(r, noResolve, depth)
	case r.Type == "AND":
		for _, s := range r.Subs {
			tri, why, name := t.eval(s, noResolve, depth+1)
			if tri != model.Yes {
				return tri, why, name
			}
		}
		return model.Yes, "", ""
	case r.Type == "OR":
		var lastWhy string
		for _, s := range r.Subs {
			tri, why, name := t.eval(s, noResolve, depth+1)
			if tri != model.No {
				return tri, why, name
			}
			if why != "" {
				lastWhy = why
			}
		}
		return model.No, lastWhy, ""
	case r.Type == "NOT":
		if len(r.Subs) != 1 {
			return model.No, "", ""
		}
		tri, why, name := t.eval(r.Subs[0], noResolve, depth+1)
		switch tri {
		case model.Yes:
			return model.No, why, name
		case model.No:
			if why == ReasonIPAssumed || why == ReasonConnInfo {
				return model.Unknown, why, name
			}
			return model.Yes, why, name
		}
		return tri, why, name
	default:
		// SRC-*, PROCESS-*, ports, NETWORK, IN-*, UID, DSCP, ...: they depend
		// on connection information a domain alone does not have.
		t.assumed[ReasonConnInfo] = true
		return model.No, ReasonConnInfo, ""
	}
}

func (t *tracer) ipRule(noResolve bool) (model.Tri, string, string) {
	if !noResolve {
		t.resolve()
	}
	if t.resolved || t.viaHosts {
		// An IP is available but its value is unknown statically.
		t.assumed[ReasonIPAssumed] = true
		return model.No, ReasonIPAssumed, ""
	}
	return model.No, ReasonNoResolve, ""
}

func (t *tracer) ruleSet(r model.Rule, noResolve bool, depth int) (model.Tri, string, string) {
	p := t.env.Store.Provider(r.Payload)
	if p.Def == nil {
		return model.Unknown, p.Reason, r.Payload
	}
	switch p.Def.Behavior {
	case "ipcidr":
		tri, why, _ := t.ipRule(noResolve)
		return tri, why, r.Payload
	case "domain":
		if !p.Loaded {
			return model.Unknown, p.Reason, r.Payload
		}
		if p.Domains.Has(t.domain) {
			return model.Yes, "", r.Payload
		}
		return model.No, "", r.Payload
	case "classical":
		if !p.Loaded {
			return model.Unknown, p.Reason, r.Payload
		}
		var lastWhy string
		for _, entry := range p.Rules {
			tri, why, name := t.eval(entry, noResolve, depth+1)
			if tri != model.No {
				if name == "" {
					name = r.Payload
				}
				return tri, why, name
			}
			if why != "" {
				lastWhy = why
			}
		}
		return model.No, lastWhy, r.Payload
	}
	return model.Unknown, p.Reason, r.Payload
}

// Impact codes.
const (
	ImpactBeforeResolution = "before-resolution"
	ImpactSameClass        = "same-class"
	ImpactMayDiffer        = "may-differ"
	ImpactNoResolution     = "no-resolution"
)

func impact(r *Result) string {
	if len(r.Unknowns) == 0 {
		return ""
	}
	if r.ResolutionStep < 0 {
		return ImpactNoResolution
	}
	same := true
	for _, u := range r.Unknowns {
		if u.StepIndex < r.ResolutionStep {
			return ImpactBeforeResolution
		}
		if u.Class != r.FinalClass {
			same = false
		}
	}
	if same {
		return ImpactSameClass
	}
	return ImpactMayDiffer
}
