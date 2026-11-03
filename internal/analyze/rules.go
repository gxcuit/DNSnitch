package analyze

import (
	"sort"
	"strconv"
	"strings"

	"dnsleak/internal/dnsserver"
	"dnsleak/internal/model"
	"dnsleak/internal/ruledata"
)

// affected is a set of domains that gets resolved and then proxied.
type affected struct {
	loc   model.Location
	row   Row
	sel   dnsserver.Selection
	level dnsserver.Level
	sev   model.Severity
	group string // group carrying the D7 assumption, if any
}

func (e *Env) newAffected(loc model.Location, row Row, sel dnsserver.Selection, group string) affected {
	level, _ := dnsserver.Worst(sel.Servers)
	loc = loc.WithRole(model.RoleAffected)
	loc.Resolver = e.resolverInfo(sel)
	return affected{loc: loc, row: row, sel: sel, level: level, sev: MatrixSeverity(row, level), group: group}
}

// resolverInfo summarizes a selection for an affected location.
func (e *Env) resolverInfo(sel dnsserver.Selection) *model.ResolverInfo {
	level, _ := dnsserver.Worst(sel.Servers)
	ri := &model.ResolverInfo{Level: level.Code()}
	switch sel.Source {
	case dnsserver.SourceSystem:
		ri.Source = model.ResolverSystem
	case dnsserver.SourcePolicy:
		ri.Source, ri.PolicyKey = model.ResolverPolicy, sel.Subkey
	case dnsserver.SourceFallbackOnly:
		ri.Source = model.ResolverFallback
	default:
		ri.Source = model.ResolverNameserver
		if len(e.Cfg.DNS.Fallback.Servers) > 0 {
			ri.Source = model.ResolverNameserverFallback
		}
	}
	return ri
}

// proxyTarget reports whether target is classified as proxy, and the group
// carrying the D7 assumption.
func (e *Env) proxyTarget(target string) (bool, string) {
	res := e.Pol.Classify(target)
	if !res.Exists || res.Class != model.PolicyProxy {
		return false, ""
	}
	if res.Assumed {
		return true, res.Group
	}
	return true, ""
}

// downstream collects, from index from of a rule chain on, the host rules
// whose target is proxy (row RULE-01) and the MATCH that ends the chain.
// SUB-RULE entries contribute what happens inside their chain: a host
// that is already resolved stays resolved there.
func (e *Env) downstream(rules []model.Rule, from int) (items []affected, match *model.Rule) {
	for j := from; j < len(rules); j++ {
		r := rules[j]
		if r.Type == "MATCH" {
			rr := r
			match = &rr
			break
		}
		if r.Err != "" {
			continue
		}
		if r.Type == "SUB-RULE" {
			items = append(items, e.subDownstream(r, map[string]bool{})...)
			continue
		}
		if !e.IsHostRule(r) {
			continue
		}
		if ok, group := e.proxyTarget(r.Target); ok {
			items = append(items, e.newAffected(r.Loc, RowResolved, e.selectForRule(r), group))
		}
	}
	return items, match
}

// subDownstream lists what happens to an already-resolved host inside the
// chain of SUB-RULE sr: proxied host rules (row RULE-01) and a proxied
// MATCH (row RULE-01 when the SUB-RULE condition is itself a host rule,
// otherwise row RULE-02).
func (e *Env) subDownstream(sr model.Rule, seen map[string]bool) []affected {
	name := sr.Target
	if seen[name] {
		return nil
	}
	seen[name] = true
	var items []affected
	for _, r := range e.Cfg.SubRules[name] {
		if r.Err != "" {
			continue
		}
		switch {
		case r.Type == "MATCH":
			if ok, group := e.proxyTarget(r.Target); ok {
				row, sel := RowUnknown, e.selectForUnknown()
				if len(sr.Subs) == 1 && e.IsHostRule(sr.Subs[0]) {
					row, sel = RowResolved, e.selectForRule(sr.Subs[0])
				}
				items = append(items, e.newAffected(r.Loc, row, sel, group))
			}
			return items
		case r.Type == "SUB-RULE":
			items = append(items, e.subDownstream(r, seen)...)
		case e.IsHostRule(r):
			if ok, group := e.proxyTarget(r.Target); ok {
				items = append(items, e.newAffected(r.Loc, RowResolved, e.selectForRule(r), group))
			}
		}
	}
	return items
}

func (e *Env) matchItem(match *model.Rule, row Row) (affected, bool) {
	if match == nil {
		return affected{}, false
	}
	ok, group := e.proxyTarget(match.Target)
	if !ok {
		return affected{}, false
	}
	return e.newAffected(match.Loc, row, e.selectForUnknown(), group), true
}

func (e *Env) checkRules() []model.Finding {
	out, iT := e.scanChain(e.Cfg.Rules)

	// sub-rules chains entered before the host has been resolved are
	// scanned as independent chains (design §9.1); chains entered after
	// the trigger are covered by downstream.
	seen := map[string]bool{}
	var queue []string
	enqueue := func(rules []model.Rule, upto int) {
		for i, r := range rules {
			if r.Type == "MATCH" || (upto >= 0 && i >= upto) {
				break
			}
			if r.Type == "SUB-RULE" && r.Err == "" && !seen[r.Target] {
				seen[r.Target] = true
				queue = append(queue, r.Target)
			}
		}
	}
	enqueue(e.Cfg.Rules, iT)
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		fs, j := e.scanChain(e.Cfg.SubRules[name])
		out = append(out, fs...)
		enqueue(e.Cfg.SubRules[name], j)
	}
	out = dedupeUnknown(out)

	out = append(out, e.rule05(iT)...)
	out = append(out, e.rule06()...)
	return out
}

// scanChain scans one rule chain (design §9.2) up to its first Always
// trigger and returns that trigger's index (-1 if there is none).
func (e *Env) scanChain(rules []model.Rule) ([]model.Finding, int) {
	var out []model.Finding
	for i, r := range rules {
		if r.Type == "MATCH" {
			break
		}
		t := e.TriggerOf(r)
		switch t.Kind {
		case KindAlways:
			out = append(out, e.alwaysFinding(rules, i, t)...)
			return out, i
		case KindConditional:
			out = append(out, e.conditionalFinding(rules, i, t)...)
		case KindUnknown:
			out = append(out, e.unknownFinding(r, t)...)
		}
	}
	return out, -1
}

// dedupeUnknown keeps one "content unknown" finding per rule-set: the same
// set can be reached through a SUB-RULE and again inside its chain.
func dedupeUnknown(fs []model.Finding) []model.Finding {
	seen := map[string]bool{}
	var out []model.Finding
	for _, f := range fs {
		if f.Args["kind"] == "unknown" {
			if seen[f.Args["set"]] {
				continue
			}
			seen[f.Args["set"]] = true
		}
		out = append(out, f)
	}
	return out
}

// pointLoc returns the location of the trigger point inside a rule-set /
// logic rule.
func pointLoc(t Trigger) model.Location {
	loc := t.Point.Loc
	loc.Text = t.Point.Raw
	return loc.WithRole(model.RoleTriggerEntry)
}

func (e *Env) alwaysFinding(rules []model.Rule, i int, t Trigger) []model.Finding {
	T := rules[i]
	var items []affected
	if T.Type == "SUB-RULE" {
		// The condition resolved the host before it enters the chain.
		items = e.subDownstream(T, map[string]bool{})
	}
	more, match := e.downstream(rules, i+1)
	items = append(items, more...)
	nRules, unknownRaw := 0, ""
	for _, it := range items {
		if it.row == RowResolved {
			nRules++
		} else if unknownRaw == "" {
			unknownRaw = it.loc.Text
		}
	}

	// Host entries after the trigger point inside T itself.
	selfAfter := false
	if ok, group := e.proxyTarget(T.Target); ok && len(t.After) > 0 {
		items = append(items, e.newAffected(T.Loc, RowResolved, e.selectForRule(T), group))
		selfAfter = true
	}
	if it, ok := e.matchItem(match, RowUnknown); ok {
		items = append(items, it)
		unknownRaw = match.Raw
	}
	hasUnknown := unknownRaw != ""
	if len(items) == 0 {
		return nil
	}

	id := e.shapeID(T)
	if id == "" {
		id = "RULE-02"
		if nRules > 0 || selfAfter {
			id = "RULE-01"
		}
	}
	scope := "rules"
	switch {
	case hasUnknown && (nRules > 0 || selfAfter):
		scope = "both"
	case hasUnknown:
		scope = "unknown"
	}

	worst := worstItem(items)
	f := model.Finding{
		ID:       id,
		Severity: worst.sev,
		Args: model.Args{
			"kind":    "always",
			"scope":   scope,
			"trigger": T.Raw,
			"count":   strconv.Itoa(nRules),
			"level":   worst.level.Code(),
			"source":  worst.sel.Source.Code(),
			"mixed":   strconv.FormatBool(mixedLevels(items)),
		},
	}
	if unknownRaw != "" {
		f.Args["match"] = unknownRaw
	}
	f.Locations = append(f.Locations, T.Loc.WithRole(model.RoleTrigger))
	if id == "RULE-03" || id == "RULE-04" {
		f.Args["entry"] = t.Point.Raw
		f.Args["set"] = t.Set
		f.Locations = append(f.Locations, pointLoc(t))
	}
	for _, it := range items {
		f.Locations = append(f.Locations, it.loc)
	}
	sels := make([]dnsserver.Selection, 0, len(items))
	for _, it := range items {
		sels = append(sels, it.sel)
	}
	f.Locations = append(f.Locations, resolverLocs(sels...)...)

	if len(t.Except) > 0 {
		key := "or-except"
		if t.Set != "" {
			key = "classical-except"
		}
		f.Notes = append(f.Notes, model.Note{Key: key, Args: model.Args{
			"set": t.Set, "count": strconv.Itoa(len(t.Except)), "entries": rawList(t.Except, 3),
		}})
	}
	if selfAfter {
		f.Notes = append(f.Notes, model.Note{Key: "after-entries", Args: model.Args{
			"count": strconv.Itoa(len(t.After)), "entries": rawList(t.After, 3),
		}})
	}
	f.Notes = append(f.Notes, e.commonNotes(items)...)
	return []model.Finding{f}
}

func (e *Env) conditionalFinding(rules []model.Rule, i int, t Trigger) []model.Finding {
	r := rules[i]
	items, match := e.downstream(rules, i+1)
	if ok, group := e.proxyTarget(r.Target); ok {
		items = append(items, e.newAffected(r.Loc, RowUnknown, e.selectForUnknown(), group))
	}
	if it, ok := e.matchItem(match, RowUnknown); ok {
		items = append(items, it)
	}
	if len(items) == 0 {
		return nil
	}
	// Domains satisfying the guard are resolved; whether they end up
	// proxied is unknown, so the RULE-02 row applies (PRD R5).
	sel := e.selectForUnknown()
	for _, g := range t.Guard {
		if e.IsHostRule(g) {
			sel = e.selectForRule(g)
			break
		}
	}
	// Only domains satisfying the guard are resolved here, so the guard's
	// resolver is the one every affected location sees.
	guardInfo := e.resolverInfo(sel)
	for i := range items {
		items[i].loc.Resolver = guardInfo
	}
	level, _ := dnsserver.Worst(sel.Servers)
	id := e.shapeID(r)
	if id == "" {
		id = "RULE-04"
	}
	f := model.Finding{
		ID:       id,
		Severity: MatrixSeverity(RowUnknown, level),
		Args: model.Args{
			"kind":    "conditional",
			"trigger": r.Raw,
			"entry":   t.Point.Raw,
			"set":     t.Set,
			"guard":   rawList(t.Guard, 3),
			"level":   level.Code(),
			"source":  sel.Source.Code(),
		},
	}
	f.Locations = append(f.Locations, r.Loc.WithRole(model.RoleTrigger), pointLoc(t))
	for _, it := range items {
		f.Locations = append(f.Locations, it.loc)
	}
	f.Locations = append(f.Locations, resolverLocs(sel)...)
	guardKey := "and-guard"
	if r.Type == "SUB-RULE" {
		guardKey = "sub-rule-guard"
	}
	f.Notes = append(f.Notes, model.Note{Key: guardKey, Args: model.Args{"guard": rawList(t.Guard, 3), "sub": r.Target}})
	f.Notes = append(f.Notes, e.commonNotes(items)...)
	return []model.Finding{f}
}

func (e *Env) unknownFinding(r model.Rule, t Trigger) []model.Finding {
	if t.UnknownReason == ruledata.ReasonNotDefined {
		return nil // reported as CFG-03
	}
	id := e.shapeID(r)
	if id == "" {
		id = "RULE-03"
	}
	f := model.Finding{
		ID:       id,
		Severity: model.Info,
		Args: model.Args{
			"kind":    "unknown",
			"trigger": r.Raw,
			"set":     t.UnknownSet,
			"reason":  t.UnknownReason,
		},
		Locations: []model.Location{r.Loc.WithRole(model.RoleTrigger)},
	}
	if p := e.Store.Provider(t.UnknownSet); p.Def != nil {
		f.Locations = append(f.Locations, p.Def.Loc.WithRole(model.RoleRelated))
		if p.Source != "" {
			f.Args["file"] = p.Source
		}
	}
	return []model.Finding{f}
}

// rule05 flags GEOIP,<not lan>,...,no-resolve used as the fallback after
// all host rules while nothing earlier has resolved the host.
func (e *Env) rule05(iT int) []model.Finding {
	var out []model.Finding
	rules := e.Cfg.Rules
	for i, r := range rules {
		if r.Type == "MATCH" || (iT >= 0 && i > iT) {
			break
		}
		if r.Type != "GEOIP" || !r.NoResolve || r.Src || r.Err != "" {
			continue
		}
		switch strings.ToLower(r.Payload) {
		case "lan", "private":
			continue
		}
		hostAfter := false
		for _, later := range rules[i+1:] {
			if later.Type == "MATCH" {
				break
			}
			if e.IsHostRule(later) {
				hostAfter = true
				break
			}
		}
		if hostAfter {
			continue
		}
		out = append(out, model.Finding{
			ID:        "RULE-05",
			Severity:  model.Info,
			Args:      model.Args{"rule": r.Raw, "country": r.Payload},
			Locations: []model.Location{r.Loc.WithRole(model.RoleConfig)},
		})
	}
	return out
}

// rule06 flags a direct final fallback (whitelist mode).
func (e *Env) rule06() []model.Finding {
	for _, r := range e.Cfg.Rules {
		if r.Type != "MATCH" {
			continue
		}
		res := e.Pol.Classify(r.Target)
		if !res.Exists || res.Class != model.PolicyDirect {
			return nil
		}
		return []model.Finding{{
			ID: "RULE-06", Severity: model.Info,
			Args:      model.Args{"kind": "match", "rule": r.Raw},
			Locations: []model.Location{r.Loc.WithRole(model.RoleConfig)},
		}}
	}
	loc := e.Cfg.RulesLoc
	if loc.Line == 0 {
		loc = model.Location{File: e.Cfg.File, Path: "rules"}
	}
	return []model.Finding{{
		ID: "RULE-06", Severity: model.Info,
		Args:      model.Args{"kind": "default"},
		Locations: []model.Location{loc.WithRole(model.RoleConfig)},
	}}
}

func worstItem(items []affected) affected {
	w := items[0]
	for _, it := range items[1:] {
		if it.sev > w.sev {
			w = it
		}
	}
	return w
}

// resolverLocs lists, for every distinct selection, the servers that
// determine its level. Selections are ordered worst first; duplicate
// servers are listed once.
func resolverLocs(sels ...dnsserver.Selection) []model.Location {
	type graded struct {
		level    dnsserver.Level
		culprits []model.DNSServer
	}
	var groups []graded
	for _, sel := range sels {
		level, culprits := dnsserver.Worst(sel.Servers)
		groups = append(groups, graded{level, culprits})
	}
	sort.SliceStable(groups, func(i, j int) bool { return groups[i].level > groups[j].level })

	type key struct {
		file string
		line int
		raw  string
	}
	var out []model.Location
	seen := map[key]bool{}
	for _, g := range groups {
		for _, s := range g.culprits {
			k := key{s.Loc.File, s.Loc.Line, s.Raw}
			if seen[k] {
				continue
			}
			seen[k] = true
			loc := s.Loc
			loc.Text = s.Raw
			out = append(out, loc.WithRole(model.RoleResolver))
		}
	}
	return out
}

// mixedLevels reports whether the affected items reach resolvers of
// different levels.
func mixedLevels(items []affected) bool {
	for _, it := range items[1:] {
		if it.level != items[0].level {
			return true
		}
	}
	return false
}

// commonNotes lists assumptions shared by leak findings.
func (e *Env) commonNotes(items []affected) []model.Note {
	var notes []model.Note
	seen := map[string]bool{}
	for _, it := range items {
		if it.group != "" && !seen[it.group] {
			seen[it.group] = true
			notes = append(notes, model.Note{Key: "group-assumed-proxy", Args: model.Args{"group": it.group}})
		}
	}
	d := &e.Cfg.DNS
	switch {
	case !d.Enable:
		notes = append(notes, model.Note{Key: "dns-disabled"})
	default:
		if len(d.NameserverPolicy) > 0 {
			notes = append(notes, model.Note{Key: "policy-static"})
		}
		if len(d.Fallback.Servers) > 0 {
			notes = append(notes, model.Note{Key: "fallback-included", Args: model.Args{"lazy": strconv.FormatBool(d.FallbackLazyQuery)}})
		}
		if d.RespectRules {
			notes = append(notes, model.Note{Key: "respect-rules-proxy"})
		}
	}
	notes = append(notes, model.Note{Key: "system-proxy-scope"})
	return notes
}
