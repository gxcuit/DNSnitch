// Package fix computes automatic repairs for check findings that have a
// mechanical fix (no-resolve on resolving rules, plaintext DNS removal, key
// typos). It edits the original text minimally, byte for byte, and never
// reads or writes files; re-checking is injected through CheckFunc. It holds
// no user-facing prose: skip reasons are language-neutral codes.
package fix

import (
	"bytes"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"dnsnitch/internal/config"
	"dnsnitch/internal/model"
	"dnsnitch/internal/ruleparse"
)

// Skip reason codes.
const (
	ReasonSharedNode       = "shared-node"        // node reached through an anchor / alias / "<<" merge
	ReasonMultiline        = "multiline"          // multi-line scalar or flow collection
	ReasonLayout           = "layout"             // the text does not have the expected shape
	ReasonKeyExists        = "key-exists"         // CFG-01: the suggested key already exists
	ReasonOtherFile        = "other-file"         // the location is not in the checked config
	ReasonRenameBreaksLoad = "rename-breaks-load" // CFG-01: renaming makes new load errors appear
	ReasonPassLimit        = "pass-limit"         // found after the last allowed rule pass
)

// ReplacementDNS replaces the servers of a nameserver / proxy-server-nameserver
// list that would become empty once its plaintext servers are removed.
const ReplacementDNS = "https://223.5.5.5/dns-query"

// MaxPasses bounds the rule phase: fixing one trigger can expose the next.
const MaxPasses = 8

// CheckFunc parses and checks config data, returning the findings (with
// locations in the same file name Build is given) or a parse error.
type CheckFunc func(data []byte) ([]model.Finding, error)

// Plan is the result of Build.
type Plan struct {
	Original []byte
	Fixed    []byte // equals Original when Edits is empty
	Edits    []Edit
	Skips    []Skip
	Hunks    []Hunk // line diff Original -> Fixed, 3 lines of context
	Passes   int    // rule-phase passes that changed the text
}

// Edit is one changed line of the original file.
type Edit struct {
	ID     string `json:"id"`
	Line   int    `json:"line"` // line in the original file
	Path   string `json:"path"`
	Before string `json:"before"` // whole line before the change
	After  string `json:"after"`  // whole line after the change; "" when deleted
}

// Skip is a fixable finding location that was left unchanged.
type Skip struct {
	ID     string `json:"id"`
	Line   int    `json:"line"` // line in the original file
	Path   string `json:"path"`
	Reason string `json:"reason"` // one of the Reason* codes
}

// Eligible reports whether a finding has an automatic fix. Info-level
// RULE-01..04 (the query goes through the proxy anyway) are not leaks:
// adding no-resolve there would only change routing.
func Eligible(f model.Finding) bool {
	switch f.ID {
	case "RULE-01", "RULE-02":
		return f.Args["kind"] == "always" && f.Severity > model.Info
	case "RULE-03", "RULE-04":
		k := f.Args["kind"]
		return (k == "always" || k == "conditional") && f.Severity > model.Info
	case "DNS-02", "DNS-09":
		return true
	case "CFG-01":
		return f.Args["suggest"] != "" && f.Args["anchor"] != "true"
	}
	return false
}

// Build computes the fixes for data (the content of file). check is called
// on the original and on intermediate texts.
func Build(file string, data []byte, check CheckFunc) (*Plan, error) {
	initial, err := check(data)
	if err != nil {
		return nil, err
	}
	r, err := newRun(file, check, false).do(data, initial)
	if err != nil {
		return nil, err
	}
	if r.renamed {
		// Renaming a key can activate a setting mihomo used to ignore and
		// make the config fail to load; then keep the typos instead.
		final, err := check(r.fixed)
		if _, added := NewError(initial, final); err != nil || added {
			if r, err = newRun(file, check, true).do(data, initial); err != nil {
				return nil, err
			}
		}
	}
	return r.plan(data), nil
}

// NewError returns an error-severity finding of after that before does not
// have (compared by ID and first location path): the fixed text must not
// make mihomo fail where the original loaded.
func NewError(before, after []model.Finding) (model.Finding, bool) {
	key := func(f model.Finding) string {
		p := ""
		if len(f.Locations) > 0 {
			p = f.Locations[0].Path
		}
		return f.ID + "\x00" + p
	}
	old := map[string]bool{}
	for _, f := range before {
		if f.Severity == model.Error {
			old[key(f)] = true
		}
	}
	for _, f := range after {
		if f.Severity == model.Error && !old[key(f)] {
			return f, true
		}
	}
	return model.Finding{}, false
}

// ref is a finding location a change belongs to.
type ref struct {
	id   string
	line int
	path string
	// primary is the path identifying the finding when it differs from
	// path (RULE-04 fixed in the chain a SUB-RULE leads to).
	primary string
}

func (rf ref) key() string {
	if rf.primary != "" {
		return coverKey(rf.id, rf.primary)
	}
	return coverKey(rf.id, rf.path)
}

type run struct {
	file     string
	check    CheckFunc
	noRename bool

	fixed    []byte
	refs     []ref
	deleted  map[int]bool // original lines removed by the DNS phase
	skips    []Skip
	seenSkip map[Skip]bool
	covered  map[string]bool // ID + primary path of handled findings
	passes   int
	renamed  bool
	// viaChain are RULE-04 findings of a SUB-RULE whose trigger point is
	// in a classical set referenced from its chain; see reasonViaChain.
	viaChain []ref
}

func newRun(file string, check CheckFunc, noRename bool) *run {
	return &run{
		file: file, check: check, noRename: noRename,
		deleted: map[int]bool{}, seenSkip: map[Skip]bool{}, covered: map[string]bool{},
	}
}

func coverKey(id, path string) string { return id + "\x00" + path }

func (r *run) skip(id string, line int, path, reason string) {
	r.skipRef(ref{id: id, line: line, path: path}, reason)
}

func (r *run) skipRef(rf ref, reason string) {
	s := Skip{ID: rf.id, Line: rf.line, Path: rf.path, Reason: reason}
	r.covered[rf.key()] = true
	if !r.seenSkip[s] {
		r.seenSkip[s] = true
		r.skips = append(r.skips, s)
	}
}

func (r *run) skipRefs(refs []ref, reason string) {
	for _, rf := range refs {
		r.skipRef(rf, reason)
	}
}

func (r *run) edited(refs []ref) {
	for _, rf := range refs {
		r.covered[rf.key()] = true
		r.refs = append(r.refs, rf)
	}
}

func (r *run) do(data []byte, fs []model.Finding) (*run, error) {
	cur := data
	capped := true
	for r.passes < MaxPasses {
		next, kept, ok, err := r.rulePass(cur, fs)
		if err != nil {
			return nil, err
		}
		if !ok {
			capped = false
			break
		}
		nfs, err := r.check(next)
		if err != nil {
			// Not expected after the per-node verification; keep the
			// last text that loaded.
			for _, op := range kept {
				r.skipRefs(op.refs, ReasonLayout)
			}
			capped = false
			break
		}
		for _, op := range kept {
			r.edited(op.refs)
			if op.rename != "" {
				r.renamed = true
			}
		}
		cur, fs = next, nfs
		r.passes++
	}
	if capped {
		for _, f := range fs {
			if Eligible(f) && isRulePhase(f.ID) {
				if loc, ok := primary(f); ok && !r.covered[coverKey(f.ID, loc.Path)] {
					r.skip(f.ID, loc.Line, loc.Path, ReasonPassLimit)
				}
			}
		}
	}
	// A finding left to its SUB-RULE chain that is still reported: the
	// chain could not be fixed (its own finding says why).
	for _, rf := range r.viaChain {
		if !r.covered[rf.key()] && reported(fs, rf) {
			r.skipRef(rf, ReasonLayout)
		}
	}
	fixed, err := r.dnsPhase(cur, fs)
	if err != nil {
		return nil, err
	}
	r.fixed = fixed
	return r, nil
}

func isRulePhase(id string) bool { return id != "DNS-02" && id != "DNS-09" }

// reported reports whether fs still has the fixable rule-phase finding rf
// belongs to.
func reported(fs []model.Finding, rf ref) bool {
	for _, f := range fs {
		if f.ID == rf.id && Eligible(f) {
			if loc, ok := primary(f); ok && loc.Path == rf.path {
				return true
			}
		}
	}
	return false
}

// primary returns the location a rule-phase finding is fixed at.
func primary(f model.Finding) (model.Location, bool) {
	want := model.RoleTrigger
	if f.ID == "CFG-01" {
		want = model.RoleConfig
	}
	return role(f, want)
}

// skipUnlocated records a finding without the expected location.
func (r *run) skipUnlocated(f model.Finding) {
	var loc model.Location
	if len(f.Locations) > 0 {
		loc = f.Locations[0]
	}
	r.skip(f.ID, loc.Line, loc.Path, ReasonLayout)
}

func role(f model.Finding, want string) (model.Location, bool) {
	for _, l := range f.Locations {
		if l.Role == want {
			return l, true
		}
	}
	return model.Location{}, false
}

// ---- rule phase ----

// nodeOp is the change of one node in one pass: insertions into its value,
// or a new text for its key.
type nodeOp struct {
	path    string
	line    int
	rename  string   // new key text; "" for a value change
	inserts []insert // value-space insertions
	refs    []ref

	newPath string // path after the change
	want    string // value (or key) expected after the change
}

type insert struct {
	pos  int
	text string
}

type rulePlanner struct {
	r       *run
	doc     *config.Doc
	src     *source
	ops     []*nodeOp
	byPath  map[string]*nodeOp
	claimed map[*yaml.Node]map[string]bool // keys created by renames in this pass
}

// target resolves a location to an editable node.
func (p *rulePlanner) target(loc model.Location) (config.Target, string) {
	if loc.File != p.r.file {
		return config.Target{}, ReasonOtherFile
	}
	t, err := p.doc.Find(loc.Path)
	if err != nil {
		return config.Target{}, ReasonLayout
	}
	if t.Shared() {
		return config.Target{}, ReasonSharedNode
	}
	return t, ""
}

func (p *rulePlanner) addInsert(path string, line, pos int, text string, rf ref) {
	op := p.byPath[path]
	if op == nil {
		op = &nodeOp{path: path, line: line}
		p.byPath[path] = op
		p.ops = append(p.ops, op)
	}
	op.refs = append(op.refs, rf)
	for _, in := range op.inserts {
		if in.pos == pos && in.text == text {
			return
		}
	}
	op.inserts = append(op.inserts, insert{pos, text})
}

// rulePass plans and applies one pass of rule-phase changes. ok is false
// when nothing changed.
func (r *run) rulePass(cur []byte, fs []model.Finding) (next []byte, kept []*nodeOp, ok bool, err error) {
	doc, err := config.Nodes(cur)
	if err != nil {
		return nil, nil, false, err
	}
	p := &rulePlanner{r: r, doc: doc, src: newSource(cur, doc.BOM), byPath: map[string]*nodeOp{}, claimed: map[*yaml.Node]map[string]bool{}}
	for _, f := range fs {
		if !Eligible(f) {
			continue
		}
		switch f.ID {
		case "RULE-01", "RULE-02", "RULE-03":
			p.planAppend(f)
		case "RULE-04":
			p.planLogic(f)
		case "CFG-01":
			p.planRename(f)
		}
	}
	ops := p.ops
	for len(ops) > 0 {
		next, ops, err = p.applyOps(cur, ops)
		if err != nil {
			return nil, nil, false, err
		}
		if len(ops) == 0 {
			break
		}
		bad, err := verifyOps(next, ops)
		if err != nil {
			return nil, nil, false, err
		}
		if len(bad) == 0 {
			return next, ops, true, nil
		}
		var good []*nodeOp
		for _, op := range ops {
			if bad[op] {
				r.skipRefs(op.refs, ReasonLayout)
			} else {
				good = append(good, op)
			}
		}
		ops = good
	}
	return nil, nil, false, nil
}

// planAppend handles RULE-01/02/03: append ",no-resolve" to the trigger rule.
func (p *rulePlanner) planAppend(f model.Finding) {
	t, ok := role(f, model.RoleTrigger)
	if !ok {
		p.r.skipUnlocated(f)
		return
	}
	tg, reason := p.target(t)
	if reason == "" {
		reason = p.appendTo(tg, ref{id: f.ID, line: t.Line, path: t.Path})
	}
	if reason != "" {
		p.r.skip(f.ID, t.Line, t.Path, reason)
	}
}

// appendTo plans ",no-resolve" at the end of the rule held by tg, which
// is at rf.path.
func (p *rulePlanner) appendTo(tg config.Target, rf ref) string {
	n := tg.Node
	if n.Kind != yaml.ScalarNode {
		return ReasonLayout
	}
	if hasNoResolve(ruleparse.Parse(n.Value, true).Params) {
		return ReasonLayout
	}
	if _, reason := p.src.scalar(n); reason != "" {
		return reason
	}
	p.addInsert(rf.path, rf.line, len(n.Value), ",no-resolve", rf)
	return ""
}

// insertInto plans ",no-resolve" before the closing parenthesis of logic
// sub-rule sub of the rule held by tg, which is at rf.path.
func (p *rulePlanner) insertInto(tg config.Target, rf ref, sub *model.Rule) string {
	if hasNoResolve(sub.Params) {
		return ReasonLayout
	}
	ext, reason := p.src.scalar(tg.Node)
	if reason != "" {
		return reason
	}
	if !ext.identity {
		return ReasonLayout // escapes: value offsets differ from text offsets
	}
	p.addInsert(rf.path, rf.line, sub.Span[1], ",no-resolve", rf)
	return ""
}

// planLogic handles RULE-04: the resolving IP sub-rule of a logic rule.
func (p *rulePlanner) planLogic(f model.Finding) {
	t, ok := role(f, model.RoleTrigger)
	if !ok {
		p.r.skipUnlocated(f)
		return
	}
	switch reason := p.logic(f, t); reason {
	case "":
	case reasonViaChain:
		p.r.viaChain = append(p.r.viaChain, ref{id: f.ID, line: t.Line, path: t.Path})
	default:
		p.r.skip(f.ID, t.Line, t.Path, reason)
	}
}

// reasonViaChain is an internal result of logic, never a Skip reason: the
// classical set holding the trigger point is referenced from the chain a
// SUB-RULE leads to, not from its condition. That chain is checked on its
// own (analyze scans chains entered before the first trigger), so its
// RULE-03 / RULE-04 finding fixes the reference; the SUB-RULE finding is
// only skipped if it is still reported after the rule phase.
const reasonViaChain = "via-chain"

func (p *rulePlanner) logic(f model.Finding, t model.Location) string {
	tg, reason := p.target(t)
	if reason != "" {
		return reason
	}
	if tg.Node.Kind != yaml.ScalarNode {
		return ReasonLayout
	}
	rule := ruleparse.Parse(tg.Node.Value, true)
	e, ok := role(f, model.RoleTriggerEntry)
	if !ok || rule.Err != "" {
		return ReasonLayout
	}
	at := ref{id: f.ID, line: t.Line, path: t.Path}
	switch {
	case e.File == p.r.file && e.Path == t.Path:
		// The trigger point is a sub-rule of the logic rule itself.
		sub := findSub(rule.Subs, func(s *model.Rule) bool { return s.Raw == e.Text })
		if sub == nil {
			return ReasonLayout
		}
		return p.insertInto(tg, at, sub)
	case e.File != p.r.file || strings.HasPrefix(e.Path, "rule-providers."):
		// The trigger point is an entry of a classical rule-set: disable
		// resolution for the RULE-SET sub-rule that references it.
		set := f.Args["set"]
		sub := findSub(rule.Subs, func(s *model.Rule) bool { return s.Type == "RULE-SET" && s.Payload == set })
		if set == "" || sub == nil {
			if set != "" && rule.Type == "SUB-RULE" {
				return reasonViaChain
			}
			if e.File != p.r.file {
				return ReasonOtherFile
			}
			return ReasonLayout
		}
		return p.insertInto(tg, at, sub)
	default:
		// The trigger point is in the chain a SUB-RULE leads to.
		eg, reason := p.target(e)
		if reason != "" {
			return reason
		}
		if eg.Node.Kind != yaml.ScalarNode {
			return ReasonLayout
		}
		in := ref{id: f.ID, line: e.Line, path: e.Path, primary: t.Path}
		if eg.Node.Value == e.Text {
			return p.appendTo(eg, in)
		}
		er := ruleparse.Parse(eg.Node.Value, true)
		sub := findSub(er.Subs, func(s *model.Rule) bool { return s.Raw == e.Text })
		if sub == nil {
			return ReasonLayout
		}
		return p.insertInto(eg, in, sub)
	}
}

// findSub returns the first logic sub-rule (depth first, in order) that
// matches and does not carry no-resolve yet.
func findSub(subs []model.Rule, match func(*model.Rule) bool) *model.Rule {
	for i := range subs {
		s := &subs[i]
		if match(s) && !s.NoResolve && !hasNoResolve(s.Params) {
			return s
		}
		if found := findSub(s.Subs, match); found != nil {
			return found
		}
	}
	return nil
}

// planRename handles CFG-01: replace a misspelled key with the suggestion.
func (p *rulePlanner) planRename(f model.Finding) {
	loc, ok := role(f, model.RoleConfig)
	if !ok {
		p.r.skipUnlocated(f)
		return
	}
	if reason := p.rename(f, loc); reason != "" {
		p.r.skip(f.ID, loc.Line, loc.Path, reason)
	}
}

func (p *rulePlanner) rename(f model.Finding, loc model.Location) string {
	tg, reason := p.target(loc)
	if reason != "" {
		return reason
	}
	suggest := f.Args["suggest"]
	if tg.Key == nil || tg.Parent == nil || !strings.HasSuffix(loc.Path, tg.Key.Value) {
		return ReasonLayout
	}
	if config.HasKey(tg.Parent, suggest) || p.claimed[tg.Parent][suggest] {
		return ReasonKeyExists
	}
	if _, reason := p.src.scalar(tg.Key); reason != "" {
		return reason
	}
	if p.r.noRename {
		return ReasonRenameBreaksLoad
	}
	if p.claimed[tg.Parent] == nil {
		p.claimed[tg.Parent] = map[string]bool{}
	}
	p.claimed[tg.Parent][suggest] = true
	op := &nodeOp{path: loc.Path, line: loc.Line, rename: suggest, refs: []ref{{id: f.ID, line: loc.Line, path: loc.Path}}}
	p.ops = append(p.ops, op)
	return ""
}

// applyOps turns ops into text replacements and applies them. Ops whose
// replacements collide with earlier ones are dropped (skipped as layout).
func (p *rulePlanner) applyOps(cur []byte, ops []*nodeOp) ([]byte, []*nodeOp, error) {
	var rs []repl
	var kept []*nodeOp
	for _, op := range ops {
		opRs, ok := p.opRepls(op)
		if ok {
			for _, x := range opRs {
				if overlaps(x, rs) {
					ok = false
					break
				}
			}
		}
		if !ok {
			p.r.skipRefs(op.refs, ReasonLayout)
			continue
		}
		rs = append(rs, opRs...)
		kept = append(kept, op)
	}
	if len(kept) == 0 {
		return cur, nil, nil
	}
	next, err := apply(cur, rs)
	if err != nil {
		return nil, nil, err
	}
	return next, kept, nil
}

// opRepls computes the replacements of op and sets op.newPath / op.want.
func (p *rulePlanner) opRepls(op *nodeOp) ([]repl, bool) {
	tg, err := p.doc.Find(op.path)
	if err != nil {
		return nil, false
	}
	if op.rename != "" {
		ext, reason := p.src.scalar(tg.Key)
		if reason != "" {
			return nil, false
		}
		op.newPath = strings.TrimSuffix(op.path, tg.Key.Value) + op.rename
		op.want = op.rename
		return []repl{{ext.inner[0], ext.inner[1], op.rename}}, true
	}
	ext, reason := p.src.scalar(tg.Node)
	if reason != "" {
		return nil, false
	}
	value := tg.Node.Value
	ins := append([]insert(nil), op.inserts...)
	sort.Slice(ins, func(i, j int) bool { return ins[i].pos > ins[j].pos })
	var rs []repl
	want := value
	for _, in := range ins {
		var at int
		switch {
		case in.pos == len(value):
			at = ext.inner[1]
		case ext.identity && in.pos >= 0 && in.pos < len(value):
			at = ext.inner[0] + in.pos
		default:
			return nil, false
		}
		rs = append(rs, repl{at, at, in.text})
		want = want[:in.pos] + in.text + want[in.pos:]
	}
	op.newPath, op.want = op.path, want
	return rs, true
}

// verifyOps re-parses next and returns the ops whose node does not hold the
// expected value.
func verifyOps(next []byte, ops []*nodeOp) (map[*nodeOp]bool, error) {
	bad := map[*nodeOp]bool{}
	doc, err := config.Nodes(next)
	if err != nil {
		for _, op := range ops {
			bad[op] = true
		}
		return bad, nil
	}
	for _, op := range ops {
		tg, err := doc.Find(op.newPath)
		switch {
		case err != nil:
			bad[op] = true
		case op.rename != "":
			bad[op] = tg.Key == nil || tg.Key.Value != op.want
		default:
			bad[op] = tg.Node.Kind != yaml.ScalarNode || tg.Node.Value != op.want
		}
		if !bad[op] {
			delete(bad, op)
		}
	}
	return bad, nil
}

// ---- DNS phase ----

// listWork collects the plaintext servers to remove from one DNS list.
type listWork struct {
	path  string
	name  string
	items map[int][]ref
}

// listChange is the planned change of one list.
type listChange struct {
	path    string
	repls   []repl
	refs    []ref // edited lines
	deleted []int // original lines removed
	want    []string
	all     []ref // every ref of the list, for skipping
}

func (r *run) dnsPhase(cur []byte, fs []model.Finding) ([]byte, error) {
	var lists []*listWork
	byPath := map[string]*listWork{}
	for _, f := range fs {
		if (f.ID != "DNS-02" && f.ID != "DNS-09") || !Eligible(f) {
			continue
		}
		for _, loc := range f.Locations {
			if loc.Role != model.RoleResolver {
				continue
			}
			if loc.File != r.file {
				r.skip(f.ID, loc.Line, loc.Path, ReasonOtherFile)
				continue
			}
			listPath, idx, ok := splitItem(loc.Path)
			name := listPath[strings.LastIndexByte(listPath, '.')+1:]
			if !ok || !strings.HasPrefix(listPath, "dns.") || (name != "nameserver" && name != "fallback" && name != "proxy-server-nameserver") {
				r.skip(f.ID, loc.Line, loc.Path, ReasonLayout)
				continue
			}
			w := byPath[listPath]
			if w == nil {
				w = &listWork{path: listPath, name: name, items: map[int][]ref{}}
				byPath[listPath] = w
				lists = append(lists, w)
			}
			w.items[idx] = append(w.items[idx], ref{id: f.ID, line: loc.Line, path: loc.Path})
		}
	}
	if len(lists) == 0 {
		return cur, nil
	}
	doc, err := config.Nodes(cur)
	if err != nil {
		return nil, err
	}
	src := newSource(cur, doc.BOM)
	var changes []*listChange
	var rs []repl
	for _, w := range lists {
		c := r.planList(doc, src, w)
		if c == nil {
			continue
		}
		ok := true
		for _, x := range c.repls {
			if overlaps(x, rs) {
				ok = false
			}
		}
		if !ok {
			r.skipRefs(c.all, ReasonLayout)
			continue
		}
		rs = append(rs, c.repls...)
		changes = append(changes, c)
	}
	for len(changes) > 0 {
		var all []repl
		for _, c := range changes {
			all = append(all, c.repls...)
		}
		next, err := apply(cur, all)
		if err != nil {
			return nil, err
		}
		ndoc, err := config.Nodes(next)
		var good []*listChange
		for _, c := range changes {
			if err == nil && listMatches(ndoc, c.path, c.want) {
				good = append(good, c)
			} else {
				r.skipRefs(c.all, ReasonLayout)
			}
		}
		if len(good) == len(changes) {
			for _, c := range changes {
				r.edited(c.refs)
				for _, l := range c.deleted {
					r.deleted[l] = true
				}
			}
			return next, nil
		}
		changes = good
	}
	return cur, nil
}

// splitItem splits "dns.nameserver[2]" into "dns.nameserver" and 2.
func splitItem(path string) (string, int, bool) {
	if !strings.HasSuffix(path, "]") {
		return path, 0, false
	}
	i := strings.LastIndexByte(path, '[')
	if i <= 0 {
		return path, 0, false
	}
	n := 0
	for _, c := range path[i+1 : len(path)-1] {
		if c < '0' || c > '9' {
			return path, 0, false
		}
		n = n*10 + int(c-'0')
	}
	if i+1 == len(path)-1 {
		return path, 0, false
	}
	return path[:i], n, true
}

// planList plans the removal of w's items; it records skips itself and
// returns nil when nothing can change.
func (r *run) planList(doc *config.Doc, src *source, w *listWork) *listChange {
	idxs := make([]int, 0, len(w.items))
	for i := range w.items {
		idxs = append(idxs, i)
	}
	sort.Ints(idxs)
	// remove holds the items still to be removed; items skipped on their
	// own are dropped from it. nil means "all requested items".
	var remove map[int]bool
	pending := func() []ref {
		var out []ref
		for _, i := range idxs {
			if remove == nil || remove[i] {
				out = append(out, w.items[i]...)
			}
		}
		return out
	}
	fail := func(reason string) *listChange {
		r.skipRefs(pending(), reason)
		return nil
	}
	lt, err := doc.Find(w.path)
	if err != nil {
		return fail(ReasonLayout)
	}
	if lt.Shared() {
		return fail(ReasonSharedNode)
	}
	keepFirst := w.name != "fallback" // nameserver lists must not become empty
	n := lt.Node
	c := &listChange{path: w.path}
	defer func() { c.all = pending() }()
	switch {
	case n.Kind == yaml.ScalarNode:
		// "nameserver: 8.8.8.8" is a one-element list.
		ext, reason := src.scalar(n)
		if reason != "" {
			return fail(reason)
		}
		if keepFirst {
			c.repls = []repl{{ext.inner[0], ext.inner[1], ReplacementDNS}}
			c.want = []string{ReplacementDNS}
		} else {
			c.repls = []repl{{ext.outer[0], ext.outer[1], "[]"}}
			c.want = []string{}
		}
		for _, rf := range pending() {
			c.refs = append(c.refs, ref{id: rf.id, line: n.Line, path: rf.path})
		}
		return c
	case n.Kind != yaml.SequenceNode:
		return fail(ReasonLayout)
	}

	// Items that can be removed.
	remove = map[int]bool{}
	for _, i := range idxs {
		if i >= len(n.Content) {
			r.skipRefs(w.items[i], ReasonLayout)
			continue
		}
		item := n.Content[i]
		if item.Kind == yaml.AliasNode || item.Anchor != "" {
			r.skipRefs(w.items[i], ReasonSharedNode)
			continue
		}
		remove[i] = true
	}

	if n.Style&yaml.FlowStyle != 0 {
		if len(remove) == 0 {
			return nil
		}
		rng, texts, reason := src.flowList(n)
		if reason != "" {
			return fail(reason)
		}
		var keep []string
		c.want = []string{}
		for i, t := range texts {
			if !remove[i] {
				keep = append(keep, t)
				c.want = append(c.want, n.Content[i].Value)
			}
		}
		if len(keep) == 0 && keepFirst {
			keep = []string{ReplacementDNS}
			c.want = []string{ReplacementDNS}
		}
		c.repls = []repl{{rng[0], rng[1], "[" + strings.Join(keep, ", ") + "]"}}
		for _, i := range idxs {
			if remove[i] {
				for _, rf := range w.items[i] {
					c.refs = append(c.refs, ref{id: rf.id, line: n.Line, path: w.path})
				}
			}
		}
		return c
	}

	// Block sequence: each removed item is a whole line.
	type lineRange struct{ start, next int }
	lines := map[int]lineRange{}
	exts := map[int]extent{}
	for _, i := range idxs {
		if !remove[i] {
			continue
		}
		item := n.Content[i]
		ext, reason := src.scalar(item)
		var lr lineRange
		if reason == "" {
			lr.start, lr.next, reason = src.blockItemLine(item, ext)
		}
		if reason != "" {
			r.skipRefs(w.items[i], reason)
			delete(remove, i)
			continue
		}
		lines[i], exts[i] = lr, ext
	}
	if len(remove) == 0 {
		return nil
	}
	empty := len(remove) == len(n.Content)
	c.want = []string{}
	for i, v := range config.ListValues(n) {
		if !remove[i] {
			c.want = append(c.want, v)
		}
	}
	for _, i := range idxs {
		if !remove[i] {
			continue
		}
		item := n.Content[i]
		if empty && keepFirst && i == 0 {
			// Keep the line of the first item, with the replacement server.
			c.repls = append(c.repls, repl{exts[i].inner[0], exts[i].inner[1], ReplacementDNS})
		} else {
			c.repls = append(c.repls, repl{lines[i].start, lines[i].next, ""})
			c.deleted = append(c.deleted, item.Line)
		}
		for _, rf := range w.items[i] {
			c.refs = append(c.refs, ref{id: rf.id, line: item.Line, path: rf.path})
		}
	}
	if empty && keepFirst {
		c.want = []string{ReplacementDNS}
	}
	if empty && !keepFirst {
		// fallback: remove every item and leave "fallback: []".
		if lt.Key == nil {
			return fail(ReasonLayout)
		}
		at, reason := src.afterColon(lt.Key)
		if reason != "" {
			return fail(reason)
		}
		c.repls = append(c.repls, repl{at, at, " []"})
		c.refs = append(c.refs, ref{id: c.refs[0].id, line: lt.Key.Line, path: w.path})
	}
	return c
}

// listMatches reports whether the list at path holds exactly want.
func listMatches(doc *config.Doc, path string, want []string) bool {
	t, err := doc.Find(path)
	if err != nil {
		return false
	}
	return slices.Equal(config.ListValues(t.Node), want)
}

// ---- plan ----

func bomLen(data []byte) int {
	if bytes.HasPrefix(data, []byte(bomText)) {
		return len(bomText)
	}
	return 0
}

// plan assembles the Plan: one Edit per finding ID and original line, with
// the line text before and after all changes.
func (r *run) plan(orig []byte) *Plan {
	p := &Plan{Original: orig, Fixed: r.fixed, Passes: r.passes, Skips: r.skips}
	if bytes.Equal(orig, r.fixed) {
		p.Fixed = orig
		p.Skips = sortSkips(p.Skips)
		return p
	}
	so := newSource(orig, bomLen(orig))
	fixedLines := splitLines(r.fixed)
	var gone []int
	for l := range r.deleted {
		gone = append(gone, l)
	}
	sort.Ints(gone)
	after := func(line int) string {
		if r.deleted[line] {
			return ""
		}
		k := sort.SearchInts(gone, line) // deleted lines before this one
		i := line - 1 - k
		if i < 0 || i >= len(fixedLines) {
			return ""
		}
		t := trimEOL(fixedLines[i])
		if i == 0 {
			t = strings.TrimPrefix(t, bomText)
		}
		return t
	}
	type idLine struct {
		id   string
		line int
	}
	seen := map[idLine]bool{}
	for _, rf := range r.refs {
		k := idLine{rf.id, rf.line}
		if seen[k] {
			continue
		}
		seen[k] = true
		p.Edits = append(p.Edits, Edit{ID: rf.id, Line: rf.line, Path: rf.path, Before: so.lineText(rf.line), After: after(rf.line)})
	}
	sort.SliceStable(p.Edits, func(i, j int) bool {
		if p.Edits[i].Line != p.Edits[j].Line {
			return p.Edits[i].Line < p.Edits[j].Line
		}
		return p.Edits[i].ID < p.Edits[j].ID
	})
	p.Skips = sortSkips(p.Skips)
	p.Hunks = Diff(orig, r.fixed, 3)
	return p
}

func sortSkips(s []Skip) []Skip {
	sort.SliceStable(s, func(i, j int) bool {
		if s[i].Line != s[j].Line {
			return s[i].Line < s[j].Line
		}
		return s[i].ID < s[j].ID
	})
	return s
}
