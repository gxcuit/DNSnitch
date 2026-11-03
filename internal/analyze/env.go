// Package analyze implements the static checks: resolution-trigger
// classification (design §9.1), rule-chain scanning (§9.2), resolver
// inference (§9.3) and the independent checks (§9.4).
package analyze

import (
	"sort"

	"dnsleak/internal/dnsserver"
	"dnsleak/internal/model"
	"dnsleak/internal/policy"
	"dnsleak/internal/ruledata"
)

// Env bundles everything derived from one config; shared with trace.
type Env struct {
	Cfg   *model.Config
	Store *ruledata.Store
	Pol   *policy.Classifier

	subTrig map[string]Trigger // memoized chainTrigger results
	subBusy map[string]bool    // sub-rules chains on the current stack
}

// NewEnv classifies policies and grades every DNS server of cfg.
func NewEnv(cfg *model.Config, home string) *Env {
	e := &Env{
		Cfg: cfg, Store: ruledata.NewStore(cfg, home), Pol: policy.New(cfg),
		subTrig: map[string]Trigger{}, subBusy: map[string]bool{},
	}
	dnsserver.GradeConfig(&cfg.DNS, e.Pol.Lookup)
	return e
}

// Row of the PRD R5 matrix.
type Row int

const (
	RowResolved Row = iota + 1 // RULE-01: domains that are certainly resolved
	RowUnknown                 // RULE-02: only unknown domains
)

// MatrixSeverity implements the PRD R5 risk matrix.
func MatrixSeverity(row Row, l dnsserver.Level) model.Severity {
	switch l {
	case dnsserver.LevelPlain:
		if row == RowResolved {
			return model.High
		}
		return model.Medium
	case dnsserver.LevelCN:
		if row == RowResolved {
			return model.Medium
		}
		return model.Low
	case dnsserver.LevelForeign:
		return model.Low
	default:
		return model.Info
	}
}

// Check runs every check and returns findings in a stable order (the report
// layer sorts them for display).
func (e *Env) Check() []model.Finding {
	var out []model.Finding
	out = append(out, e.checkUnknownKeys()...)
	out = append(out, e.checkMissingRefs()...)
	out = append(out, e.checkDNS()...)
	out = append(out, e.checkRules()...)
	return out
}

// SortFindings orders findings by severity (desc), first location line,
// then ID.
func SortFindings(fs []model.Finding) {
	firstLine := func(f model.Finding) int {
		if len(f.Locations) == 0 {
			return 0
		}
		return f.Locations[0].Line
	}
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity != fs[j].Severity {
			return fs[i].Severity > fs[j].Severity
		}
		if li, lj := firstLine(fs[i]), firstLine(fs[j]); li != lj {
			return li < lj
		}
		return fs[i].ID < fs[j].ID
	})
}
