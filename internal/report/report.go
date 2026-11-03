// Package report renders findings and trace results as text (Chinese) or
// JSON. All prose comes from messages_zh.go.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"dnsleak/internal/analyze"
	"dnsleak/internal/dnsserver"
	"dnsleak/internal/model"
	"dnsleak/internal/trace"
)

// Formats.
const (
	FormatText = "text"
	FormatJSON = "json"
)

// maxPerRoleShown caps consecutive locations of one role in text output.
const maxPerRoleShown = 6

// ExitCode returns 1 if any finding is error / high / medium, else 0.
func ExitCode(fs []model.Finding) int {
	for _, f := range fs {
		if f.Severity >= model.Medium {
			return 1
		}
	}
	return 0
}

// Counts returns the number of findings per severity.
func Counts(fs []model.Finding) map[model.Severity]int {
	m := map[model.Severity]int{}
	for _, f := range fs {
		m[f.Severity]++
	}
	return m
}

// WriteCheck renders the result of `check`. Findings are sorted in place.
func WriteCheck(w io.Writer, format, file string, fs []model.Finding) error {
	analyze.SortFindings(fs)
	if format == FormatJSON {
		return writeCheckJSON(w, file, fs)
	}
	return writeCheckText(w, file, fs)
}

func locString(l model.Location) string {
	switch {
	case l.Line > 0:
		return l.File + ":" + strconv.Itoa(l.Line)
	case l.Path != "":
		return l.File + " (" + l.Path + ", " + labelUnknownLine + ")"
	default:
		return l.File
	}
}

func writeCheckText(w io.Writer, file string, fs []model.Finding) error {
	var b strings.Builder
	b.WriteString(labelCheckHeader + file + "\n\n")
	if len(fs) == 0 {
		b.WriteString(labelNoFindings + "\n\n")
	}
	for _, f := range fs {
		head := "[" + severityZh[f.Severity] + "] " + f.ID
		if len(f.Locations) > 0 {
			head += "  " + locString(f.Locations[0])
		}
		b.WriteString(head + "\n")
		b.WriteString("  " + findingMessage(f) + "\n")
		if len(f.Locations) > 0 {
			b.WriteString("  " + labelLocations + "\n")
			perRole := map[string]int{}
			for i, l := range f.Locations {
				perRole[l.Role]++
				n := perRole[l.Role]
				if n <= maxPerRoleShown {
					line := fmt.Sprintf("    %-6s %s", zh(roleZh, l.Role), locString(l))
					if l.Text != "" {
						line += "  " + l.Text
					}
					if l.Resolver != nil {
						line += "  " + resolverAnnotZh(l.Resolver)
					}
					b.WriteString(line + "\n")
				}
				// After the last location of a role run, report hidden ones.
				last := i == len(f.Locations)-1 || f.Locations[i+1].Role != l.Role
				if last && n > maxPerRoleShown {
					b.WriteString("    " + fmt.Sprintf(labelMore, n-maxPerRoleShown) + "\n")
					perRole[l.Role] = 0
				}
			}
		}
		if fix := findingFix(f); fix != "" {
			b.WriteString("  " + labelFix + fix + "\n")
		}
		if len(f.Notes) > 0 {
			b.WriteString("  " + labelNotes + "\n")
			for _, n := range f.Notes {
				b.WriteString("    - " + noteText(n) + "\n")
			}
		}
		b.WriteString("\n")
	}
	b.WriteString(summaryText(Counts(fs)) + "\n")
	_, err := io.WriteString(w, b.String())
	return err
}

// FindingView is one finding as rendered for JSON output and the GUI.
type FindingView struct {
	ID        string           `json:"id"`
	Severity  string           `json:"severity"`
	Message   string           `json:"message"`
	Locations []model.Location `json:"locations"`
	Fix       string           `json:"fix"`
	Notes     []string         `json:"notes"`
}

// Summary counts findings per severity.
type Summary struct {
	Error  int `json:"error"`
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
	Info   int `json:"info"`
}

// CheckResult is the rendered result of `check`: the JSON output of the CLI
// and the value returned to the GUI.
type CheckResult struct {
	File     string        `json:"file"`
	Findings []FindingView `json:"findings"`
	Summary  Summary       `json:"summary"`
}

func toFindingView(f model.Finding) FindingView {
	jf := FindingView{
		ID:        f.ID,
		Severity:  f.Severity.String(),
		Message:   findingMessage(f),
		Locations: f.Locations,
		Fix:       findingFix(f),
		Notes:     []string{},
	}
	if jf.Locations == nil {
		jf.Locations = []model.Location{}
	}
	for _, n := range f.Notes {
		jf.Notes = append(jf.Notes, noteText(n))
	}
	return jf
}

// BuildCheckResult renders findings (already sorted, see
// analyze.SortFindings) into a CheckResult, keeping their order.
func BuildCheckResult(file string, fs []model.Finding) CheckResult {
	out := CheckResult{File: file, Findings: []FindingView{}}
	for _, f := range fs {
		out.Findings = append(out.Findings, toFindingView(f))
	}
	c := Counts(fs)
	out.Summary = Summary{Error: c[model.Error], High: c[model.High], Medium: c[model.Medium], Low: c[model.Low], Info: c[model.Info]}
	return out
}

func writeCheckJSON(w io.Writer, file string, fs []model.Finding) error {
	return writeJSON(w, BuildCheckResult(file, fs))
}

// Labels maps the codes used in CheckResult (severity enum, location role,
// resolver level and source) to display names. Built by GUILabels.
type Labels struct {
	Severity       map[string]string `json:"severity"`
	Role           map[string]string `json:"role"`
	Level          map[string]string `json:"level"`
	ResolverSource map[string]string `json:"resolver_source"`
	Text           map[string]string `json:"text"` // other short strings, keyed by LabelText*
}

// Keys of Labels.Text.
const (
	LabelTextUnknownLine = "unknown_line" // location without a line number
)

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// ---- trace ----

// TraceExitCode returns 1 when the trace verdict is a leak of medium or
// higher severity, else 0.
func TraceExitCode(r *trace.Result) int {
	if r.Verdict == trace.VerdictLeak && r.Severity >= model.Medium {
		return 1
	}
	return 0
}

// WriteTrace renders a trace result.
func WriteTrace(w io.Writer, format, file string, r *trace.Result) error {
	if format == FormatJSON {
		return writeTraceJSON(w, file, r)
	}
	return writeTraceText(w, file, r)
}

func stepRuleLoc(s trace.Step) string {
	if s.Rule.Loc.Line > 0 {
		return locString(s.Rule.Loc)
	}
	return s.Rule.Loc.File
}

func classLabel(class string) string { return zh(classZh, class) }

func writeTraceText(w io.Writer, file string, r *trace.Result) error {
	var b strings.Builder
	b.WriteString(fmt.Sprintf(labelTraceHeader, r.Domain, file) + "\n\n")
	if r.Hosts != nil {
		b.WriteString(fmt.Sprintf(labelHostsHit, r.Hosts.Pattern, locString(r.Hosts.Loc)) + "\n\n")
	}
	for i, s := range r.Steps {
		indent := strings.Repeat("    ", s.Depth)
		line := fmt.Sprintf("%s%2d. [%s] %s  %s", indent, i+1, zh(traceOutcomeZh, s.Outcome), stepRuleLoc(s), s.Rule.Raw)
		switch s.Outcome {
		case trace.OutMatch:
			if s.Class != "" {
				line += fmt.Sprintf(labelStepTarget, s.Target, classLabel(s.Class))
			} else if s.Rule.Type == "SUB-RULE" {
				line += fmt.Sprintf(labelSubRuleEnter, s.Target)
			}
		case trace.OutUnknown:
			line += fmt.Sprintf(labelStepReason, reasonWithName(s.Reason, s.Name))
			if s.DataFile != "" {
				line += fmt.Sprintf(labelStepDataFile, s.DataFile)
			}
			if s.Class != "" {
				line += fmt.Sprintf(labelIfMatched, s.Target, classLabel(s.Class))
			}
		case trace.OutAssumed, trace.OutNoMatch:
			if s.Reason != "" && s.Resolution == nil {
				line += fmt.Sprintf(labelStepReason, zh(reasonZh, s.Reason))
			}
		}
		b.WriteString(line + "\n")
		if s.Resolution != nil {
			writeResolutionText(&b, indent+"      ", s.Resolution)
			if s.Reason != "" {
				b.WriteString(indent + "      " + zh(reasonZh, s.Reason) + "\n")
			}
		}
	}
	b.WriteString("\n")

	if r.FinalRule != nil {
		b.WriteString(fmt.Sprintf(labelFinal, r.FinalRule.Raw, r.FinalTarget, classLabel(r.FinalClass)) + "\n")
	} else {
		b.WriteString(labelFinalDefault + "\n")
	}
	b.WriteString(labelVerdict + zh(verdictZh, r.Verdict) + "\n")
	if r.Verdict == trace.VerdictLeak || r.Verdict == trace.VerdictRedundant {
		b.WriteString(fmt.Sprintf(labelSeverity, severityZh[r.Severity]) + "\n")
	}
	if r.Uncertain {
		var refs []string
		for _, u := range r.Unknowns {
			refs = append(refs, fmt.Sprintf(labelStepRef, u.StepIndex+1, reasonWithName(u.Reason, u.Name)))
		}
		b.WriteString(fmt.Sprintf(labelUncertain, strings.Join(refs, labelListSep)) + "\n")
		b.WriteString("  " + zh(impactZh, r.Impact) + "\n")
	}
	if len(r.Notes) > 0 {
		b.WriteString(labelNotes + "\n")
		for _, n := range r.Notes {
			b.WriteString("  - " + noteText(n) + "\n")
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func reasonWithName(reason, name string) string {
	s := zh(reasonZh, reason)
	if name != "" {
		s = fmt.Sprintf(labelNamedReason, name, s)
	}
	return s
}

func writeResolutionText(b *strings.Builder, indent string, res *trace.Resolution) {
	if res.ViaHosts {
		b.WriteString(indent + labelResolutionHost + "\n")
		return
	}
	src := zh(sourceZh, res.Selection.Source.Code())
	if res.Selection.Policy != nil {
		src += fmt.Sprintf(labelPolicyKey, res.Selection.Policy.Key)
	}
	b.WriteString(indent + fmt.Sprintf(labelResolution, src) + "\n")
	for _, s := range res.Selection.Servers {
		b.WriteString(fmt.Sprintf("%s  - %-32s %-10s %s\n", indent, s.Raw, zh(serverZh, dnsserver.ServerCode(s)), locString(s.Loc)))
	}
	b.WriteString(indent + fmt.Sprintf(labelLevel, zh(levelZh, res.Level.Code())) + "\n")
}

type jsonServer struct {
	Server string `json:"server"`
	Grade  string `json:"grade"`
	File   string `json:"file"`
	Line   int    `json:"line"`
}

type jsonResolution struct {
	ViaHosts  bool         `json:"via_hosts"`
	Source    string       `json:"source,omitempty"`
	PolicyKey string       `json:"policy_key,omitempty"`
	Servers   []jsonServer `json:"servers"`
	Level     string       `json:"level,omitempty"`
}

type jsonStep struct {
	Step       int             `json:"step"`
	Depth      int             `json:"depth"`
	Rule       string          `json:"rule"`
	File       string          `json:"file"`
	Line       int             `json:"line"`
	Outcome    string          `json:"outcome"`
	Reason     string          `json:"reason,omitempty"`
	Name       string          `json:"name,omitempty"`
	DataFile   string          `json:"data_file,omitempty"`
	Target     string          `json:"target,omitempty"`
	Class      string          `json:"class,omitempty"`
	Resolution *jsonResolution `json:"resolution,omitempty"`
}

type jsonVerdict struct {
	Code        string   `json:"code"`
	Severity    string   `json:"severity,omitempty"`
	Message     string   `json:"message"`
	FinalRule   string   `json:"final_rule"`
	FinalTarget string   `json:"final_target"`
	FinalClass  string   `json:"final_class"`
	Uncertain   bool     `json:"uncertain"`
	Impact      string   `json:"impact,omitempty"`
	UnknownStep []int    `json:"unknown_steps"`
	Notes       []string `json:"notes"`
}

type jsonTrace struct {
	File    string      `json:"file"`
	Domain  string      `json:"domain"`
	Hosts   string      `json:"hosts,omitempty"`
	Steps   []jsonStep  `json:"steps"`
	Verdict jsonVerdict `json:"verdict"`
}

func writeTraceJSON(w io.Writer, file string, r *trace.Result) error {
	out := jsonTrace{File: file, Domain: r.Domain, Steps: []jsonStep{}}
	if r.Hosts != nil {
		out.Hosts = r.Hosts.Pattern
	}
	for i, s := range r.Steps {
		js := jsonStep{
			Step: i + 1, Depth: s.Depth, Rule: s.Rule.Raw, File: s.Rule.Loc.File, Line: s.Rule.Loc.Line,
			Outcome: s.Outcome, Reason: s.Reason, Name: s.Name, DataFile: s.DataFile, Target: s.Target, Class: s.Class,
		}
		if s.Resolution != nil {
			jr := &jsonResolution{ViaHosts: s.Resolution.ViaHosts, Servers: []jsonServer{}}
			if !s.Resolution.ViaHosts {
				jr.Source = s.Resolution.Selection.Source.Code()
				jr.Level = s.Resolution.Level.Code()
				if p := s.Resolution.Selection.Policy; p != nil {
					jr.PolicyKey = p.Key
				}
				for _, sv := range s.Resolution.Selection.Servers {
					jr.Servers = append(jr.Servers, jsonServer{Server: sv.Raw, Grade: dnsserver.ServerCode(sv), File: sv.Loc.File, Line: sv.Loc.Line})
				}
			}
			js.Resolution = jr
		}
		out.Steps = append(out.Steps, js)
	}
	v := jsonVerdict{
		Code: r.Verdict, Message: zh(verdictZh, r.Verdict), FinalTarget: r.FinalTarget, FinalClass: r.FinalClass,
		Uncertain: r.Uncertain, Impact: r.Impact, UnknownStep: []int{}, Notes: []string{},
	}
	if r.Verdict == trace.VerdictLeak || r.Verdict == trace.VerdictRedundant {
		v.Severity = r.Severity.String()
	}
	if r.FinalRule != nil {
		v.FinalRule = r.FinalRule.Raw
	}
	for _, u := range r.Unknowns {
		v.UnknownStep = append(v.UnknownStep, u.StepIndex+1)
	}
	for _, n := range r.Notes {
		v.Notes = append(v.Notes, noteText(n))
	}
	out.Verdict = v
	return writeJSON(w, out)
}
