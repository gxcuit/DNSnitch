package report

import (
	"io"
	"strconv"
	"strings"

	"dnsleak/internal/platform"
)

// Combined conclusion codes of StatusView.ConclusionCode.
const (
	ConclusionRisk        = "risk"        // TUN on + smart name resolution not disabled: certain leak
	ConclusionProtected   = "protected"   // smart name resolution disabled
	ConclusionTUNOff      = "tun-off"     // TUN off: the setting does not matter now
	ConclusionUnknown     = "unknown"     // a state could not be determined
	ConclusionUnsupported = "unsupported" // not Windows
)

// StatusItem is one inspected setting as rendered for text, JSON and GUI.
type StatusItem struct {
	Title  string   `json:"title"`  // display name of the setting
	State  string   `json:"state"`  // platform.State* code
	Label  string   `json:"label"`  // display name of State
	Reason string   `json:"reason"` // platform.Reason* code
	Detail []string `json:"detail"` // evidence lines
	Note   string   `json:"note"`   // extra remark, may be empty
}

// FixStep is one display-only remedy step. Command is shown for the user
// to copy; dnsleak never runs it.
type FixStep struct {
	Text    string `json:"text"`
	Command string `json:"command,omitempty"`
}

// StatusView is the rendered system status: the JSON output of
// `dnsleak status` and the value returned to the GUI.
type StatusView struct {
	OS             string     `json:"os"`
	Smart          StatusItem `json:"smart"`
	TUN            StatusItem `json:"tun"`
	Risk           bool       `json:"risk"`
	ConclusionCode string     `json:"conclusion_code"` // Conclusion*
	Conclusion     string     `json:"conclusion"`
	Fix            []FixStep  `json:"fix"` // empty unless smart name resolution may be in effect
}

// conclusionCode combines the two states.
func conclusionCode(s platform.Snapshot) string {
	switch {
	case s.Smart.State == platform.StateUnsupported || s.TUN.State == platform.StateUnsupported:
		return ConclusionUnsupported
	case s.Risk:
		return ConclusionRisk
	case s.Smart.State == platform.StateDisabled:
		return ConclusionProtected
	case s.TUN.State == platform.StateOff:
		return ConclusionTUNOff
	default:
		return ConclusionUnknown
	}
}

// BuildStatusView renders a snapshot.
func BuildStatusView(s platform.Snapshot) StatusView {
	v := StatusView{
		OS: s.OS,
		Smart: StatusItem{
			Title:  statusTitleSmart,
			State:  s.Smart.State,
			Label:  zh(smartStateZh, s.Smart.State),
			Reason: s.Smart.Reason,
			Detail: smartDetailZh(s),
		},
		TUN: StatusItem{
			Title:  statusTitleTUN,
			State:  s.TUN.State,
			Label:  zh(tunStateZh, s.TUN.State),
			Reason: s.TUN.Reason,
			Detail: tunDetailZh(s.TUN),
			Note:   zh(tunNoteZh, s.TUN.Note),
		},
		Risk:           s.Risk,
		ConclusionCode: conclusionCode(s),
		Fix:            []FixStep{},
	}
	v.Conclusion = conclusionZh(v.ConclusionCode, s)
	if s.Smart.State == platform.StateEnabled || s.Smart.State == platform.StateUnknown {
		v.Fix = append(v.Fix, smartFixZh...)
	}
	return v
}

// StatusExitCode returns 1 when the status is a certain leak, else 0.
// Unknown states are not a risk.
func StatusExitCode(v StatusView) int {
	if v.Risk {
		return 1
	}
	return 0
}

// WriteStatus renders the result of `status`.
func WriteStatus(w io.Writer, format string, v StatusView) error {
	if format == FormatJSON {
		return writeJSON(w, v)
	}
	var b strings.Builder
	b.WriteString(labelStatusHeader + "\n\n")
	for _, it := range []StatusItem{v.Smart, v.TUN} {
		b.WriteString(it.Title + labelStatusSep + it.Label + "\n")
		for _, d := range it.Detail {
			b.WriteString("  " + d + "\n")
		}
		if it.Note != "" {
			b.WriteString("  " + labelStatusNote + it.Note + "\n")
		}
		b.WriteString("\n")
	}
	b.WriteString(labelStatusConclusion + v.Conclusion + "\n")
	if len(v.Fix) > 0 {
		b.WriteString("\n" + labelStatusFix + "\n")
		for i, f := range v.Fix {
			b.WriteString("  " + strconv.Itoa(i+1) + ". " + f.Text + "\n")
			if f.Command != "" {
				b.WriteString("     " + f.Command + "\n")
			}
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}
