package report

import (
	"fmt"
	"io"
	"strings"

	"dnsnitch/internal/fix"
	"dnsnitch/internal/model"
)

// Codes of FixResult.NotWrittenReason.
const (
	NotWrittenDryRun  = "dry-run"        // there are edits but nothing was written (--dry-run, GUI preview)
	NotWrittenNothing = "nothing-to-fix" // no edits, so no file
)

// FixSkip is a fixable finding location that was left unchanged.
type FixSkip struct {
	ID         string `json:"id"`
	Line       int    `json:"line"` // line in the original file (0 = unknown)
	Path       string `json:"path"`
	Reason     string `json:"reason"`      // fix.Reason* code
	ReasonText string `json:"reason_text"` // display text of Reason
}

// FixResult is the rendered result of `fix`: the JSON output of the CLI and
// the value returned to the GUI.
type FixResult struct {
	File             string     `json:"file"`
	Output           string     `json:"output"` // written path, or the path it would be written to
	Written          bool       `json:"written"`
	NotWrittenReason string     `json:"not_written_reason"` // NotWritten* code; "" when written
	Edits            []fix.Edit `json:"edits"`
	Skipped          []FixSkip  `json:"skipped"`
	Diff             []fix.Hunk `json:"diff"`
	Before           Summary    `json:"before"` // findings of the config
	After            Summary    `json:"after"`  // findings of the fixed text
	// Remaining are the findings of the fixed text. When there are edits,
	// their locations in the config refer to the fixed text and carry
	// Output as file name.
	Remaining []FindingView `json:"remaining"`
}

// BuildFixResult renders the outcome of a fix. plan may be nil (nothing to
// fix); before and after must be sorted (analyze.SortFindings); written
// tells whether the fixed text was saved to output.
func BuildFixResult(file, output string, plan *fix.Plan, before, after []model.Finding, written bool) FixResult {
	r := FixResult{
		File: file, Output: output, Written: written,
		Edits: []fix.Edit{}, Skipped: []FixSkip{}, Diff: []fix.Hunk{}, Remaining: []FindingView{},
		Before: summarize(before), After: summarize(after),
	}
	changed := plan != nil && len(plan.Edits) > 0
	if plan != nil {
		r.Edits = append(r.Edits, plan.Edits...)
		r.Diff = append(r.Diff, plan.Hunks...)
		for _, s := range plan.Skips {
			r.Skipped = append(r.Skipped, FixSkip{ID: s.ID, Line: s.Line, Path: s.Path, Reason: s.Reason, ReasonText: zh(fixSkipZh, s.Reason)})
		}
	}
	switch {
	case written:
	case changed:
		r.NotWrittenReason = NotWrittenDryRun
	default:
		r.NotWrittenReason = NotWrittenNothing
	}
	for _, f := range after {
		if changed {
			f = relocate(f, file, output)
		}
		r.Remaining = append(r.Remaining, toFindingView(f))
	}
	return r
}

// relocate returns f with its locations in file renamed to output (a copy;
// f's own slice is not modified).
func relocate(f model.Finding, file, output string) model.Finding {
	locs := make([]model.Location, len(f.Locations))
	for i, l := range f.Locations {
		if l.File == file {
			l.File = output
		}
		locs[i] = l
	}
	f.Locations = locs
	return f
}

// WriteFix renders the result of `fix`.
func WriteFix(w io.Writer, format string, r FixResult) error {
	if format == FormatJSON {
		return writeJSON(w, r)
	}
	return writeFixText(w, r)
}

func writeFixText(w io.Writer, r FixResult) error {
	var b strings.Builder
	b.WriteString(fmt.Sprintf(labelFixHeader, r.File) + "\n\n")

	if len(r.Edits) == 0 {
		b.WriteString(labelFixNoEdits + "\n\n")
	} else {
		b.WriteString(fmt.Sprintf(labelFixEdits, len(r.Edits)) + "\n")
		for _, e := range r.Edits {
			b.WriteString("  " + e.ID + "  " + locString(model.Location{File: r.File, Line: e.Line, Path: e.Path}) + "\n")
			b.WriteString("    " + labelFixBefore + strings.TrimSpace(e.Before) + "\n")
			after := labelFixDeleted
			if e.After != "" {
				after = strings.TrimSpace(e.After)
			}
			b.WriteString("    " + labelFixAfter + after + "\n")
		}
		b.WriteString("\n")
	}

	if len(r.Skipped) > 0 {
		b.WriteString(fmt.Sprintf(labelFixSkipped, len(r.Skipped)) + "\n")
		for _, s := range r.Skipped {
			loc := s.Path
			if s.Reason != fix.ReasonOtherFile {
				// Other-file lines belong to another file (a rule-set).
				loc = locString(model.Location{File: r.File, Line: s.Line, Path: s.Path})
				if s.Line > 0 && s.Path != "" {
					loc += "  " + s.Path
				}
			}
			b.WriteString("  " + s.ID + "  " + loc + "\n")
			b.WriteString("    " + labelFixReason + s.ReasonText + "\n")
		}
		b.WriteString("\n")
	}

	if len(r.Diff) > 0 {
		b.WriteString(labelFixDiff + "\n")
		b.WriteString(fix.Unified(r.File, r.Output, r.Diff))
		b.WriteString("\n")
	}

	if len(r.Edits) == 0 {
		b.WriteString(labelFixUnchanged + "\n\n")
		writeFindingsText(&b, r.Remaining)
		b.WriteString(summaryLine(labelSummary, r.After) + "\n\n")
	} else {
		b.WriteString(labelFixRemaining + "\n\n")
		writeFindingsText(&b, r.Remaining)
		b.WriteString(summaryLine(labelFixSummaryPre, r.Before) + "\n")
		b.WriteString(summaryLine(labelFixSummaryPost, r.After) + "\n\n")
	}

	switch {
	case r.Written:
		b.WriteString(fmt.Sprintf(labelFixWritten, r.Output) + "\n")
	case r.NotWrittenReason == NotWrittenDryRun:
		b.WriteString(fmt.Sprintf(fixNotWrittenZh[NotWrittenDryRun], r.Output) + "\n")
	default:
		b.WriteString(zh(fixNotWrittenZh, r.NotWrittenReason) + "\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}
