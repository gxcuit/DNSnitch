package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"dnsnitch/internal/fix"
	"dnsnitch/internal/model"
)

func samplePlan() *fix.Plan {
	orig := []byte("rules:\n  - GEOIP,CN,DIRECT\n  - MATCH,PROXY\ndns:\n  nameserver:\n    - 8.8.8.8\n    - https://doh.pub/dns-query\n")
	fixed := []byte("rules:\n  - GEOIP,CN,DIRECT,no-resolve\n  - MATCH,PROXY\ndns:\n  nameserver:\n    - https://doh.pub/dns-query\n")
	return &fix.Plan{
		Original: orig, Fixed: fixed,
		Edits: []fix.Edit{
			{ID: "RULE-01", Line: 2, Path: "rules[0]", Before: "  - GEOIP,CN,DIRECT", After: "  - GEOIP,CN,DIRECT,no-resolve"},
			{ID: "DNS-02", Line: 6, Path: "dns.nameserver[0]", Before: "    - 8.8.8.8"},
		},
		Skips: []fix.Skip{{ID: "RULE-01", Line: 9, Path: "rules[3]", Reason: fix.ReasonMultiline}},
		Hunks: fix.Diff(orig, fixed, 3),
	}
}

var (
	beforeFindings = []model.Finding{
		{ID: "RULE-01", Severity: model.High, Args: model.Args{"kind": "always"},
			Locations: []model.Location{{File: "c.yaml", Line: 2, Path: "rules[0]", Role: model.RoleTrigger}}},
		{ID: "DNS-02", Severity: model.Medium,
			Locations: []model.Location{{File: "c.yaml", Line: 6, Path: "dns.nameserver[0]", Role: model.RoleResolver}}},
	}
	afterFindings = []model.Finding{
		{ID: "RULE-05", Severity: model.Low,
			Locations: []model.Location{
				{File: "c.yaml", Line: 2, Text: "GEOIP,CN,DIRECT,no-resolve", Role: model.RoleConfig},
				{File: "set.yaml", Line: 1, Role: model.RoleRelated},
			}},
	}
)

func TestBuildFixResult(t *testing.T) {
	p := samplePlan()
	r := BuildFixResult("c.yaml", "c.fixed.yaml", p, beforeFindings, afterFindings, false)
	if r.Written || r.NotWrittenReason != NotWrittenDryRun || len(r.Edits) != 2 || len(r.Diff) != 1 {
		t.Errorf("dry run = %+v", r)
	}
	if r.Before.High != 1 || r.Before.Medium != 1 || r.After.Low != 1 || r.After.High != 0 {
		t.Errorf("summaries = %+v / %+v", r.Before, r.After)
	}
	if len(r.Skipped) != 1 || r.Skipped[0].Reason != fix.ReasonMultiline || r.Skipped[0].ReasonText != fixSkipZh[fix.ReasonMultiline] {
		t.Errorf("skipped = %+v", r.Skipped)
	}
	// Remaining locations in the config refer to the fixed text.
	locs := r.Remaining[0].Locations
	if locs[0].File != "c.fixed.yaml" || locs[1].File != "set.yaml" {
		t.Errorf("remaining locations = %+v", locs)
	}
	if afterFindings[0].Locations[0].File != "c.yaml" {
		t.Error("BuildFixResult modified its input")
	}

	if r := BuildFixResult("c.yaml", "c.fixed.yaml", p, beforeFindings, afterFindings, true); !r.Written || r.NotWrittenReason != "" {
		t.Errorf("written = %+v", r)
	}

	// Nothing to fix: findings keep the config's name, empty arrays.
	for _, plan := range []*fix.Plan{nil, {Original: p.Original, Fixed: p.Original}} {
		r := BuildFixResult("c.yaml", "c.fixed.yaml", plan, beforeFindings, beforeFindings, false)
		if r.NotWrittenReason != NotWrittenNothing || r.Edits == nil || r.Skipped == nil || r.Diff == nil || len(r.Edits) != 0 {
			t.Errorf("nothing to fix = %+v", r)
		}
		if r.Remaining[0].Locations[0].File != "c.yaml" || !r.Remaining[0].AutoFix {
			t.Errorf("remaining = %+v", r.Remaining)
		}
	}
}

func TestWriteFixJSON(t *testing.T) {
	var buf bytes.Buffer
	r := BuildFixResult("c.yaml", "c.fixed.yaml", samplePlan(), beforeFindings, afterFindings, false)
	if err := WriteFix(&buf, FormatJSON, r); err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"file", "output", "written", "not_written_reason", "edits", "skipped", "diff", "before", "after", "remaining"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing key %s", k)
		}
	}
	for _, want := range []string{`"after": ""`, `"reason": "multiline"`, `"reason_text": "`, `"old_start": 1`, `"op": "-"`, `"auto_fix": false`, `"file": "c.fixed.yaml"`} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("json lacks %s:\n%s", want, buf.String())
		}
	}
}

func TestWriteFixText(t *testing.T) {
	var buf bytes.Buffer
	r := BuildFixResult("c.yaml", "c.fixed.yaml", samplePlan(), beforeFindings, afterFindings, false)
	if err := WriteFix(&buf, FormatText, r); err != nil {
		t.Fatal(err)
	}
	text := buf.String()
	order := []string{
		"自动修复：c.yaml",
		"已修改（2 处）：",
		"  RULE-01  c.yaml:2\n    修改前：- GEOIP,CN,DIRECT\n    修改后：- GEOIP,CN,DIRECT,no-resolve\n",
		"  DNS-02  c.yaml:6\n    修改前：- 8.8.8.8\n    修改后：（删除这一行）\n",
		"未自动修改（1 处）",
		"  RULE-01  c.yaml:9  rules[3]\n    原因：" + fixSkipZh[fix.ReasonMultiline],
		"差异：\n--- c.yaml\n+++ c.fixed.yaml\n@@ -1,7 +1,6 @@\n",
		"-  - GEOIP,CN,DIRECT\n+  - GEOIP,CN,DIRECT,no-resolve\n",
		"-    - 8.8.8.8\n",
		"修复后仍存在的检查结果：",
		"[低] RULE-05  c.fixed.yaml:2",
		"修复前：错误 0，高 1，中 1，低 0，提示 0\n修复后：错误 0，高 0，中 0，低 1，提示 0\n",
		"未写入：--dry-run",
		"c.fixed.yaml）。\n",
	}
	pos := 0
	for _, want := range order {
		i := strings.Index(text[pos:], want)
		if i < 0 {
			t.Fatalf("text lacks %q after offset %d:\n%s", want, pos, text)
		}
		pos += i + len(want)
	}

	buf.Reset()
	r = BuildFixResult("c.yaml", "/tmp/out.yaml", samplePlan(), beforeFindings, afterFindings, true)
	_ = WriteFix(&buf, FormatText, r)
	if !strings.HasSuffix(buf.String(), "已写入：/tmp/out.yaml（原配置文件未修改）\n") {
		t.Errorf("written text:\n%s", buf.String())
	}

	buf.Reset()
	r = BuildFixResult("c.yaml", "c.fixed.yaml", nil, afterFindings, afterFindings, false)
	_ = WriteFix(&buf, FormatText, r)
	text = buf.String()
	for _, want := range []string{labelFixNoEdits, labelFixUnchanged, "[低] RULE-05  c.yaml:2", "汇总：错误 0，高 0，中 0，低 1，提示 0", fixNotWrittenZh[NotWrittenNothing]} {
		if !strings.Contains(text, want) {
			t.Errorf("nothing-to-fix text lacks %q:\n%s", want, text)
		}
	}
	for _, unwanted := range []string{labelFixDiff, labelFixSummaryPre, "dnsnitch fix"} {
		if strings.Contains(text, unwanted) {
			t.Errorf("nothing-to-fix text has %q:\n%s", unwanted, text)
		}
	}

	// other-file skips do not claim a line of the config.
	buf.Reset()
	p := samplePlan()
	p.Skips = []fix.Skip{{ID: "RULE-04", Line: 3, Path: "payload[1]", Reason: fix.ReasonOtherFile}}
	_ = WriteFix(&buf, FormatText, BuildFixResult("c.yaml", "o.yaml", p, nil, nil, false))
	if !strings.Contains(buf.String(), "  RULE-04  payload[1]\n") || strings.Contains(buf.String(), "c.yaml:3") {
		t.Errorf("other-file skip:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "\r") {
		t.Error("output must use \\n only")
	}
}

func TestFixProse(t *testing.T) {
	for _, code := range []string{fix.ReasonSharedNode, fix.ReasonMultiline, fix.ReasonLayout, fix.ReasonKeyExists,
		fix.ReasonOtherFile, fix.ReasonRenameBreaksLoad, fix.ReasonPassLimit} {
		if fixSkipZh[code] == "" {
			t.Errorf("no text for skip reason %s", code)
		}
	}
	if len(fixSkipZh) != 7 {
		t.Errorf("unexpected skip reasons: %v", fixSkipZh)
	}
	seen := map[string]string{ErrorText(ErrKindArgs, "x"): ErrKindArgs}
	for _, k := range []string{ErrKindVerify, ErrKindSameFile, ErrKindExists, ErrKindWrite, ErrKindChanged} {
		s := ErrorText(k, "DETAIL")
		if !strings.Contains(s, "DETAIL") {
			t.Errorf("%s text drops the detail: %s", k, s)
		}
		if other, dup := seen[s]; dup {
			t.Errorf("%s has the same text as %s", k, other)
		}
		seen[s] = k
	}
	if !strings.Contains(UsageText(), "dnsnitch fix") || !strings.Contains(UsageText(), "--dry-run") {
		t.Error("usage does not describe fix")
	}
}

// check: auto_fix per finding, and the hint line after the summary.
func TestCheckAutoFix(t *testing.T) {
	fs := []model.Finding{
		{ID: "RULE-01", Severity: model.High, Args: model.Args{"kind": "always"}},
		{ID: "RULE-02", Severity: model.Info, Args: model.Args{"kind": "always"}},
		{ID: "DNS-02", Severity: model.Medium},
		{ID: "RULE-05", Severity: model.Low},
	}
	r := BuildCheckResult("c.yaml", fs)
	got := map[string]bool{}
	for _, f := range r.Findings {
		got[f.ID] = f.AutoFix
	}
	if !got["RULE-01"] || got["RULE-02"] || !got["DNS-02"] || got["RULE-05"] {
		t.Errorf("auto_fix = %v", got)
	}
	var buf bytes.Buffer
	if err := WriteCheck(&buf, FormatText, "c.yaml", fs); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(buf.String(), "汇总：错误 0，高 1，中 1，低 1，提示 1\n其中 2 项可用 dnsnitch fix 自动修复。\n") {
		t.Errorf("check text:\n%s", buf.String())
	}
	buf.Reset()
	_ = WriteCheck(&buf, FormatText, "c.yaml", fs[3:])
	if strings.Contains(buf.String(), "dnsnitch fix") {
		t.Errorf("hint without fixable findings:\n%s", buf.String())
	}
}
