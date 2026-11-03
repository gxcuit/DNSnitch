package report

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

	"dnsleak/internal/model"
)

func TestExitCode(t *testing.T) {
	for _, c := range []struct {
		sev  model.Severity
		want int
	}{{model.Info, 0}, {model.Low, 0}, {model.Medium, 1}, {model.High, 1}, {model.Error, 1}} {
		if got := ExitCode([]model.Finding{{Severity: c.sev}}); got != c.want {
			t.Errorf("%v: %d", c.sev, got)
		}
	}
	if ExitCode(nil) != 0 {
		t.Errorf("empty")
	}
}

func TestEveryIDHasText(t *testing.T) {
	ids := []string{"CFG-01", "CFG-02", "CFG-03", "DNS-01", "DNS-02", "DNS-04", "DNS-05", "DNS-06", "DNS-07", "DNS-08", "DNS-09",
		"RULE-01", "RULE-02", "RULE-03", "RULE-04", "RULE-05", "RULE-06"}
	for _, id := range ids {
		f := model.Finding{ID: id, Args: model.Args{}}
		if findingMessage(f) == id || findingFix(f) == "" {
			t.Errorf("%s has no message / fix", id)
		}
	}
}

func TestJSONAndText(t *testing.T) {
	fs := []model.Finding{
		{ID: "DNS-02", Severity: model.Medium, Args: model.Args{"servers": "8.8.8.8"},
			Locations: []model.Location{{File: "c.yaml", Line: 5, Text: "8.8.8.8", Role: model.RoleResolver}}},
		{ID: "RULE-06", Severity: model.Info, Args: model.Args{"kind": "default"},
			Locations: []model.Location{{File: "c.yaml", Path: "rules", Role: model.RoleConfig}},
			Notes:     []model.Note{{Key: "system-proxy-scope"}}},
	}
	var buf bytes.Buffer
	if err := WriteCheck(&buf, FormatJSON, "c.yaml", fs); err != nil {
		t.Fatal(err)
	}
	var out struct {
		Findings []map[string]any `json:"findings"`
		Summary  map[string]int   `json:"summary"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 2 || out.Findings[0]["severity"] != "medium" || out.Summary["info"] != 1 {
		t.Errorf("json = %s", buf.String())
	}
	for _, k := range []string{"id", "severity", "message", "locations", "fix", "notes"} {
		if _, ok := out.Findings[0][k]; !ok {
			t.Errorf("missing key %s", k)
		}
	}

	buf.Reset()
	if err := WriteCheck(&buf, FormatText, "c.yaml", fs); err != nil {
		t.Fatal(err)
	}
	text := buf.String()
	for _, want := range []string{"[中] DNS-02  c.yaml:5", "[提示] RULE-06", "c.yaml (rules, 行号未知)", "汇总：错误 0，高 0，中 1，低 0，提示 1"} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "\r") {
		t.Errorf("output must use \\n only")
	}
}

// TestProseOnlyInMessages enforces that user-facing Chinese text lives in
// messages_zh.go (implement.md review point).
func TestProseOnlyInMessages(t *testing.T) {
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".trellis", ".claude", "docs", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") || d.Name() == "messages_zh.go" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(data), "\n") {
			code := line
			if idx := strings.Index(code, "//"); idx >= 0 {
				code = code[:idx]
			}
			for _, r := range code {
				if unicode.Is(unicode.Han, r) {
					t.Errorf("%s:%d contains Chinese text outside messages_zh.go: %s", path, i+1, strings.TrimSpace(line))
					break
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestResolverWordingAndAnnotation(t *testing.T) {
	base := model.Args{"kind": "always", "scope": "both", "trigger": "GEOIP,CN,DIRECT", "count": "2", "match": "MATCH,PROXY", "level": "plain"}
	for _, id := range []string{"RULE-01", "RULE-02", "RULE-03", "RULE-04"} {
		uniform := model.Args{"mixed": "false"}
		mixed := model.Args{"mixed": "true"}
		for k, v := range base {
			uniform[k], mixed[k] = v, v
		}
		u := findingMessage(model.Finding{ID: id, Args: uniform})
		m := findingMessage(model.Finding{ID: id, Args: mixed})
		if !strings.Contains(u, "会先发给明文 DNS") || strings.Contains(u, "最差") {
			t.Errorf("%s uniform: %s", id, u)
		}
		if !strings.Contains(m, "其中最差的情况会发给明文 DNS") {
			t.Errorf("%s mixed: %s", id, m)
		}
	}
	if msg := findingMessage(model.Finding{ID: "DNS-04", Args: model.Args{"key": "geosite:x", "level": "plain"}}); !strings.Contains(msg, "交给明文 DNS 解析") {
		t.Errorf("DNS-04 spacing: %s", msg)
	}

	fs := []model.Finding{{
		ID: "RULE-01", Severity: model.High, Args: base,
		Locations: []model.Location{
			{File: "c.yaml", Line: 3, Text: "GEOIP,CN,DIRECT", Role: model.RoleTrigger},
			{File: "c.yaml", Line: 4, Text: "DOMAIN-SUFFIX,google.com,PROXY", Role: model.RoleAffected,
				Resolver: &model.ResolverInfo{Level: "cn", Source: model.ResolverNameserver}},
			{File: "c.yaml", Line: 5, Text: "GEOSITE,gfw,PROXY", Role: model.RoleAffected,
				Resolver: &model.ResolverInfo{Level: "plain", Source: model.ResolverPolicy, PolicyKey: "geosite:gfw"}},
		},
	}}
	var buf bytes.Buffer
	if err := WriteCheck(&buf, FormatText, "c.yaml", fs); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"c.yaml:4  DOMAIN-SUFFIX,google.com,PROXY  → 国内加密 DNS（nameserver）",
		"c.yaml:5  GEOSITE,gfw,PROXY  → 明文 DNS（nameserver-policy: geosite:gfw）",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("text lacks %q:\n%s", want, buf.String())
		}
	}
	buf.Reset()
	if err := WriteCheck(&buf, FormatJSON, "c.yaml", fs); err != nil {
		t.Fatal(err)
	}
	var out struct {
		Findings []struct {
			Locations []struct {
				Resolver *struct {
					Level     string `json:"level"`
					Source    string `json:"source"`
					PolicyKey string `json:"policy_key"`
				} `json:"resolver"`
			} `json:"locations"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	locs := out.Findings[0].Locations
	if locs[0].Resolver != nil || locs[1].Resolver.Level != "cn" || locs[2].Resolver.PolicyKey != "geosite:gfw" {
		t.Errorf("json = %s", buf.String())
	}
}
