package fix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dnsnitch/internal/analyze"
	"dnsnitch/internal/config"
	"dnsnitch/internal/model"
)

// realCheck is the CheckFunc the app uses: config.Parse + analyze.
func realCheck(file, home string) CheckFunc {
	return func(data []byte) ([]model.Finding, error) {
		cfg, err := config.Parse(file, data)
		if err != nil {
			return nil, err
		}
		fs := analyze.NewEnv(cfg, home).Check()
		analyze.SortFindings(fs)
		return fs, nil
	}
}

// head declares the policies used by inline test configs.
const head = "proxies:\n" +
	"  - {name: hk, type: ss, server: a.example.com, port: 1, cipher: x, password: y}\n" +
	"proxy-groups:\n" +
	"  - {name: PROXY, type: select, proxies: [hk]}\n"

// build runs Build on inline config text with the real analyzer.
func build(t *testing.T, text string) *Plan {
	t.Helper()
	p, err := Build("cfg.yaml", []byte(text), realCheck("cfg.yaml", t.TempDir()))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return p
}

func buildFile(t *testing.T, file string) *Plan {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Build(file, data, realCheck(file, filepath.Dir(file)))
	if err != nil {
		t.Fatalf("Build(%s): %v", file, err)
	}
	return p
}

func ids(fs []model.Finding) string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return strings.Join(out, " ")
}

func hasID(fs []model.Finding, id string) bool {
	for _, f := range fs {
		if f.ID == id {
			return true
		}
	}
	return false
}

func skipReasons(p *Plan) map[string]string {
	m := map[string]string{}
	for _, s := range p.Skips {
		m[s.ID+"@"+s.Path] = s.Reason
	}
	return m
}

func fixture(name string) string { return filepath.Join("..", "..", "testdata", name) }
