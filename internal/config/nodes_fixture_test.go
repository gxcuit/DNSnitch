package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dnsnitch/internal/analyze"
	"dnsnitch/internal/config"
	"dnsnitch/internal/model"
)

// Every location path that Parse / analyze report for the config itself
// must resolve with Doc.Find to a node on the same line.
func TestFindResolvesFixtureLocations(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "testdata", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	examples, _ := filepath.Glob(filepath.Join("..", "..", "examples", "*.yaml"))
	files = append(files, examples...)
	checked := 0
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if config.IsEncrypted(data) {
			continue
		}
		cfg, err := config.Parse(file, data)
		if err != nil {
			t.Errorf("%s: %v", file, err)
			continue
		}
		fs := analyze.NewEnv(cfg, t.TempDir()).Check()
		doc, err := config.Nodes(data)
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		var locs []model.Location
		for _, f := range fs {
			locs = append(locs, f.Locations...)
		}
		for _, r := range cfg.Rules {
			locs = append(locs, r.Loc)
		}
		for _, l := range cfg.UnknownKeys {
			locs = append(locs, l.Loc)
		}
		for _, loc := range locs {
			if loc.File != file || loc.Path == "" || loc.Line == 0 {
				continue
			}
			tg, err := doc.Find(loc.Path)
			if errors.Is(err, config.ErrNotFound) && (loc.Path == "dns.nameserver" || loc.Path == "dns.default-nameserver") {
				continue // built-in default servers, located at the dns key
			}
			if err != nil {
				t.Errorf("%s: Find(%q): %v", file, loc.Path, err)
				continue
			}
			line := tg.Node.Line
			if !strings.HasSuffix(loc.Path, "]") && tg.Key != nil {
				line = tg.Key.Line
			}
			if line != loc.Line {
				t.Errorf("%s: Find(%q) line %d, location line %d", file, loc.Path, line, loc.Line)
			}
			checked++
		}
	}
	if checked < 50 {
		t.Errorf("only %d locations checked", checked)
	}
}
