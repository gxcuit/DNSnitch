package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
)

// TestProseOnlyInMessages mirrors the root-module test of the same name:
// user-facing text of the GUI's Go code must come from
// internal/report/messages_zh.go, never from gui/*.go.
func TestProseOnlyInMessages(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
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
	}
}
