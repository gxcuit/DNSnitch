package fix

import (
	"os"
	"path/filepath"
	"testing"

	"dnsnitch/internal/config"
)

// Every repository config: Build succeeds, the result loads without new
// errors, edit lines match, and every fixable finding is accounted for.
func TestAllFixtures(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("..", "..", "testdata", "*.yaml"))
	examples, _ := filepath.Glob(filepath.Join("..", "..", "examples", "*.yaml"))
	for _, file := range append(files, examples...) {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if config.IsEncrypted(data) {
			continue
		}
		check := realCheck(file, filepath.Dir(file))
		before, err := check(data)
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		p, err := Build(file, data, check)
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		after, err := check(p.Fixed)
		if err != nil {
			t.Fatalf("%s: fixed text does not load: %v", file, err)
		}
		if _, added := NewError(before, after); added {
			t.Errorf("%s: new error findings %s", file, ids(after))
		}
		assertEditLines(t, p)
		assertCovered(t, before, after, p)
	}
}

// FuzzBuild: Build never panics, and when it changes the text the result
// still loads and the edit records match both texts.
func FuzzBuild(f *testing.F) {
	for _, tc := range buildCases() {
		f.Add(tc.in)
	}
	home := f.TempDir()
	f.Fuzz(func(t *testing.T, in string) {
		check := realCheck("cfg.yaml", home)
		if _, err := check([]byte(in)); err != nil {
			return
		}
		p, err := Build("cfg.yaml", []byte(in), check)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		if len(p.Edits) > 0 {
			if _, err := check(p.Fixed); err != nil {
				t.Fatalf("fixed text does not load: %v\n%s", err, p.Fixed)
			}
		}
		assertEditLines(t, p)
	})
}
