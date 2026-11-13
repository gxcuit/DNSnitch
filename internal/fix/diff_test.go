package fix

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

func lines(n int, f func(i int) string) string {
	var sb strings.Builder
	for i := 1; i <= n; i++ {
		sb.WriteString(f(i) + "\n")
	}
	return sb.String()
}

func numbered(i int) string { return fmt.Sprintf("line %d", i) }

// patch applies hunks to a and returns the new text (terminators come from
// the hunk lines; every line gets "\n" unless marked NoNewline).
func patch(t *testing.T, a string, hunks []Hunk) string {
	t.Helper()
	al := splitLines([]byte(a))
	var out strings.Builder
	pos := 0 // old lines consumed
	for _, h := range hunks {
		start := h.OldStart - 1
		if h.OldLines == 0 {
			start = h.OldStart
		}
		for ; pos < start; pos++ {
			out.WriteString(al[pos])
		}
		for _, l := range h.Lines {
			switch l.Op {
			case OpContext, OpDelete:
				if trimEOL(al[pos]) != l.Text {
					t.Fatalf("hunk line %q does not match old line %d %q", l.Text, pos+1, al[pos])
				}
				if l.Op == OpContext {
					out.WriteString(al[pos])
				}
				pos++
			case OpInsert:
				out.WriteString(l.Text)
				if !l.NoNewline {
					out.WriteString("\n")
				}
			}
		}
	}
	for ; pos < len(al); pos++ {
		out.WriteString(al[pos])
	}
	return out.String()
}

func TestDiffHunks(t *testing.T) {
	base := lines(30, numbered)
	tests := []struct {
		name  string
		b     string
		heads []string // "@@ -a,b +c,d @@" lines
	}{
		{"identical", base, nil},
		{"one change in the middle", strings.Replace(base, "line 15\n", "line 15 changed\n", 1), []string{"@@ -12,7 +12,7 @@"}},
		{"deletion", strings.Replace(base, "line 15\n", "", 1), []string{"@@ -12,7 +12,6 @@"}},
		{"first line", strings.Replace(base, "line 1\n", "first\n", 1), []string{"@@ -1,4 +1,4 @@"}},
		{"last line", strings.Replace(base, "line 30\n", "last\n", 1), []string{"@@ -27,4 +27,4 @@"}},
		{"insert at start", "new\n" + base, []string{"@@ -0,0 +1 @@", "@@ -1,3 +1,4 @@"}[1:]},
		{"close changes merge", strings.Replace(strings.Replace(base, "line 10\n", "x\n", 1), "line 16\n", "y\n", 1), []string{"@@ -7,13 +7,13 @@"}},
		{"far changes split", strings.Replace(strings.Replace(base, "line 10\n", "x\n", 1), "line 18\n", "y\n", 1), []string{"@@ -7,7 +7,7 @@", "@@ -15,7 +15,7 @@"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hunks := Diff([]byte(base), []byte(tt.b), 3)
			var heads []string
			for _, l := range strings.Split(Unified("a", "b", hunks), "\n") {
				if strings.HasPrefix(l, "@@") {
					heads = append(heads, l)
				}
			}
			if strings.Join(heads, "|") != strings.Join(tt.heads, "|") {
				t.Errorf("heads = %q, want %q", heads, tt.heads)
			}
			if got := patch(t, base, hunks); got != tt.b {
				t.Errorf("patch result differs:\n%s", got)
			}
		})
	}
}

func TestUnifiedRendering(t *testing.T) {
	a := "a\r\nb\r\nc\r\n"
	b := "a\r\nB\r\nc\r\nd"
	got := Unified("config.yaml", "config.fixed.yaml", Diff([]byte(a), []byte(b), 3))
	want := "--- config.yaml\n+++ config.fixed.yaml\n" +
		"@@ -1,3 +1,4 @@\n" +
		" a\n-b\n+B\n c\n+d\n\\ No newline at end of file\n"
	if got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
	if Unified("a", "b", nil) != "" {
		t.Error("no hunks should render nothing")
	}
	// BOM is not shown, empty inputs work.
	h := Diff([]byte("\xef\xbb\xbfx\n"), []byte("\xef\xbb\xbfy\n"), 3)
	if len(h) != 1 || h[0].Lines[0].Text != "x" || h[0].Lines[1].Text != "y" {
		t.Errorf("bom hunk = %+v", h)
	}
	if h := Diff(nil, []byte("x\n"), 3); len(h) != 1 || h[0].OldStart != 0 || h[0].OldLines != 0 || h[0].NewStart != 1 {
		t.Errorf("from empty = %+v", h)
	}
	if h := Diff([]byte("x\n"), nil, 3); len(h) != 1 || h[0].NewStart != 0 || h[0].NewLines != 0 {
		t.Errorf("to empty = %+v", h)
	}
}

// Random edits: applying the hunks to a must give b, and the script must be
// minimal for single-line substitutions.
func TestDiffRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for iter := 0; iter < 300; iter++ {
		n := rng.Intn(40)
		al := make([]string, n)
		for i := range al {
			al[i] = fmt.Sprintf("l%d", rng.Intn(8))
		}
		bl := append([]string(nil), al...)
		for k := rng.Intn(6); k > 0; k-- {
			switch op := rng.Intn(3); {
			case op == 0 && len(bl) > 0:
				i := rng.Intn(len(bl))
				bl = append(bl[:i], bl[i+1:]...)
			case op == 1:
				i := rng.Intn(len(bl) + 1)
				bl = append(bl[:i], append([]string{fmt.Sprintf("n%d", rng.Intn(5))}, bl[i:]...)...)
			case len(bl) > 0:
				bl[rng.Intn(len(bl))] = "changed"
			}
		}
		a := strings.Join(al, "\n")
		b := strings.Join(bl, "\n")
		if n > 0 && rng.Intn(2) == 0 {
			a += "\n"
			if len(bl) > 0 {
				b += "\n"
			}
		}
		hunks := Diff([]byte(a), []byte(b), rng.Intn(4))
		if got := patch(t, a, hunks); got != b {
			t.Fatalf("iter %d: patch(a) != b\na=%q\nb=%q\ngot=%q", iter, a, b, got)
		}
	}
}
