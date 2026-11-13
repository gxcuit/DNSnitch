package fix

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"dnsnitch/internal/config"
)

func parseDoc(t *testing.T, data string) (*config.Doc, *source) {
	t.Helper()
	d, err := config.Nodes([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	return d, newSource([]byte(data), d.BOM)
}

func walkNodes(n *yaml.Node, f func(*yaml.Node)) {
	if n == nil {
		return
	}
	f(n)
	for _, c := range n.Content {
		walkNodes(c, f)
	}
}

// offset() must land on the first character of every plain scalar, whatever
// precedes it on the line (multibyte text, emoji) and whatever the line
// terminators (CRLF) or BOM.
func TestOffsetMatchesYAMLColumns(t *testing.T) {
	body := "# 注释 \U0001F3AF\n" +
		"名字: {a: 中文, b: [\U0001F3AF 全球直连, x, 'y', \"z\"]}\n" +
		"rules:\n" +
		"  - GEOIP,private,\U0001F3AF 全球直连\n" +
		"  - 'DOMAIN,例子.com,\U0001F680 代理'   # 注释\n" +
		"list: [ é, ü ,  ß]\n"
	for _, variant := range []struct{ name, data string }{
		{"lf", body},
		{"crlf", strings.ReplaceAll(body, "\n", "\r\n")},
		{"bom", "\xef\xbb\xbf" + body},
		{"bom crlf", "\xef\xbb\xbf" + strings.ReplaceAll(body, "\n", "\r\n")},
	} {
		t.Run(variant.name, func(t *testing.T) {
			d, src := parseDoc(t, variant.data)
			count := 0
			walkNodes(d.Root, func(n *yaml.Node) {
				if n.Kind != yaml.ScalarNode {
					return
				}
				ext, reason := src.scalar(n)
				if reason != "" {
					t.Errorf("%q at %d:%d: %s", n.Value, n.Line, n.Column, reason)
					return
				}
				inner := variant.data[ext.inner[0]:ext.inner[1]]
				if inner != n.Value || !ext.identity {
					t.Errorf("%q at %d:%d: text %q", n.Value, n.Line, n.Column, inner)
				}
				count++
			})
			if count < 15 {
				t.Errorf("only %d scalars checked", count)
			}
		})
	}
}

func TestScalarSpans(t *testing.T) {
	tests := []struct {
		name     string
		doc      string
		path     string
		outer    string // text of the whole token
		identity bool
		reason   string
	}{
		{"plain", "a: hello world # c\n", "a", "hello world", true, ""},
		{"plain key", "nameserver-police:\n  x: 1\n", "nameserver-police", "nameserver-police", true, ""},
		{"single", "a: 'it''s' # c\n", "a", "'it''s'", false, ""},
		{"single plain text", "a: 'abc'\n", "a", "'abc'", true, ""},
		{"double escapes", "a: \"tab\\there\\x2F\"\n", "a", "\"tab\\there\\x2F\"", false, ""},
		{"double plain text", "a: \"a,b\"\n", "a", "\"a,b\"", true, ""},
		{"double with quote", "a: \"say \\\"hi\\\"\"\n", "a", "\"say \\\"hi\\\"\"", false, ""},
		{"literal", "a: |-\n  x\n", "a", "", false, ReasonMultiline},
		{"folded", "a: >\n  x\n", "a", "", false, ReasonMultiline},
		{"multi-line plain", "a: x,\n  y\n", "a", "", false, ReasonMultiline},
		{"multi-line single", "a: 'x\n  y'\n", "a", "", false, ReasonMultiline},
		{"multi-line double", "a: \"x\n  y\"\n", "a", "", false, ReasonMultiline},
		{"tagged", "a: !!str 8.8.8.8\n", "a", "", false, ReasonLayout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, src := parseDoc(t, tt.doc)
			tg, err := d.Find(tt.path)
			if err != nil {
				t.Fatal(err)
			}
			n := tg.Node
			if tt.name == "plain key" {
				n = tg.Key
			}
			ext, reason := src.scalar(n)
			if reason != tt.reason {
				t.Fatalf("reason = %q, want %q", reason, tt.reason)
			}
			if reason != "" {
				return
			}
			if got := tt.doc[ext.outer[0]:ext.outer[1]]; got != tt.outer {
				t.Errorf("outer = %q, want %q", got, tt.outer)
			}
			if ext.identity != tt.identity {
				t.Errorf("identity = %v", ext.identity)
			}
		})
	}
}

func TestFlowList(t *testing.T) {
	tests := []struct {
		doc    string
		rng    string
		items  []string
		reason string
	}{
		{"a: [x, 'y', \"z\"]  # c\n", "[x, 'y', \"z\"]", []string{"x", "'y'", "\"z\""}, ""},
		{"a: [ x ,y, ]\n", "[ x ,y, ]", []string{"x", "y"}, ""},
		{"a: []\n", "[]", nil, ""},
		{"a: [x,\n  y]\n", "", nil, ReasonMultiline},
		{"a: [x\n  ]\n", "", nil, ReasonMultiline},
		{"b: &b x\na: [*b, y]\n", "", nil, ReasonSharedNode},
	}
	for _, tt := range tests {
		d, src := parseDoc(t, tt.doc)
		tg, err := d.Find("a")
		if err != nil {
			t.Fatal(err)
		}
		rng, items, reason := src.flowList(tg.Node)
		if reason != tt.reason {
			t.Errorf("%q: reason %q, want %q", tt.doc, reason, tt.reason)
			continue
		}
		if reason != "" {
			continue
		}
		if got := tt.doc[rng[0]:rng[1]]; got != tt.rng {
			t.Errorf("%q: range %q", tt.doc, got)
		}
		if strings.Join(items, "|") != strings.Join(tt.items, "|") {
			t.Errorf("%q: items %q", tt.doc, items)
		}
	}
}

func TestBlockItemLineAndColon(t *testing.T) {
	doc := "ns:\n" +
		"  - a\n" +
		"  -   'b'   # c\r\n" +
		"  - - c\n" +
		"  -\n" +
		"    d\n" +
		"fb:   # comment\n" +
		"  - e\n" +
		"tg: !!seq\n" +
		"  - f\n" +
		"last:\n" +
		"- g"
	d, src := parseDoc(t, doc)
	line := func(path string) (string, string) {
		tg, err := d.Find(path)
		if err != nil {
			t.Fatal(err)
		}
		ext, reason := src.scalar(tg.Node)
		if reason != "" {
			return "", reason
		}
		s, n, reason := src.blockItemLine(tg.Node, ext)
		return doc[s:n], reason
	}
	for _, tt := range []struct{ path, want, reason string }{
		{"ns[0]", "  - a\n", ""},
		{"ns[1]", "  -   'b'   # c\r\n", ""},
		{"ns[2][0]", "", ReasonLayout},
		{"ns[3]", "", ReasonLayout},
		{"last[0]", "- g", ""},
	} {
		got, reason := line(tt.path)
		if got != tt.want || reason != tt.reason {
			t.Errorf("%s: %q %q, want %q %q", tt.path, got, reason, tt.want, tt.reason)
		}
	}
	for _, tt := range []struct{ path, after, reason string }{
		{"fb", "   # comment\n", ""},
		{"ns", "\n", ""},
		{"tg", "", ReasonLayout},
	} {
		tg, err := d.Find(tt.path)
		if err != nil {
			t.Fatal(err)
		}
		at, reason := src.afterColon(tg.Key)
		if reason != tt.reason {
			t.Errorf("%s: reason %q", tt.path, reason)
			continue
		}
		if reason == "" && !strings.HasPrefix(doc[at:], tt.after) {
			t.Errorf("%s: after colon %q", tt.path, doc[at:at+5])
		}
	}
}

func TestApply(t *testing.T) {
	data := []byte("0123456789")
	got, err := apply(data, []repl{{8, 10, "x"}, {1, 1, "+"}, {3, 5, ""}})
	if err != nil || string(got) != "0+12567x" {
		t.Errorf("apply = %q, %v", got, err)
	}
	if _, err := apply(data, []repl{{1, 4, "a"}, {3, 5, "b"}}); err == nil {
		t.Error("overlap accepted")
	}
	if _, err := apply(data, []repl{{2, 2, "a"}, {2, 2, "b"}}); err == nil {
		t.Error("two insertions at one offset accepted")
	}
	if !overlaps(repl{2, 2, ""}, []repl{{2, 4, ""}}) || overlaps(repl{4, 5, ""}, []repl{{2, 4, ""}}) {
		t.Error("overlaps")
	}
}

func TestHasNoResolve(t *testing.T) {
	if !hasNoResolve([]string{"src", " NO-RESOLVE"}) || hasNoResolve([]string{"no-resolve-x"}) || hasNoResolve(nil) {
		t.Error("hasNoResolve")
	}
}
