package fix

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// source indexes the lines of a config text so that yaml.v3 node positions
// (1-based line, 1-based column counted in characters, both relative to the
// text after the BOM) can be turned into byte offsets of the full text.
type source struct {
	data   []byte // full text, including a leading BOM
	bom    int    // length of the BOM
	starts []int  // starts[i] is the offset of line i+1 in data
}

func newSource(data []byte, bom int) *source {
	s := &source{data: data, bom: bom, starts: []int{bom}}
	for i := bom; i < len(data); i++ {
		if data[i] == '\n' && i+1 < len(data) {
			s.starts = append(s.starts, i+1)
		}
	}
	return s
}

// line returns the offsets of a line: its start, the end of its content
// (before "\n" / "\r\n") and the start of the next line.
func (s *source) line(n int) (start, end, next int, ok bool) {
	if n < 1 || n > len(s.starts) {
		return 0, 0, 0, false
	}
	start = s.starts[n-1]
	next = len(s.data)
	if n < len(s.starts) {
		next = s.starts[n]
	}
	end = next
	if end > start && s.data[end-1] == '\n' {
		end--
	}
	if end > start && s.data[end-1] == '\r' {
		end--
	}
	return start, end, next, true
}

// offset converts a node position to a byte offset in data.
func (s *source) offset(line, col int) (int, bool) {
	start, end, _, ok := s.line(line)
	if !ok || col < 1 {
		return 0, false
	}
	pos := start
	for c := 1; c < col; c++ {
		if pos >= end {
			return 0, false
		}
		_, w := utf8.DecodeRune(s.data[pos:end])
		pos += w
	}
	return pos, true
}

// lineText returns line n without its terminator (and without a BOM).
func (s *source) lineText(n int) string {
	start, end, _, ok := s.line(n)
	if !ok {
		return ""
	}
	if n == 1 && start < s.bom {
		start = s.bom
	}
	return string(s.data[start:end])
}

// extent is where a scalar sits in the text.
type extent struct {
	outer [2]int // whole token, quotes included
	inner [2]int // the characters between the quotes (= outer for plain)
	// identity: the inner bytes equal Node.Value byte for byte (no escapes),
	// so an offset into the value is the same offset into inner.
	identity bool
}

// scalar locates the text of a single-line scalar node and verifies that
// the located text decodes to exactly Node.Value. The reason is non-empty
// when the node cannot be edited in place.
func (s *source) scalar(n *yaml.Node) (extent, string) {
	if n == nil || n.Kind != yaml.ScalarNode {
		return extent{}, ReasonLayout
	}
	if n.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		return extent{}, ReasonMultiline
	}
	if n.Style&yaml.TaggedStyle != 0 {
		return extent{}, ReasonLayout
	}
	pos, ok := s.offset(n.Line, n.Column)
	if !ok {
		return extent{}, ReasonLayout
	}
	_, end, _, _ := s.line(n.Line)
	d := s.data
	switch {
	case n.Style&yaml.DoubleQuotedStyle != 0:
		if pos >= end || d[pos] != '"' {
			return extent{}, ReasonLayout
		}
		j := pos + 1
		for ; j < end && d[j] != '"'; j++ {
			if d[j] == '\\' {
				j++
			}
		}
		if j >= end {
			return extent{}, ReasonMultiline
		}
		var v string
		if err := yaml.Unmarshal(d[pos:j+1], &v); err != nil || v != n.Value {
			return extent{}, ReasonLayout
		}
		inner := d[pos+1 : j]
		return extent{outer: [2]int{pos, j + 1}, inner: [2]int{pos + 1, j}, identity: string(inner) == n.Value}, ""
	case n.Style&yaml.SingleQuotedStyle != 0:
		if pos >= end || d[pos] != '\'' {
			return extent{}, ReasonLayout
		}
		j := pos + 1
		for ; j < end; j++ {
			if d[j] == '\'' {
				if j+1 < end && d[j+1] == '\'' {
					j++
					continue
				}
				break
			}
		}
		if j >= end {
			return extent{}, ReasonMultiline
		}
		inner := string(d[pos+1 : j])
		if strings.ReplaceAll(inner, "''", "'") != n.Value {
			return extent{}, ReasonLayout
		}
		return extent{outer: [2]int{pos, j + 1}, inner: [2]int{pos + 1, j}, identity: inner == n.Value}, ""
	case n.Style == 0:
		// A plain scalar has no escapes: on one line its text is its value.
		stop := pos + len(n.Value)
		if stop > end {
			return extent{}, ReasonMultiline
		}
		if string(d[pos:stop]) != n.Value {
			return extent{}, ReasonLayout
		}
		return extent{outer: [2]int{pos, stop}, inner: [2]int{pos, stop}, identity: true}, ""
	}
	return extent{}, ReasonLayout
}

// restIsComment reports whether b (the rest of a line) is blank or blank
// followed by a comment.
func restIsComment(b []byte) bool {
	t := bytes.TrimLeft(b, " \t")
	if len(t) == 0 {
		return true
	}
	return t[0] == '#' && len(t) < len(b)
}

// blockItemLine returns the range of the whole line (terminator included)
// holding block sequence item n, provided the line holds nothing but
// "- <item>" and an optional comment.
func (s *source) blockItemLine(n *yaml.Node, ext extent) (start, next int, reason string) {
	start, end, next, ok := s.line(n.Line)
	if !ok || ext.outer[0] < start || ext.outer[1] > end {
		return 0, 0, ReasonLayout
	}
	before := s.data[start:ext.outer[0]]
	dash := bytes.TrimRight(before, " \t")
	if len(dash) == len(before) || len(dash) == 0 || dash[len(dash)-1] != '-' {
		return 0, 0, ReasonLayout
	}
	if len(bytes.TrimLeft(dash[:len(dash)-1], " \t")) != 0 {
		return 0, 0, ReasonLayout
	}
	if !restIsComment(s.data[ext.outer[1]:end]) {
		return 0, 0, ReasonLayout
	}
	return start, next, ""
}

// afterColon returns the offset right after the ":" that follows mapping
// key k, provided nothing but blanks and an optional comment follow it on
// the line (the value is a block collection on the next lines).
func (s *source) afterColon(k *yaml.Node) (int, string) {
	ext, reason := s.scalar(k)
	if reason != "" {
		return 0, reason
	}
	_, end, _, _ := s.line(k.Line)
	j := ext.outer[1]
	for j < end && (s.data[j] == ' ' || s.data[j] == '\t') {
		j++
	}
	if j >= end || s.data[j] != ':' {
		return 0, ReasonLayout
	}
	j++
	if !restIsComment(s.data[j:end]) {
		return 0, ReasonLayout
	}
	return j, ""
}

// flowList returns the range of a single-line flow sequence "[...]" and the
// source text of each item. Items must be scalars (aliases are reported as
// shared nodes).
func (s *source) flowList(n *yaml.Node) (rng [2]int, items []string, reason string) {
	lb, ok := s.offset(n.Line, n.Column)
	_, end, _, _ := s.line(n.Line)
	if !ok || lb >= end || s.data[lb] != '[' {
		return rng, nil, ReasonLayout
	}
	j := lb + 1
	for _, c := range n.Content {
		if c.Kind == yaml.AliasNode || c.Anchor != "" {
			return rng, nil, ReasonSharedNode
		}
		if c.Line != n.Line {
			return rng, nil, ReasonMultiline
		}
		ext, reason := s.scalar(c)
		if reason != "" {
			return rng, nil, reason
		}
		if ext.outer[0] < j {
			return rng, nil, ReasonLayout
		}
		items = append(items, string(s.data[ext.outer[0]:ext.outer[1]]))
		j = ext.outer[1]
	}
	skip := func() {
		for j < end && (s.data[j] == ' ' || s.data[j] == '\t') {
			j++
		}
	}
	skip()
	if len(n.Content) > 0 && j < end && s.data[j] == ',' {
		j++
		skip()
	}
	if j >= end {
		return rng, nil, ReasonMultiline
	}
	if s.data[j] != ']' {
		return rng, nil, ReasonLayout
	}
	return [2]int{lb, j + 1}, items, ""
}

// repl replaces data[start:end] with text.
type repl struct {
	start, end int
	text       string
}

// apply returns data with all replacements applied. Replacements must not
// overlap, and two insertions at the same offset are refused because their
// order would be ambiguous.
func apply(data []byte, rs []repl) ([]byte, error) {
	rs = append([]repl(nil), rs...)
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].start < rs[j].start })
	var out bytes.Buffer
	out.Grow(len(data) + 64)
	pos := 0
	for i, r := range rs {
		if r.start < pos || r.end < r.start || r.end > len(data) {
			return nil, fmt.Errorf("overlapping or invalid edit at offset %d", r.start)
		}
		if i > 0 && r.start == rs[i-1].start && r.start == r.end && rs[i-1].start == rs[i-1].end {
			return nil, fmt.Errorf("two insertions at offset %d", r.start)
		}
		out.Write(data[pos:r.start])
		out.WriteString(r.text)
		pos = r.end
	}
	out.Write(data[pos:])
	return out.Bytes(), nil
}

// overlaps reports whether r overlaps any of rs (insertions at the same
// offset count as overlapping).
func overlaps(r repl, rs []repl) bool {
	for _, o := range rs {
		if r.start == o.start || (r.start < o.end && o.start < r.end) {
			return true
		}
	}
	return false
}

// hasNoResolve reports whether a rule parameter list already contains
// no-resolve, ignoring case.
func hasNoResolve(params []string) bool {
	for _, p := range params {
		if strings.EqualFold(strings.TrimSpace(p), "no-resolve") {
			return true
		}
	}
	return false
}

// splitLines splits data into lines, each keeping its terminator. A final
// line without terminator is kept; no empty line follows a final "\n".
func splitLines(data []byte) []string {
	var out []string
	for len(data) > 0 {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			out = append(out, string(data))
			break
		}
		out = append(out, string(data[:i+1]))
		data = data[i+1:]
	}
	return out
}

// trimEOL removes a trailing "\n" or "\r\n".
func trimEOL(l string) string {
	l = strings.TrimSuffix(l, "\n")
	return strings.TrimSuffix(l, "\r")
}

// bomText is the UTF-8 byte order mark.
const bomText = "\xef\xbb\xbf"
