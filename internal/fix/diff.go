package fix

import (
	"strconv"
	"strings"
)

// Diff line operations.
const (
	OpContext = " "
	OpDelete  = "-"
	OpInsert  = "+"
)

// DiffLine is one line of a hunk.
type DiffLine struct {
	Op   string `json:"op"`   // OpContext, OpDelete or OpInsert
	Text string `json:"text"` // the line without its terminator
	// NoNewline marks the last line of a file that has no terminator.
	NoNewline bool `json:"no_newline,omitempty"`
}

// Hunk is a group of changed lines with context, in unified diff terms:
// OldStart / NewStart are 1-based; for an empty range they are the number
// of the line before it (0 at the start of the file).
type Hunk struct {
	OldStart int        `json:"old_start"`
	OldLines int        `json:"old_lines"`
	NewStart int        `json:"new_start"`
	NewLines int        `json:"new_lines"`
	Lines    []DiffLine `json:"lines"`
}

// diffOp is one step of an edit script; a and b are the numbers of old and
// new lines consumed before it.
type diffOp struct {
	op   string
	a, b int
}

// Diff compares a and b line by line (Myers' O(ND) algorithm) and groups
// the changes into hunks with the given number of context lines.
func Diff(a, b []byte, context int) []Hunk {
	al, bl := splitLines(a), splitLines(b)
	ops := myers(al, bl)
	if context < 0 {
		context = 0
	}
	var hunks []Hunk
	i := 0
	for i < len(ops) {
		if ops[i].op == OpContext {
			i++
			continue
		}
		// [first, last] are changes; extend while the next change is within
		// 2*context unchanged lines.
		first, last := i, i
		for j := i + 1; j < len(ops); j++ {
			if ops[j].op == OpContext {
				continue
			}
			if j-last-1 > 2*context {
				break
			}
			last = j
		}
		start := max(0, first-context)
		end := min(len(ops), last+context+1)
		hunks = append(hunks, makeHunk(ops[start:end], al, bl))
		i = end
	}
	return hunks
}

func makeHunk(ops []diffOp, al, bl []string) Hunk {
	h := Hunk{OldStart: ops[0].a, NewStart: ops[0].b}
	for _, o := range ops {
		var src []string
		idx := 0
		switch o.op {
		case OpContext:
			h.OldLines++
			h.NewLines++
			src, idx = al, o.a
		case OpDelete:
			h.OldLines++
			src, idx = al, o.a
		default:
			h.NewLines++
			src, idx = bl, o.b
		}
		line := src[idx]
		text := trimEOL(line)
		if idx == 0 {
			text = strings.TrimPrefix(text, bomText)
		}
		h.Lines = append(h.Lines, DiffLine{
			Op: o.op, Text: text,
			NoNewline: idx == len(src)-1 && !strings.HasSuffix(line, "\n"),
		})
	}
	if h.OldLines > 0 {
		h.OldStart++
	}
	if h.NewLines > 0 {
		h.NewStart++
	}
	return h
}

// myers returns the shortest edit script turning a into b. The V arrays
// are kept only for diagonals -d..d of each step, so memory is O(D*D).
func myers(a, b []string) []diffOp {
	n, m := len(a), len(b)
	maxD := n + m
	off := maxD + 1
	v := make([]int, 2*maxD+3)
	var trace [][]int
	found := false
	for d := 0; d <= maxD && !found; d++ {
		for k := -d; k <= d; k += 2 {
			var x int
			if k == -d || (k != d && v[off+k-1] < v[off+k+1]) {
				x = v[off+k+1]
			} else {
				x = v[off+k-1] + 1
			}
			y := x - k
			for x < n && y < m && a[x] == b[y] {
				x++
				y++
			}
			v[off+k] = x
			if x >= n && y >= m {
				found = true
				break
			}
		}
		snap := make([]int, 2*d+1)
		copy(snap, v[off-d:off+d+1])
		trace = append(trace, snap)
	}

	// Walk back from (n, m).
	var rev []diffOp
	x, y := n, m
	for d := len(trace) - 1; d > 0; d-- {
		prev := trace[d-1] // index k+(d-1)
		at := func(k int) int { return prev[k+d-1] }
		k := x - y
		var pk int
		if k == -d || (k != d && at(k-1) < at(k+1)) {
			pk = k + 1
		} else {
			pk = k - 1
		}
		px := at(pk)
		py := px - pk
		mx := px
		if pk == k-1 {
			mx = px + 1 // a deletion moved right
		}
		for x > mx {
			x--
			y--
			rev = append(rev, diffOp{op: OpContext, a: x, b: y})
		}
		if pk == k+1 {
			rev = append(rev, diffOp{op: OpInsert, a: px, b: py})
		} else {
			rev = append(rev, diffOp{op: OpDelete, a: px, b: py})
		}
		x, y = px, py
	}
	for x > 0 && y > 0 {
		x--
		y--
		rev = append(rev, diffOp{op: OpContext, a: x, b: y})
	}
	ops := make([]diffOp, len(rev))
	for i, o := range rev {
		ops[len(rev)-1-i] = o
	}
	return ops
}

// Unified renders hunks as a unified diff with the given file names in the
// "---" / "+++" header. It returns "" when there are no hunks.
func Unified(oldName, newName string, hunks []Hunk) string {
	if len(hunks) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("--- " + oldName + "\n")
	sb.WriteString("+++ " + newName + "\n")
	rng := func(start, n int) string {
		if n == 1 {
			return strconv.Itoa(start)
		}
		return strconv.Itoa(start) + "," + strconv.Itoa(n)
	}
	for _, h := range hunks {
		sb.WriteString("@@ -" + rng(h.OldStart, h.OldLines) + " +" + rng(h.NewStart, h.NewLines) + " @@\n")
		for _, l := range h.Lines {
			sb.WriteString(l.Op + l.Text + "\n")
			if l.NoNewline {
				sb.WriteString("\\ No newline at end of file\n")
			}
		}
	}
	return sb.String()
}
