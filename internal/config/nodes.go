package config

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// ErrNotFound is returned (wrapped) by Doc.Find when a path does not exist.
var ErrNotFound = errors.New("config path not found")

// Doc is the YAML node tree of a config file. It maps the location paths
// produced by Parse (model.Location.Path) back to nodes, so that callers can
// edit the original text at the node's line and column.
type Doc struct {
	// Root is the top-level node of the first document (nil when empty).
	Root *yaml.Node
	// BOM is the length of the UTF-8 byte order mark stripped before
	// parsing (0 or 3). Node lines and columns refer to the data after it,
	// so byte offsets into the original data must add BOM.
	BOM int
}

// Nodes parses config data (optionally starting with a UTF-8 BOM) into a
// Doc. Errors are ErrEncrypted or *ParseError, as for Parse.
func Nodes(data []byte) (*Doc, error) {
	if IsEncrypted(data) {
		return nil, ErrEncrypted
	}
	d := &Doc{}
	if bytes.HasPrefix(data, utf8BOM) {
		d.BOM = len(utf8BOM)
		data = data[d.BOM:]
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, &ParseError{err}
	}
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		d.Root = doc.Content[0]
	}
	return d, nil
}

// Target is the node a location path refers to.
type Target struct {
	// Node is the value at the path, aliases resolved. For "x[0]" where x
	// is a plain scalar (treated as a one-element list by Parse), Node is
	// that scalar and Key / Parent are those of x.
	Node *yaml.Node
	// Key is the mapping key of Node; nil for sequence items.
	Key *yaml.Node
	// Parent is the sequence or mapping holding Node. For a pair merged in
	// with "<<" it is the merge source mapping that actually holds Key.
	Parent *yaml.Node
	// ViaAlias: an alias was followed on the way to Node.
	ViaAlias bool
	// ViaMerge: a "<<" merge key was followed on the way to Node.
	ViaMerge bool
	// Anchored: Node, its key, or a container on the way defines an
	// anchor, so other places of the file may share the node.
	Anchored bool
}

// Shared reports whether editing the node's text may change more than the
// place the path names (anchor, alias or merge involved).
func (t Target) Shared() bool { return t.ViaAlias || t.ViaMerge || t.Anchored }

const maxPathDepth = 64

// Find resolves a location path such as "rules[3]", "sub-rules.a.b[0]",
// "dns.nameserver[1]", "dns.nameserver-police" or "proxy-groups[0].proxies[2]".
// Mapping keys may contain "." or "[": at each mapping the longest key that
// matches the rest of the path is tried first. "<<" merge keys are followed
// with the same precedence as Parse.
func (d *Doc) Find(path string) (Target, error) {
	if d == nil || d.Root == nil || path == "" {
		return Target{}, fmt.Errorf("%w: %q", ErrNotFound, path)
	}
	root := resolve(d.Root)
	if root == nil {
		return Target{}, fmt.Errorf("%w: %q", ErrNotFound, path)
	}
	start := Target{Node: root, ViaAlias: d.Root.Kind == yaml.AliasNode, Anchored: root.Anchor != ""}
	if t, ok := walk(start, path, 0); ok {
		return t, nil
	}
	return Target{}, fmt.Errorf("%w: %q", ErrNotFound, path)
}

// walk resolves rest (a key segment or "[i]" first) below t.Node.
func walk(t Target, rest string, depth int) (Target, bool) {
	if rest == "" {
		return t, true
	}
	if depth > maxPathDepth {
		return Target{}, false
	}
	n := t.Node
	switch n.Kind {
	case yaml.MappingNode:
		var cands []pair
		for _, p := range pairs(n) {
			k := p.key.Value
			if !strings.HasPrefix(rest, k) {
				continue
			}
			if tail := rest[len(k):]; tail == "" || tail[0] == '.' || tail[0] == '[' {
				cands = append(cands, p)
			}
		}
		sort.SliceStable(cands, func(i, j int) bool { return len(cands[i].key.Value) > len(cands[j].key.Value) })
		for _, p := range cands {
			tail := rest[len(p.key.Value):]
			if strings.HasPrefix(tail, ".") {
				if tail = tail[1:]; tail == "" {
					continue
				}
			}
			child := resolve(p.val)
			if child == nil {
				continue
			}
			next := Target{
				Node: child, Key: p.key, Parent: p.owner,
				ViaAlias: t.ViaAlias || p.val.Kind == yaml.AliasNode,
				ViaMerge: t.ViaMerge || p.merged,
				Anchored: t.Anchored || child.Anchor != "" || p.key.Anchor != "" || (p.owner != nil && p.owner.Anchor != ""),
			}
			if res, ok := walk(next, tail, depth+1); ok {
				return res, true
			}
		}
	case yaml.SequenceNode:
		i, tail, ok := splitIndex(rest)
		if !ok || i >= len(n.Content) {
			return Target{}, false
		}
		c := n.Content[i]
		child := resolve(c)
		if child == nil {
			return Target{}, false
		}
		next := Target{
			Node: child, Parent: n,
			ViaAlias: t.ViaAlias || c.Kind == yaml.AliasNode,
			ViaMerge: t.ViaMerge,
			Anchored: t.Anchored || child.Anchor != "",
		}
		return walk(next, tail, depth+1)
	case yaml.ScalarNode:
		// items() treats a non-null scalar as a one-element sequence.
		i, tail, ok := splitIndex(rest)
		if !ok || i != 0 || n.Tag == "!!null" {
			return Target{}, false
		}
		return walk(t, tail, depth+1)
	}
	return Target{}, false
}

// splitIndex parses a leading "[i]" and returns i and the rest of the path
// (a following "." is dropped).
func splitIndex(rest string) (int, string, bool) {
	if !strings.HasPrefix(rest, "[") {
		return 0, "", false
	}
	end := strings.IndexByte(rest, ']')
	if end < 2 {
		return 0, "", false
	}
	i, err := strconv.Atoi(rest[1:end])
	if err != nil || i < 0 {
		return 0, "", false
	}
	tail := rest[end+1:]
	if strings.HasPrefix(tail, ".") {
		if tail = tail[1:]; tail == "" {
			return 0, "", false
		}
	}
	return i, tail, true
}

// HasKey reports whether mapping n has key, counting keys merged in with
// "<<" (the effective keys seen by Parse).
func HasKey(n *yaml.Node, key string) bool {
	k, _ := get(n, key)
	return k != nil
}

// ListValues returns the values of a list node the way Parse reads a DNS
// server list: the elements of a sequence, or a non-null scalar as a
// one-element list (aliases followed). A non-scalar element yields "\x00",
// which no server string equals.
func ListValues(n *yaml.Node) []string {
	out := []string{}
	for _, it := range items(n) {
		if it == nil || it.Kind != yaml.ScalarNode {
			out = append(out, "\x00")
			continue
		}
		out = append(out, it.Value)
	}
	return out
}
