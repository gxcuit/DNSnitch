package config

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// resolve follows aliases.
func resolve(n *yaml.Node) *yaml.Node {
	for i := 0; n != nil && n.Kind == yaml.AliasNode && i < 100; i++ {
		n = n.Alias
	}
	return n
}

type pair struct {
	key, val *yaml.Node
}

func isMergeKey(k *yaml.Node) bool {
	return k.Kind == yaml.ScalarNode && k.Value == "<<" && (k.Tag == "!!merge" || k.Tag == "" || k.ShortTag() == "!!merge")
}

// pairs returns the effective key/value pairs of a mapping, expanding "<<"
// merge keys in place. Explicit keys override merged ones; among merged
// mappings the first one wins.
func pairs(n *yaml.Node) []pair {
	return pairsDepth(n, 0)
}

func pairsDepth(n *yaml.Node, depth int) []pair {
	n = resolve(n)
	if n == nil || n.Kind != yaml.MappingNode || depth > 32 {
		return nil
	}
	explicit := map[string]bool{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if k := n.Content[i]; !isMergeKey(k) {
			explicit[k.Value] = true
		}
	}
	seen := map[string]bool{}
	var out []pair
	add := func(p pair) {
		if seen[p.key.Value] {
			return
		}
		seen[p.key.Value] = true
		out = append(out, p)
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if !isMergeKey(k) {
			add(pair{k, v})
			continue
		}
		v = resolve(v)
		var sources []*yaml.Node
		switch v.Kind {
		case yaml.MappingNode:
			sources = []*yaml.Node{v}
		case yaml.SequenceNode:
			sources = v.Content
		}
		for _, src := range sources {
			for _, p := range pairsDepth(src, depth+1) {
				if !explicit[p.key.Value] {
					add(p)
				}
			}
		}
	}
	return out
}

// get returns the value of key in mapping n, or nil.
func get(n *yaml.Node, key string) (keyNode, val *yaml.Node) {
	for _, p := range pairs(n) {
		if p.key.Value == key {
			return p.key, resolve(p.val)
		}
	}
	return nil, nil
}

// scalar returns the scalar value of n ("" if n is not a scalar).
func scalar(n *yaml.Node) string {
	n = resolve(n)
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

// boolean decodes n as a YAML bool; def is returned if n is nil or invalid.
func boolean(n *yaml.Node, def bool) bool {
	n = resolve(n)
	if n == nil || n.Kind != yaml.ScalarNode {
		return def
	}
	switch strings.ToLower(n.Value) {
	case "true", "yes", "on", "y":
		return true
	case "false", "no", "off", "n":
		return false
	}
	return def
}

// items returns the elements of a sequence; a scalar is treated as a
// one-element sequence.
func items(n *yaml.Node) []*yaml.Node {
	n = resolve(n)
	if n == nil {
		return nil
	}
	switch n.Kind {
	case yaml.SequenceNode:
		out := make([]*yaml.Node, 0, len(n.Content))
		for _, c := range n.Content {
			out = append(out, resolve(c))
		}
		return out
	case yaml.ScalarNode:
		if n.Tag == "!!null" {
			return nil
		}
		return []*yaml.Node{n}
	}
	return nil
}
