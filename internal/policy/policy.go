// Package policy classifies proxies, proxy groups and built-in policies as
// direct / proxy / reject / pass (PRD R2, decision D7).
package policy

import "dnsnitch/internal/model"

// Builtin policies.
var builtins = map[string]model.PolicyClass{
	"DIRECT":      model.PolicyDirect,
	"COMPATIBLE":  model.PolicyDirect,
	"REJECT":      model.PolicyReject,
	"REJECT-DROP": model.PolicyReject,
	"PASS":        model.PolicyPass,
	// GLOBAL is the implicit select group containing every proxy.
	"GLOBAL": model.PolicyProxy,
}

// Result is the classification of one policy name.
type Result struct {
	Class  model.PolicyClass
	Exists bool
	// Assumed is true when a group mixes proxies with DIRECT / REJECT and
	// was classified as proxy by assumption (D7).
	Assumed bool
	// Group is the name of the (outermost) group that carries the
	// assumption, if any.
	Group string
}

// Classifier classifies policy names of one config.
type Classifier struct {
	proxies map[string]bool
	groups  map[string]*model.ProxyGroup
	cache   map[string]Result
}

// New builds a classifier for cfg.
func New(cfg *model.Config) *Classifier {
	c := &Classifier{proxies: map[string]bool{}, groups: map[string]*model.ProxyGroup{}, cache: map[string]Result{}}
	for _, p := range cfg.Proxies {
		c.proxies[p.Name] = true
	}
	for i := range cfg.ProxyGroups {
		g := &cfg.ProxyGroups[i]
		c.groups[g.Name] = g
	}
	return c
}

// Exists reports whether name is a builtin, proxy or group.
func (c *Classifier) Exists(name string) bool {
	if _, ok := builtins[name]; ok {
		return true
	}
	return c.proxies[name] || c.groups[name] != nil
}

// Classify classifies name.
func (c *Classifier) Classify(name string) Result {
	if r, ok := c.cache[name]; ok {
		return r
	}
	r := c.classify(name, map[string]bool{})
	c.cache[name] = r
	return r
}

// Lookup adapts Classify to dnsserver.ProxyLookup.
func (c *Classifier) Lookup(name string) (model.PolicyClass, bool) {
	r := c.Classify(name)
	return r.Class, r.Exists
}

func (c *Classifier) classify(name string, visiting map[string]bool) Result {
	if cl, ok := builtins[name]; ok {
		return Result{Class: cl, Exists: true}
	}
	if c.proxies[name] {
		return Result{Class: model.PolicyProxy, Exists: true}
	}
	g := c.groups[name]
	if g == nil {
		return Result{Exists: false}
	}
	if visiting[name] {
		// Cycle: stop and treat as proxy (design §7).
		return Result{Class: model.PolicyProxy, Exists: true, Assumed: true, Group: name}
	}
	visiting[name] = true
	defer delete(visiting, name)

	hasProxy := len(g.Use) > 0 || g.IncludeAll
	hasDirect, hasReject, hasPass, hasOther := false, false, false, false
	var inner Result
	for _, m := range g.Members {
		r := c.classify(m.Name, visiting)
		if !r.Exists {
			continue
		}
		switch r.Class {
		case model.PolicyProxy:
			hasProxy = true
			if r.Assumed && inner.Group == "" {
				inner = r
			}
		case model.PolicyDirect:
			hasDirect = true
		case model.PolicyReject:
			hasReject = true
		case model.PolicyPass:
			hasPass = true
		}
	}
	hasOther = hasDirect || hasReject || hasPass
	switch {
	case hasProxy:
		res := Result{Class: model.PolicyProxy, Exists: true}
		if hasOther {
			res.Assumed, res.Group = true, name
		} else if inner.Assumed {
			res.Assumed, res.Group = true, inner.Group
		}
		return res
	case hasDirect:
		return Result{Class: model.PolicyDirect, Exists: true}
	case hasReject:
		return Result{Class: model.PolicyReject, Exists: true}
	case hasPass:
		return Result{Class: model.PolicyPass, Exists: true}
	default:
		// An empty group falls back to COMPATIBLE (direct) in mihomo.
		return Result{Class: model.PolicyDirect, Exists: true}
	}
}
