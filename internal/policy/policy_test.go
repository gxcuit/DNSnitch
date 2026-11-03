package policy

import (
	"testing"

	"dnsleak/internal/model"
)

func group(name string, members ...string) model.ProxyGroup {
	g := model.ProxyGroup{Name: name, Type: "select"}
	for _, m := range members {
		g.Members = append(g.Members, model.NameRef{Name: m})
	}
	return g
}

func TestClassify(t *testing.T) {
	cfg := &model.Config{
		Proxies: []model.NameRef{{Name: "hk"}},
		ProxyGroups: []model.ProxyGroup{
			group("PROXY", "hk"),
			group("MIXED", "PROXY", "DIRECT"),
			group("OUTER", "MIXED"),
			group("DIRECTS", "DIRECT", "REJECT"),
			group("REJECTS", "REJECT", "REJECT-DROP"),
			group("EMPTY"),
			group("LOOP-A", "LOOP-B", "DIRECT"),
			group("LOOP-B", "LOOP-A"),
			{Name: "PROVIDER", Use: []string{"airport"}},
			{Name: "ALL", IncludeAll: true},
		},
	}
	c := New(cfg)
	tests := []struct {
		name    string
		class   model.PolicyClass
		exists  bool
		assumed bool
		group   string
	}{
		{"DIRECT", model.PolicyDirect, true, false, ""},
		{"COMPATIBLE", model.PolicyDirect, true, false, ""},
		{"REJECT", model.PolicyReject, true, false, ""},
		{"REJECT-DROP", model.PolicyReject, true, false, ""},
		{"PASS", model.PolicyPass, true, false, ""},
		{"GLOBAL", model.PolicyProxy, true, false, ""},
		{"hk", model.PolicyProxy, true, false, ""},
		{"PROXY", model.PolicyProxy, true, false, ""},
		{"MIXED", model.PolicyProxy, true, true, "MIXED"},
		{"OUTER", model.PolicyProxy, true, true, "MIXED"},
		{"DIRECTS", model.PolicyDirect, true, false, ""},
		{"REJECTS", model.PolicyReject, true, false, ""},
		{"EMPTY", model.PolicyDirect, true, false, ""},
		{"LOOP-A", model.PolicyProxy, true, true, "LOOP-A"},
		{"PROVIDER", model.PolicyProxy, true, false, ""},
		{"ALL", model.PolicyProxy, true, false, ""},
		{"nope", model.PolicyDirect, false, false, ""},
	}
	for _, tt := range tests {
		r := c.Classify(tt.name)
		if r.Class != tt.class || r.Exists != tt.exists || r.Assumed != tt.assumed || r.Group != tt.group {
			t.Errorf("%s: got %+v", tt.name, r)
		}
	}
}
