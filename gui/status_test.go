package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"dnsleak/internal/platform"
	"dnsleak/internal/report"
)

// TestSystemStatusMatchesCLI checks that the binding returns the same view
// as `dnsleak status --format json` for the same (injected) facts.
func TestSystemStatusMatchesCLI(t *testing.T) {
	f := platform.Facts{
		OS: platform.OSWindows,
		Adapters: []platform.Adapter{{Name: "Mihomo", Description: "Meta Tunnel", IfIndex: 21, IfType: 53, Up: true,
			IPv4: []string{"198.18.0.1/30"}, Wintun: true, MatchedBy: platform.MatchedByComponentID}},
		EgressIfIndex: 21,
	}
	old := inspectSystem
	inspectSystem = func() platform.Snapshot { return platform.Decide(f) }
	t.Cleanup(func() { inspectSystem = old })

	got := NewApp().SystemStatus()
	if !got.Risk || got.TUN.State != platform.StateOn || got.Smart.State != platform.StateEnabled || len(got.Fix) == 0 {
		t.Errorf("view = %+v", got)
	}
	var cli bytes.Buffer
	if err := report.WriteStatus(&cli, report.FormatJSON, report.BuildStatusView(platform.Decide(f))); err != nil {
		t.Fatal(err)
	}
	var want report.StatusView
	if err := json.Unmarshal(cli.Bytes(), &want); err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(got)
	b, _ := json.Marshal(want)
	if !bytes.Equal(a, b) {
		t.Errorf("binding:\n%s\ncli:\n%s", a, b)
	}
}
