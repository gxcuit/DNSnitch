package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"dnsleak/internal/platform"
)

// withFacts makes `status` see the given facts instead of the machine.
func withFacts(t *testing.T, f platform.Facts) {
	t.Helper()
	old := inspectSystem
	inspectSystem = func() platform.Snapshot { return platform.Decide(f) }
	t.Cleanup(func() { inspectSystem = old })
}

var (
	sampleMihomo = platform.Adapter{Name: "Mihomo", Description: "Meta Tunnel", IfIndex: 21, IfType: 53, Up: true,
		IPv4: []string{"198.18.0.1/30"}, Wintun: true, MatchedBy: platform.MatchedByComponentID}
	sampleWLAN = platform.Adapter{Name: "WLAN", Description: "Wi-Fi", IfIndex: 12, IfType: 71, Up: true,
		IPv4: []string{"192.168.1.20/24"}}
	smartOne  = platform.SmartFacts{Present: true, IsDWORD: true, Value: 1}
	smartNone = platform.SmartFacts{}
)

type jsonStatus struct {
	OS    string `json:"os"`
	Smart struct {
		State  string   `json:"state"`
		Label  string   `json:"label"`
		Detail []string `json:"detail"`
	} `json:"smart"`
	TUN struct {
		State  string   `json:"state"`
		Label  string   `json:"label"`
		Detail []string `json:"detail"`
		Note   string   `json:"note"`
	} `json:"tun"`
	Risk           bool   `json:"risk"`
	ConclusionCode string `json:"conclusion_code"`
	Conclusion     string `json:"conclusion"`
	Fix            []struct {
		Text    string `json:"text"`
		Command string `json:"command"`
	} `json:"fix"`
}

func statusJSON(t *testing.T, args ...string) (jsonStatus, int) {
	t.Helper()
	out, code := runCLI(t, append([]string{"status", "--format", "json"}, args...)...)
	var res jsonStatus
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("invalid JSON (%v):\n%s", err, out)
	}
	return res, code
}

func TestStatusTextDisabled(t *testing.T) {
	// AC1: DisableSmartNameResolution = 1 → 已禁用; TUN off.
	withFacts(t, platform.Facts{OS: platform.OSWindows, Smart: smartOne, Adapters: []platform.Adapter{sampleWLAN}, EgressIfIndex: 12})
	out, code := runCLI(t, "status")
	if code != 0 {
		t.Errorf("exit %d", code)
	}
	for _, want := range []string{"智能多宿主名称解析：已禁用", "TUN 模式：未开启", "结论："} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestStatusRiskExitCode(t *testing.T) {
	withFacts(t, platform.Facts{OS: platform.OSWindows, Smart: smartNone,
		Adapters: []platform.Adapter{sampleWLAN, sampleMihomo}, EgressIfIndex: 21})
	res, code := statusJSON(t)
	if code != 1 || !res.Risk || res.ConclusionCode != "risk" || res.Smart.State != "enabled" || res.TUN.State != "on" {
		t.Errorf("exit %d, %+v", code, res)
	}
	if len(res.Fix) == 0 || !strings.Contains(res.Fix[1].Command, `reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"`) {
		t.Errorf("fix = %+v", res.Fix)
	}
	if !strings.Contains(strings.Join(res.TUN.Detail, "\n"), "198.18.0.1/30") {
		t.Errorf("tun detail = %v", res.TUN.Detail)
	}

	out, code := runCLI(t, "status")
	if code != 1 || !strings.Contains(out, "必然发生 DNS 泄露") {
		t.Errorf("text exit %d:\n%s", code, out)
	}
}

func TestStatusCombinations(t *testing.T) {
	on := platform.Facts{OS: platform.OSWindows, Adapters: []platform.Adapter{sampleWLAN, sampleMihomo}, EgressIfIndex: 21}
	notEgress := platform.Facts{OS: platform.OSWindows, Adapters: []platform.Adapter{sampleWLAN, sampleMihomo}, EgressIfIndex: 12}
	for _, c := range []struct {
		name  string
		f     platform.Facts
		smart platform.SmartFacts
		exit  int
		code  string
		tun   string
	}{
		{"on + disabled", on, smartOne, 0, "protected", "on"},
		{"not egress + enabled", notEgress, smartNone, 0, "tun-off", "off"},
		{"unknown smart + on", on, platform.SmartFacts{Err: "denied"}, 0, "unknown", "on"},
		{"unknown tun + enabled", platform.Facts{OS: platform.OSWindows, NetErr: "boom"}, smartNone, 0, "unknown", "unknown"},
		{"linux", platform.Facts{OS: "linux"}, smartNone, 0, "unsupported", "unsupported"},
	} {
		f := c.f
		f.Smart = c.smart
		withFacts(t, f)
		res, code := statusJSON(t)
		if code != c.exit || res.ConclusionCode != c.code || res.TUN.State != c.tun {
			t.Errorf("%s: exit %d, %+v", c.name, code, res)
		}
	}
	withFacts(t, notEgress)
	res, _ := statusJSON(t)
	if res.TUN.Note == "" {
		t.Errorf("adapter-not-egress note missing: %+v", res.TUN)
	}
}

func TestStatusArgs(t *testing.T) {
	withFacts(t, platform.Facts{OS: platform.OSWindows, Smart: smartOne})
	for _, args := range [][]string{
		{"status", "extra.yaml"},
		{"status", "--format", "xml"},
		{"status", "--home", "x"},
		{"status", "--home", ""},
		{"status", "--home="},
	} {
		var out, errOut bytes.Buffer
		if code := run(args, &out, &errOut); code != 2 || errOut.Len() == 0 || out.Len() != 0 {
			t.Errorf("%v: exit %d, stdout %q", args, code, out.String())
		}
	}
	// Flags may come before or after the subcommand's (absent) arguments.
	if out, code := runCLI(t, "status", "--format", "json"); code != 0 || !strings.HasPrefix(out, "{") {
		t.Errorf("json: exit %d %q", code, out)
	}
	if out, code := runCLI(t, "help"); code != 0 || !strings.Contains(out, "dnsleak status") {
		t.Errorf("usage lacks status: %d\n%s", code, out)
	}
}
