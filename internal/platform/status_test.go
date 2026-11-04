package platform

import "testing"

// Adapters sampled on the dev machine with mihomo-party TUN on
// (research/tun-and-smart-resolution.md).
func mihomoAdapter() Adapter {
	a := Adapter{Name: "Mihomo", Description: "Meta Tunnel", GUID: "{9E6FE1DA-841B-EE9D-1002-5210FB95904A}",
		IfIndex: 21, IfType: 53, Up: true, IPv4: []string{"198.18.0.1/30"}}
	a.Wintun, a.MatchedBy = ClassifyWintun(a.IfType, a.Description, "Wintun", true)
	return a
}

func wlanAdapter() Adapter {
	a := Adapter{Name: "WLAN", Description: "Intel(R) Wi-Fi 6E AX211 160MHz", IfIndex: 12, IfType: 71, Up: true,
		IPv4: []string{"192.168.1.20/24"}}
	a.Wintun, a.MatchedBy = ClassifyWintun(a.IfType, a.Description, "pci\\ven_8086", true)
	return a
}

func hyperVAdapter() Adapter {
	a := Adapter{Name: "vEthernet (FSE HostVnic)", Description: "Hyper-V Virtual Ethernet Adapter", IfIndex: 30, IfType: 6, Up: true,
		IPv4: []string{"172.20.0.1/20"}}
	a.Wintun, a.MatchedBy = ClassifyWintun(a.IfType, a.Description, "", true)
	return a
}

func TestClassifyWintun(t *testing.T) {
	for _, c := range []struct {
		name          string
		ifType        uint32
		desc, comp    string
		known         bool
		want          bool
		wantMatchedBy string
	}{
		{"mihomo sample", 53, "Meta Tunnel", "Wintun", true, true, MatchedByComponentID},
		{"component id lower case", 53, "Meta Tunnel", "wintun", true, true, MatchedByComponentID},
		{"component id wins over description", 53, "Meta Tunnel", "ms_ndiswanip", true, false, ""},
		{"Hyper-V vEthernet", 6, "Hyper-V Virtual Ethernet Adapter", "", true, false, ""},
		{"Hyper-V vSwitch", 6, "Hyper-V Virtual Switch Extension Adapter", "vms_vsmp", true, false, ""},
		{"WAN Miniport", 6, "WAN Miniport (IP)", "ms_ndiswanip", true, false, ""},
		{"WLAN", 71, "Intel(R) Wi-Fi 6E AX211 160MHz", "pci\\ven_8086", true, false, ""},
		{"fallback Meta Tunnel", 53, "Meta Tunnel", "", false, true, MatchedByFallback},
		{"fallback WireGuard", 53, "WireGuard Tunnel", "", false, true, MatchedByFallback},
		{"fallback wrong type", 6, "Meta Tunnel", "", false, false, ""},
		{"fallback other virtual", 53, "Some VPN Adapter", "", false, false, ""},
		{"fallback WLAN", 71, "Intel(R) Wi-Fi 6E AX211 160MHz", "", false, false, ""},
	} {
		got, by := ClassifyWintun(c.ifType, c.desc, c.comp, c.known)
		if got != c.want || by != c.wantMatchedBy {
			t.Errorf("%s: got %v/%q, want %v/%q", c.name, got, by, c.want, c.wantMatchedBy)
		}
	}
}

func smartFacts(present, dword bool, v uint32, typ, err string) SmartFacts {
	return SmartFacts{Present: present, IsDWORD: dword, Value: v, Type: typ, Err: err}
}

func TestDecideSmart(t *testing.T) {
	for _, c := range []struct {
		name       string
		os         string
		f          SmartFacts
		state      string
		reason     string
		value      int64 // -1 = nil
		valueType  string
		errorEmpty bool
	}{
		{"value 1", OSWindows, smartFacts(true, true, 1, "", ""), StateDisabled, ReasonValue, 1, "", true},
		{"value 0", OSWindows, smartFacts(true, true, 0, "", ""), StateEnabled, ReasonValue, 0, "", true},
		{"missing", OSWindows, smartFacts(false, false, 0, "", ""), StateEnabled, ReasonNotSet, -1, "", true},
		{"wrong type", OSWindows, smartFacts(true, false, 0, "REG_SZ", ""), StateUnknown, ReasonNotDWORD, -1, "REG_SZ", true},
		{"unexpected value", OSWindows, smartFacts(true, true, 2, "", ""), StateUnknown, ReasonUnexpectedValue, 2, "", true},
		{"read error", OSWindows, smartFacts(false, false, 0, "", "Access is denied."), StateUnknown, ReasonReadError, -1, "", false},
		{"linux", "linux", smartFacts(false, false, 0, "", ""), StateUnsupported, ReasonUnsupportedOS, -1, "", true},
		{"darwin", "darwin", smartFacts(true, true, 1, "", ""), StateUnsupported, ReasonUnsupportedOS, -1, "", true},
	} {
		s := Decide(Facts{OS: c.os, Smart: c.f}).Smart
		if s.State != c.state || s.Reason != c.reason || s.ValueType != c.valueType || (s.Error == "") != c.errorEmpty {
			t.Errorf("%s: %+v", c.name, s)
		}
		if (c.value < 0) != (s.Value == nil) || (s.Value != nil && int64(*s.Value) != c.value) {
			t.Errorf("%s: value %v, want %d", c.name, s.Value, c.value)
		}
		if s.KeyPath != `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient` || s.ValueName != "DisableSmartNameResolution" {
			t.Errorf("%s: key %q value %q", c.name, s.KeyPath, s.ValueName)
		}
	}
}

func TestDecideTUN(t *testing.T) {
	mihomo := mihomoAdapter()
	down := mihomoAdapter()
	down.Up = false
	fallback := mihomoAdapter()
	fallback.Wintun, fallback.MatchedBy = ClassifyWintun(53, "Meta Tunnel", "", false)

	for _, c := range []struct {
		name     string
		f        Facts
		state    string
		reason   string
		note     string
		adapter  string // expected TUNStatus.Adapter name, "" = nil
		egress   string // expected TUNStatus.Egress name, "" = nil
		hasError bool
	}{
		{"wintun is egress (sample)", Facts{OS: OSWindows, Adapters: []Adapter{wlanAdapter(), hyperVAdapter(), mihomo}, EgressIfIndex: 21},
			StateOn, ReasonAdapterEgress, "", "Mihomo", "Mihomo", false},
		{"wintun by fallback is egress", Facts{OS: OSWindows, Adapters: []Adapter{wlanAdapter(), fallback}, EgressIfIndex: 21},
			StateOn, ReasonAdapterEgress, "", "Mihomo", "Mihomo", false},
		{"wintun present, egress WLAN", Facts{OS: OSWindows, Adapters: []Adapter{wlanAdapter(), mihomo}, EgressIfIndex: 12},
			StateOff, ReasonAdapterNotEgress, NoteAdapterNotEgress, "Mihomo", "WLAN", false},
		{"wintun present, no route", Facts{OS: OSWindows, Adapters: []Adapter{wlanAdapter(), mihomo}},
			StateOff, ReasonAdapterNotEgress, NoteAdapterNotEgress, "Mihomo", "", false},
		{"wintun present, route lookup failed", Facts{OS: OSWindows, Adapters: []Adapter{wlanAdapter(), mihomo}, EgressErr: "network unreachable"},
			StateUnknown, ReasonEgressError, "", "Mihomo", "", true},
		{"wintun down", Facts{OS: OSWindows, Adapters: []Adapter{wlanAdapter(), down}, EgressIfIndex: 12},
			StateOff, ReasonNoAdapter, "", "", "WLAN", false},
		{"no wintun (TUN off sample)", Facts{OS: OSWindows, Adapters: []Adapter{wlanAdapter(), hyperVAdapter()}, EgressIfIndex: 12},
			StateOff, ReasonNoAdapter, "", "", "WLAN", false},
		{"no wintun, route lookup failed", Facts{OS: OSWindows, Adapters: []Adapter{wlanAdapter()}, EgressErr: "x"},
			StateOff, ReasonNoAdapter, "", "", "", false},
		{"adapter list failed", Facts{OS: OSWindows, NetErr: "boom", EgressIfIndex: 21},
			StateUnknown, ReasonNetError, "", "", "", true},
		{"linux", Facts{OS: "linux", Adapters: []Adapter{mihomo}, EgressIfIndex: 21},
			StateUnsupported, ReasonUnsupportedOS, "", "", "", false},
	} {
		tu := Decide(c.f).TUN
		if tu.State != c.state || tu.Reason != c.reason || tu.Note != c.note || (tu.Error != "") != c.hasError {
			t.Errorf("%s: %+v", c.name, tu)
		}
		if name(tu.Adapter) != c.adapter || name(tu.Egress) != c.egress {
			t.Errorf("%s: adapter %q egress %q", c.name, name(tu.Adapter), name(tu.Egress))
		}
	}
}

func TestDecideTUNPicksEgressWintun(t *testing.T) {
	other := mihomoAdapter()
	other.Name, other.IfIndex, other.GUID = "wg0", 40, "{X}"
	tu := Decide(Facts{OS: OSWindows, Adapters: []Adapter{other, mihomoAdapter()}, EgressIfIndex: 21}).TUN
	if tu.State != StateOn || name(tu.Adapter) != "Mihomo" {
		t.Errorf("%+v", tu)
	}
	if tu.Adapter.IPv4[0] != "198.18.0.1/30" || tu.Adapter.MatchedBy != MatchedByComponentID {
		t.Errorf("evidence: %+v", tu.Adapter)
	}
}

func name(a *Adapter) string {
	if a == nil {
		return ""
	}
	return a.Name
}

func TestRisk(t *testing.T) {
	on := Facts{OS: OSWindows, Adapters: []Adapter{wlanAdapter(), mihomoAdapter()}, EgressIfIndex: 21}
	off := Facts{OS: OSWindows, Adapters: []Adapter{wlanAdapter()}, EgressIfIndex: 12}
	unknownTUN := Facts{OS: OSWindows, NetErr: "boom"}
	smart := map[string]SmartFacts{
		StateDisabled: smartFacts(true, true, 1, "", ""),
		StateEnabled:  smartFacts(false, false, 0, "", ""),
		StateUnknown:  smartFacts(true, false, 0, "REG_SZ", ""),
	}
	for _, c := range []struct {
		tun   Facts
		smart string
		risk  bool
	}{
		{on, StateEnabled, true},
		{on, StateDisabled, false},
		{on, StateUnknown, false},
		{off, StateEnabled, false},
		{off, StateDisabled, false},
		{unknownTUN, StateEnabled, false},
		{unknownTUN, StateUnknown, false},
	} {
		f := c.tun
		f.Smart = smart[c.smart]
		s := Decide(f)
		if s.Smart.State != c.smart || s.Risk != c.risk {
			t.Errorf("tun %s smart %s: risk %v", s.TUN.State, s.Smart.State, s.Risk)
		}
	}
	if Decide(Facts{OS: "darwin"}).Risk {
		t.Errorf("unsupported OS is no risk")
	}
}

func TestRegistryTypeName(t *testing.T) {
	if RegistryTypeName(1) != "REG_SZ" || RegistryTypeName(4) != "REG_DWORD" || RegistryTypeName(11) != "REG_QWORD" || RegistryTypeName(99) != "REG_TYPE_99" {
		t.Errorf("names")
	}
}

// TestInspectDoesNotPanic runs the real collection once. Its result depends
// on the machine, so only the invariants are checked.
func TestInspectDoesNotPanic(t *testing.T) {
	s := Inspect()
	if s.Smart.State == "" || s.TUN.State == "" {
		t.Errorf("empty state: %+v", s)
	}
}
