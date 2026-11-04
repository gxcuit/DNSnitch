package platform

import "strconv"

// States (language-neutral codes; report translates them).
const (
	StateOn  = "on"  // TUN: active
	StateOff = "off" // TUN: not active

	StateDisabled = "disabled" // smart name resolution disabled (safe)
	StateEnabled  = "enabled"  // smart name resolution in effect (Windows default)

	StateUnknown     = "unknown"
	StateUnsupported = "unsupported"
)

// Reason codes explaining a state.
const (
	ReasonUnsupportedOS = "unsupported-os"

	// Smart name resolution.
	ReasonNotSet          = "not-set"          // key or value missing: Windows default
	ReasonValue           = "value"            // DWORD 0 or 1
	ReasonNotDWORD        = "not-dword"        // value has another type
	ReasonUnexpectedValue = "unexpected-value" // DWORD other than 0 / 1
	ReasonReadError       = "read-error"

	// TUN.
	ReasonAdapterEgress    = "adapter-egress"     // wintun adapter is the egress
	ReasonNoAdapter        = "no-adapter"         // no enabled wintun adapter
	ReasonAdapterNotEgress = "adapter-not-egress" // wintun adapter present, egress elsewhere
	ReasonNetError         = "net-error"          // adapters could not be listed
	ReasonEgressError      = "egress-error"       // route lookup failed with wintun present
)

// NoteAdapterNotEgress marks a wintun adapter that carries no internet
// traffic (auto-route probably off).
const NoteAdapterNotEgress = "adapter-not-egress"

// SmartStatus is the decided state of smart multi-homed name resolution.
type SmartStatus struct {
	State     string  // State*
	Reason    string  // Reason*
	Value     *uint32 // DWORD value when read
	ValueType string  // registry type name when not a DWORD
	KeyPath   string  // full key, e.g. HKLM\SOFTWARE\...\DNSClient
	ValueName string
	Error     string // OS error text for ReasonReadError
}

// TUNStatus is the decided state of TUN mode.
type TUNStatus struct {
	State         string   // State*
	Reason        string   // Reason*
	Adapter       *Adapter // the wintun adapter (the egress one when several)
	Egress        *Adapter // adapter of EgressIfIndex, if listed
	EgressIfIndex uint32
	Note          string // Note*
	Error         string // OS error text for net-error / egress-error
}

// Snapshot is the decided system status.
type Snapshot struct {
	OS    string
	Smart SmartStatus
	TUN   TUNStatus
	// Risk: TUN is on and smart name resolution is not disabled, so DNS
	// queries are certain to leak past TUN. Unknown states are no risk.
	Risk bool
}

// Inspect reads the current system state (read-only) and decides it.
func Inspect() Snapshot { return Decide(collect()) }

// Decide turns raw facts into states. It is pure.
func Decide(f Facts) Snapshot {
	s := Snapshot{OS: f.OS, Smart: decideSmart(f), TUN: decideTUN(f)}
	s.Risk = s.TUN.State == StateOn && s.Smart.State == StateEnabled
	return s
}

func decideSmart(f Facts) SmartStatus {
	s := SmartStatus{KeyPath: SmartKeyRoot + `\` + SmartKeyPath, ValueName: SmartValueName}
	sf := f.Smart
	switch {
	case f.OS != OSWindows:
		s.State, s.Reason = StateUnsupported, ReasonUnsupportedOS
	case sf.Err != "":
		s.State, s.Reason, s.Error = StateUnknown, ReasonReadError, sf.Err
	case !sf.Present:
		s.State, s.Reason = StateEnabled, ReasonNotSet
	case !sf.IsDWORD:
		s.State, s.Reason, s.ValueType = StateUnknown, ReasonNotDWORD, sf.Type
	default:
		v := sf.Value
		s.Value = &v
		switch v {
		case 0:
			s.State, s.Reason = StateEnabled, ReasonValue
		case 1:
			s.State, s.Reason = StateDisabled, ReasonValue
		default:
			s.State, s.Reason = StateUnknown, ReasonUnexpectedValue
		}
	}
	return s
}

func decideTUN(f Facts) TUNStatus {
	t := TUNStatus{EgressIfIndex: f.EgressIfIndex}
	switch {
	case f.OS != OSWindows:
		t.State, t.Reason = StateUnsupported, ReasonUnsupportedOS
		return t
	case f.NetErr != "":
		t.State, t.Reason, t.Error = StateUnknown, ReasonNetError, f.NetErr
		return t
	}
	var wintun []Adapter
	for _, a := range f.Adapters {
		if f.EgressIfIndex != 0 && a.IfIndex == f.EgressIfIndex {
			e := cloneAdapter(a)
			t.Egress = &e
		}
		if a.Up && a.Wintun {
			wintun = append(wintun, a)
		}
	}
	if len(wintun) == 0 {
		t.State, t.Reason = StateOff, ReasonNoAdapter
		return t
	}
	for _, a := range wintun {
		if f.EgressIfIndex != 0 && a.IfIndex == f.EgressIfIndex {
			w := cloneAdapter(a)
			t.Adapter = &w
			t.State, t.Reason = StateOn, ReasonAdapterEgress
			return t
		}
	}
	w := cloneAdapter(wintun[0])
	t.Adapter = &w
	if f.EgressIfIndex == 0 && f.EgressErr != "" {
		t.State, t.Reason, t.Error = StateUnknown, ReasonEgressError, f.EgressErr
		return t
	}
	t.State, t.Reason, t.Note = StateOff, ReasonAdapterNotEgress, NoteAdapterNotEgress
	return t
}

func cloneAdapter(a Adapter) Adapter {
	a.IPv4 = append([]string(nil), a.IPv4...)
	return a
}

// RegistryTypeName names a registry value type (REG_*); unknown types are
// shown as REG_TYPE_<n>.
func RegistryTypeName(t uint32) string {
	names := []string{"REG_NONE", "REG_SZ", "REG_EXPAND_SZ", "REG_BINARY", "REG_DWORD",
		"REG_DWORD_BIG_ENDIAN", "REG_LINK", "REG_MULTI_SZ", "REG_RESOURCE_LIST",
		"REG_FULL_RESOURCE_DESCRIPTOR", "REG_RESOURCE_REQUIREMENTS_LIST", "REG_QWORD"}
	if int(t) < len(names) {
		return names[t]
	}
	return "REG_TYPE_" + strconv.FormatUint(uint64(t), 10)
}
