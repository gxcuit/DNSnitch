// Package platform inspects the local operating system (read-only) for the
// two settings behind the Windows TUN DNS leak: whether TUN mode is actually
// active and whether smart multi-homed name resolution is disabled.
//
// It returns language-neutral codes only; report renders them. It imports no
// other internal package. Collection (inspect_*.go) is separated from the
// pure decision logic (Decide) so that every combination can be tested on
// any OS without touching the machine.
package platform

import "strings"

// OSWindows is runtime.GOOS on Windows.
const OSWindows = "windows"

// Registry location of the "Turn off smart multi-homed name resolution"
// group policy (HKEY_LOCAL_MACHINE).
const (
	SmartKeyRoot   = `HKLM`
	SmartKeyPath   = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`
	SmartValueName = "DisableSmartNameResolution"
)

// EgressProbe is the public address whose best route identifies the
// internet egress adapter. Only the route table is queried; nothing is sent.
const EgressProbe = "1.1.1.1"

// IfTypePropVirtual is IF_TYPE_PROP_VIRTUAL (wintun adapters report it).
const IfTypePropVirtual = 53

// WintunComponentID is the driver ComponentId of wintun adapters.
const WintunComponentID = "wintun"

// How an adapter was identified as wintun (Adapter.MatchedBy).
const (
	MatchedByComponentID = "component-id"
	MatchedByFallback    = "fallback"
)

// Adapter is one network adapter as reported by the OS.
type Adapter struct {
	Name        string   `json:"name"`        // friendly name, e.g. "Mihomo"
	Description string   `json:"description"` // e.g. "Meta Tunnel"
	GUID        string   `json:"guid"`        // AdapterName / NetCfgInstanceId
	IfIndex     uint32   `json:"if_index"`
	IfType      uint32   `json:"if_type"`
	Up          bool     `json:"up"`
	IPv4        []string `json:"ipv4"` // CIDR, e.g. "198.18.0.1/30"
	Wintun      bool     `json:"wintun"`
	MatchedBy   string   `json:"matched_by,omitempty"` // MatchedBy* when Wintun
}

// SmartFacts is the raw registry read of SmartValueName.
type SmartFacts struct {
	Present bool   // the key and the value exist
	IsDWORD bool   // value type is REG_DWORD
	Value   uint32 // valid when Present && IsDWORD
	Type    string // registry type name when Present && !IsDWORD
	Err     string // read failure other than "does not exist"
}

// Facts is the raw result of collection, before any decision.
type Facts struct {
	OS            string
	Smart         SmartFacts
	Adapters      []Adapter
	EgressIfIndex uint32 // best interface towards EgressProbe; 0 = none
	NetErr        string // adapter enumeration failed
	EgressErr     string // route lookup failed
}

// ClassifyWintun decides whether an adapter is a wintun adapter.
// componentID is the driver ComponentId found in the network class registry
// key for the adapter; known reports whether it could be read at all.
//
// Primary rule: ComponentId equals "wintun" (case-insensitive).
// Fallback (ComponentId not readable): IfType 53 and a description ending in
// " Tunnel" (wintun's naming, e.g. "Meta Tunnel", "WireGuard Tunnel").
func ClassifyWintun(ifType uint32, description, componentID string, known bool) (bool, string) {
	if known {
		if strings.EqualFold(strings.TrimSpace(componentID), WintunComponentID) {
			return true, MatchedByComponentID
		}
		return false, ""
	}
	if ifType == IfTypePropVirtual && strings.HasSuffix(strings.TrimSpace(description), " Tunnel") {
		return true, MatchedByFallback
	}
	return false, ""
}
