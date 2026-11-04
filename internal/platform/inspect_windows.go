//go:build windows

package platform

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// netClassKey is the device class key of network adapters (HKLM). Each
// numbered subkey describes one adapter driver instance.
const netClassKey = `SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}`

// collect gathers raw facts. Everything here is read-only: registry keys are
// opened with QUERY_VALUE / ENUMERATE_SUB_KEYS access, adapters are listed
// and the route table is queried; no setting is changed and no packet sent.
func collect() Facts {
	f := Facts{OS: OSWindows, Smart: readSmart()}
	adapters, err := listAdapters()
	if err != nil {
		f.NetErr = err.Error()
	} else {
		f.Adapters = adapters
	}
	idx, err := egressIfIndex()
	if err != nil {
		f.EgressErr = err.Error()
	} else {
		f.EgressIfIndex = idx
	}
	return f
}

func readSmart() SmartFacts {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, SmartKeyPath, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return SmartFacts{}
	}
	if err != nil {
		return SmartFacts{Err: err.Error()}
	}
	defer k.Close()

	// A nil buffer returns the value type only.
	_, typ, err := k.GetValue(SmartValueName, nil)
	if errors.Is(err, registry.ErrNotExist) {
		return SmartFacts{}
	}
	if err != nil {
		return SmartFacts{Err: err.Error()}
	}
	if typ != registry.DWORD {
		return SmartFacts{Present: true, Type: RegistryTypeName(typ)}
	}
	v, _, err := k.GetIntegerValue(SmartValueName)
	if err != nil {
		return SmartFacts{Err: err.Error()}
	}
	return SmartFacts{Present: true, IsDWORD: true, Value: uint32(v)}
}

// componentIDs maps NetCfgInstanceId (adapter GUID, upper case) to the
// driver ComponentId, read from the network class key. Subkeys that cannot
// be opened (e.g. "Properties" denies access to normal users) are skipped.
// ok is false when the class key itself cannot be enumerated.
func componentIDs() (ids map[string]string, ok bool) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, netClassKey, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, false
	}
	defer k.Close()
	names, err := k.ReadSubKeyNames(-1)
	if err != nil && len(names) == 0 {
		return nil, false
	}
	ids = map[string]string{}
	for _, name := range names {
		sk, err := registry.OpenKey(k, name, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		guid, _, err1 := sk.GetStringValue("NetCfgInstanceId")
		// A readable instance without ComponentId is known not to be
		// wintun (wintun always sets it): record "" so that the fallback
		// rule is not applied to it.
		comp, _, err2 := sk.GetStringValue("ComponentId")
		sk.Close()
		if err1 == nil && guid != "" && (err2 == nil || errors.Is(err2, registry.ErrNotExist)) {
			if err2 != nil {
				comp = ""
			}
			ids[strings.ToUpper(guid)] = comp
		}
	}
	return ids, true
}

func listAdapters() ([]Adapter, error) {
	const flags = windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_DNS_SERVER
	size := uint32(16 << 10)
	var buf []byte
	for i := 0; ; i++ {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0,
			(*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) || i >= 4 {
			return nil, err
		}
	}

	ids, idsOK := componentIDs()
	var out []Adapter
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); aa != nil; aa = aa.Next {
		a := Adapter{
			Name:        windows.UTF16PtrToString(aa.FriendlyName),
			Description: windows.UTF16PtrToString(aa.Description),
			GUID:        windows.BytePtrToString(aa.AdapterName),
			IfIndex:     aa.IfIndex,
			IfType:      aa.IfType,
			Up:          aa.OperStatus == windows.IfOperStatusUp,
		}
		for u := aa.FirstUnicastAddress; u != nil; u = u.Next {
			ip := u.Address.IP()
			if ip4 := ip.To4(); ip4 != nil && len(ip) == net.IPv4len {
				a.IPv4 = append(a.IPv4, ip4.String()+"/"+strconv.Itoa(int(u.OnLinkPrefixLength)))
			}
		}
		comp, known := "", false
		if idsOK {
			comp, known = ids[strings.ToUpper(a.GUID)]
		}
		a.Wintun, a.MatchedBy = ClassifyWintun(a.IfType, a.Description, comp, known)
		out = append(out, a)
	}
	return out, nil
}

// egressIfIndex returns the interface of the best route to EgressProbe.
// GetBestInterfaceEx only consults the route table.
func egressIfIndex() (uint32, error) {
	ip := net.ParseIP(EgressProbe).To4()
	sa := &windows.SockaddrInet4{}
	copy(sa.Addr[:], ip)
	var idx uint32
	if err := windows.GetBestInterfaceEx(sa, &idx); err != nil {
		return 0, err
	}
	return idx, nil
}
