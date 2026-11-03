// Package testutil builds rule data (.mrs, GeoSite.dat) for tests, so no
// binary fixtures need to be committed. It is only imported by tests.
package testutil

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"sort"

	"github.com/klauspost/compress/zstd"
	"github.com/metacubex/mihomo/component/cidr"
	"github.com/metacubex/mihomo/component/trie"
	"google.golang.org/protobuf/encoding/protowire"
)

// mrs wraps body the way rules/provider/mrs_converter.go does.
func mrs(behavior byte, count int, body func(w *bytes.Buffer) error) ([]byte, error) {
	var raw bytes.Buffer
	raw.Write([]byte{'M', 'R', 'S', 1})
	raw.WriteByte(behavior)
	_ = binary.Write(&raw, binary.BigEndian, int64(count))
	_ = binary.Write(&raw, binary.BigEndian, int64(0)) // extra length
	if err := body(&raw); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	enc, err := zstd.NewWriter(&out)
	if err != nil {
		return nil, err
	}
	if _, err := enc.Write(raw.Bytes()); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// DomainMrs builds a behavior=domain .mrs file.
func DomainMrs(domains []string) ([]byte, error) {
	var b trie.DomainSetBuilder
	for _, d := range domains {
		if err := b.Insert(d); err != nil {
			return nil, err
		}
	}
	set := b.Build()
	return mrs(0, len(domains), func(w *bytes.Buffer) error { return set.WriteBin(w) })
}

// IPCIDRMrs builds a behavior=ipcidr .mrs file.
func IPCIDRMrs(cidrs []string) ([]byte, error) {
	set := cidr.NewIpCidrSet()
	for _, c := range cidrs {
		if err := set.AddIpCidrForString(c); err != nil {
			return nil, err
		}
	}
	if err := set.Merge(); err != nil {
		return nil, err
	}
	return mrs(1, len(cidrs), func(w *bytes.Buffer) error { return set.WriteBin(w) })
}

// GeoSite domain types.
const (
	GeoPlain  = 0
	GeoRegex  = 1
	GeoSuffix = 2
	GeoFull   = 3
)

// GeoDomain is one entry of a geosite list.
type GeoDomain struct {
	Type  int
	Value string
	Attrs []string
}

// GeoSiteDat encodes lists as a v2ray GeoSiteList protobuf.
func GeoSiteDat(lists map[string][]GeoDomain) []byte {
	names := make([]string, 0, len(lists))
	for n := range lists {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []byte
	for _, name := range names {
		var site []byte
		site = protowire.AppendTag(site, 1, protowire.BytesType)
		site = protowire.AppendString(site, name)
		for _, d := range lists[name] {
			var dom []byte
			dom = protowire.AppendTag(dom, 1, protowire.VarintType)
			dom = protowire.AppendVarint(dom, uint64(d.Type))
			dom = protowire.AppendTag(dom, 2, protowire.BytesType)
			dom = protowire.AppendString(dom, d.Value)
			for _, a := range d.Attrs {
				var attr []byte
				attr = protowire.AppendTag(attr, 1, protowire.BytesType)
				attr = protowire.AppendString(attr, a)
				attr = protowire.AppendTag(attr, 2, protowire.VarintType)
				attr = protowire.AppendVarint(attr, 1)
				dom = protowire.AppendTag(dom, 3, protowire.BytesType)
				dom = protowire.AppendBytes(dom, attr)
			}
			site = protowire.AppendTag(site, 2, protowire.BytesType)
			site = protowire.AppendBytes(site, dom)
		}
		out = protowire.AppendTag(out, 1, protowire.BytesType)
		out = protowire.AppendBytes(out, site)
	}
	return out
}

// WriteFile writes data to path, creating parent directories.
func WriteFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
