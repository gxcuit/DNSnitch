package ruledata

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
)

// GeoSite domain types (v2ray router.Domain.Type).
const (
	geoPlain  = 0 // keyword
	geoRegex  = 1
	geoDomain = 2 // suffix
	geoFull   = 3
)

// GeoSite is a lazily decoded GeoSite.dat (v2ray protobuf):
//
//	GeoSiteList { repeated GeoSite entry = 1 }
//	GeoSite     { string country_code = 1; repeated Domain domain = 2 }
//	Domain      { Type type = 1; string value = 2; repeated Attribute attribute = 3 }
//	Attribute   { string key = 1; oneof { bool bool_value = 2; int64 int_value = 3 } }
type GeoSite struct {
	Path  string
	data  []byte
	cache map[string]*Site
}

// Site is one decoded geosite list, optionally filtered by attributes.
type Site struct {
	Name    string
	domains []geoEntry
}

type geoEntry struct {
	typ   uint64
	value string
	attrs []string
	re    *regexp.Regexp
}

// ErrGeoSiteMissing is returned when <home>/GeoSite.dat does not exist.
var ErrGeoSiteMissing = errors.New("GeoSite.dat not found")

// FindGeoSite returns the path of GeoSite.dat in home (case-insensitive,
// constant/path.go).
func FindGeoSite(home string) (string, error) {
	entries, err := os.ReadDir(home)
	if err != nil {
		return "", ErrGeoSiteMissing
	}
	for _, e := range entries {
		if !e.IsDir() && strings.EqualFold(e.Name(), "GeoSite.dat") {
			return filepath.Join(home, e.Name()), nil
		}
	}
	return "", ErrGeoSiteMissing
}

// OpenGeoSite reads GeoSite.dat from home.
func OpenGeoSite(home string) (*GeoSite, error) {
	path, err := FindGeoSite(home)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return &GeoSite{Path: path, data: data, cache: map[string]*Site{}}, nil
}

var errGeoSiteCorrupt = errors.New("GeoSite.dat is corrupt")

// Site returns the list for a rule payload such as "youtube",
// "google@cn" or "geolocation-!cn". ok is false if the list is absent.
func (g *GeoSite) Site(name string) (*Site, bool, error) {
	key := strings.ToLower(strings.TrimSpace(name))
	if s, ok := g.cache[key]; ok {
		return s, s != nil, nil
	}
	parts := strings.Split(key, "@")
	list := strings.TrimSpace(parts[0])
	var attrs []string
	for _, a := range parts[1:] {
		if a = strings.TrimSpace(a); a != "" {
			attrs = append(attrs, a)
		}
	}

	raw, found, err := g.findList(list)
	if err != nil {
		return nil, false, err
	}
	if !found {
		g.cache[key] = nil
		return nil, false, nil
	}
	all, err := decodeDomains(raw)
	if err != nil {
		return nil, false, err
	}
	site := &Site{Name: key}
	for _, d := range all {
		if hasAllAttrs(d.attrs, attrs) {
			site.domains = append(site.domains, d)
		}
	}
	g.cache[key] = site
	return site, true, nil
}

func hasAllAttrs(have, want []string) bool {
	for _, w := range want {
		found := false
		for _, h := range have {
			if strings.EqualFold(h, w) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// findList scans the top-level entries and returns the raw bytes of the
// GeoSite message whose country_code equals name (case-insensitive).
func (g *GeoSite) findList(name string) ([]byte, bool, error) {
	b := g.data
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return nil, false, errGeoSiteCorrupt
		}
		b = b[n:]
		if num == 1 && typ == protowire.BytesType {
			msg, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return nil, false, errGeoSiteCorrupt
			}
			b = b[m:]
			if code, ok := countryCode(msg); ok && strings.EqualFold(code, name) {
				return msg, true, nil
			}
			continue
		}
		m := protowire.ConsumeFieldValue(num, typ, b)
		if m < 0 {
			return nil, false, errGeoSiteCorrupt
		}
		b = b[m:]
	}
	return nil, false, nil
}

func countryCode(msg []byte) (string, bool) {
	for len(msg) > 0 {
		num, typ, n := protowire.ConsumeTag(msg)
		if n < 0 {
			return "", false
		}
		msg = msg[n:]
		if num == 1 && typ == protowire.BytesType {
			v, m := protowire.ConsumeBytes(msg)
			if m < 0 {
				return "", false
			}
			return string(v), true
		}
		m := protowire.ConsumeFieldValue(num, typ, msg)
		if m < 0 {
			return "", false
		}
		msg = msg[m:]
	}
	return "", false
}

func decodeDomains(msg []byte) ([]geoEntry, error) {
	var out []geoEntry
	for len(msg) > 0 {
		num, typ, n := protowire.ConsumeTag(msg)
		if n < 0 {
			return nil, errGeoSiteCorrupt
		}
		msg = msg[n:]
		if num == 2 && typ == protowire.BytesType {
			v, m := protowire.ConsumeBytes(msg)
			if m < 0 {
				return nil, errGeoSiteCorrupt
			}
			msg = msg[m:]
			d, err := decodeDomain(v)
			if err != nil {
				return nil, err
			}
			out = append(out, d)
			continue
		}
		m := protowire.ConsumeFieldValue(num, typ, msg)
		if m < 0 {
			return nil, errGeoSiteCorrupt
		}
		msg = msg[m:]
	}
	return out, nil
}

func decodeDomain(b []byte) (geoEntry, error) {
	var d geoEntry
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return d, errGeoSiteCorrupt
		}
		b = b[n:]
		switch {
		case num == 1 && typ == protowire.VarintType:
			v, m := protowire.ConsumeVarint(b)
			if m < 0 {
				return d, errGeoSiteCorrupt
			}
			d.typ, b = v, b[m:]
		case num == 2 && typ == protowire.BytesType:
			v, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return d, errGeoSiteCorrupt
			}
			d.value, b = string(v), b[m:]
		case num == 3 && typ == protowire.BytesType:
			v, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return d, errGeoSiteCorrupt
			}
			b = b[m:]
			if key, ok := countryCode(v); ok { // Attribute.key is field 1 too
				d.attrs = append(d.attrs, key)
			}
		default:
			m := protowire.ConsumeFieldValue(num, typ, b)
			if m < 0 {
				return d, errGeoSiteCorrupt
			}
			b = b[m:]
		}
	}
	if d.typ == geoRegex {
		// Lower-casing a pattern would change escapes such as \D or \W.
		re, err := regexp.Compile(d.value)
		if err == nil {
			d.re = re
		}
	} else {
		d.value = strings.ToLower(d.value)
	}
	return d, nil
}

// Match reports whether domain is in the list.
func (s *Site) Match(domain string) bool {
	if s == nil {
		return false
	}
	domain = strings.ToLower(domain)
	for _, d := range s.domains {
		switch d.typ {
		case geoPlain:
			if strings.Contains(domain, d.value) {
				return true
			}
		case geoRegex:
			if d.re != nil && d.re.MatchString(domain) {
				return true
			}
		case geoDomain:
			if domain == d.value || strings.HasSuffix(domain, "."+d.value) {
				return true
			}
		case geoFull:
			if domain == d.value {
				return true
			}
		}
	}
	return false
}
