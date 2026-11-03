// Package ruledata loads rule-provider contents and GeoSite.dat from local
// files only. Nothing is ever downloaded; missing data is reported as
// unknown with a reason code.
package ruledata

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/metacubex/mihomo/component/cidr"
	"github.com/metacubex/mihomo/component/trie"
	"gopkg.in/yaml.v3"

	"dnsleak/internal/model"
	"dnsleak/internal/ruleparse"
)

// Reason codes for unavailable provider data.
const (
	ReasonNotDefined  = "not-defined"  // RULE-SET refers to an undefined provider
	ReasonNoFile      = "no-file"      // path / cache file does not exist
	ReasonNoSource    = "no-source"    // neither payload, path nor url
	ReasonReadError   = "read-error"   // file exists but cannot be read
	ReasonParseError  = "parse-error"  // content cannot be decoded
	ReasonBadFormat   = "bad-format"   // unsupported format / behavior combination
	ReasonBadBehavior = "bad-behavior" // unknown behavior
)

// Provider is the loaded content of a rule-provider.
type Provider struct {
	Def    *model.RuleProvider
	Loaded bool
	Source string // file path, or "" for inline payload
	Reason string // set when !Loaded
	Detail string // error detail when !Loaded
	Count  int

	Domains *trie.DomainSet // behavior=domain
	CIDRs   *cidr.IpCidrSet // behavior=ipcidr
	Rules   []model.Rule    // behavior=classical
}

// CachePath returns mihomo's default cache path for an http provider
// without path: <home>/rules/<md5(url)>.
func CachePath(home, url string) string {
	sum := md5.Sum([]byte(url))
	return filepath.Join(home, "rules", hex.EncodeToString(sum[:]))
}

// resolvePath resolves a provider path relative to home like
// C.Path.Resolve.
func resolvePath(home, p string) string {
	p = filepath.FromSlash(p)
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Join(home, p)
}

// LoadProvider loads the content of def. home is mihomo's home directory.
func LoadProvider(def *model.RuleProvider, home string) *Provider {
	pv := &Provider{Def: def}
	switch def.Behavior {
	case "domain", "ipcidr", "classical":
	default:
		pv.Reason, pv.Detail = ReasonBadBehavior, def.Behavior
		return pv
	}

	if def.Type == "inline" {
		entries := make([]entry, 0, len(def.Payload))
		for i, v := range def.Payload {
			entries = append(entries, entry{v, def.PayloadLocs[i]})
		}
		pv.fill(entries)
		return pv
	}

	var file string
	switch {
	case def.Path != "":
		file = resolvePath(home, def.Path)
	case def.Type == "http" && def.URL != "":
		file = CachePath(home, def.URL)
	default:
		pv.Reason = ReasonNoSource
		return pv
	}
	pv.Source = file

	data, err := os.ReadFile(file)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			pv.Reason = ReasonNoFile
		} else {
			pv.Reason, pv.Detail = ReasonReadError, err.Error()
		}
		return pv
	}

	switch def.Format {
	case "mrs":
		if err := pv.loadMrs(data); err != nil {
			pv.Reason, pv.Detail = ReasonParseError, err.Error()
			if errors.Is(err, errMrsClassical) {
				pv.Reason = ReasonBadFormat
			}
			return pv
		}
		pv.Loaded = true
	case "text":
		pv.fill(textEntries(data, file))
	case "yaml", "":
		entries, err := yamlEntries(data, file)
		if err != nil {
			pv.Reason, pv.Detail = ReasonParseError, err.Error()
			return pv
		}
		pv.fill(entries)
	default:
		pv.Reason, pv.Detail = ReasonBadFormat, def.Format
	}
	return pv
}

type entry struct {
	value string
	loc   model.Location
}

func (pv *Provider) fill(entries []entry) {
	switch pv.Def.Behavior {
	case "domain":
		var b trie.DomainSetBuilder
		for _, e := range entries {
			if e.value == "" || strings.ContainsRune(e.value, '/') {
				continue
			}
			if b.Insert(e.value) == nil {
				pv.Count++
			}
		}
		pv.Domains = b.Build()
	case "ipcidr":
		set := cidr.NewIpCidrSet()
		for _, e := range entries {
			if e.value != "" && set.AddIpCidrForString(e.value) == nil {
				pv.Count++
			}
		}
		_ = set.Merge()
		pv.CIDRs = set
	case "classical":
		for _, e := range entries {
			if e.value == "" {
				continue
			}
			r := ruleparse.ParseClassical(e.value)
			if r.Err != "" {
				continue // mihomo logs and skips invalid entries
			}
			r.Index = len(pv.Rules)
			pv.Rules = append(pv.Rules, ruleparse.WithLoc(r, e.loc))
		}
		pv.Count = len(pv.Rules)
	}
	pv.Loaded = true
}

func textEntries(data []byte, file string) []entry {
	var out []entry
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		s := strings.TrimSpace(sc.Text())
		if s == "" || s[0] == '#' || strings.HasPrefix(s, "//") {
			continue
		}
		out = append(out, entry{s, model.Location{File: file, Line: line, Text: s}})
	}
	return out
}

func yamlEntries(data []byte, file string) ([]entry, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("no payload")
	}
	m := doc.Content[0]
	var list *yaml.Node
	for i := 0; i+1 < len(m.Content); i += 2 {
		if k := m.Content[i].Value; k == "payload" || k == "rules" {
			list = m.Content[i+1]
		}
	}
	if list == nil || list.Kind != yaml.SequenceNode {
		return nil, errors.New("no payload")
	}
	var out []entry
	for _, it := range list.Content {
		if it.Kind != yaml.ScalarNode {
			continue
		}
		out = append(out, entry{it.Value, model.Location{File: file, Line: it.Line, Text: it.Value}})
	}
	return out, nil
}

// MrsMagic is the .mrs header (rules/provider/mrs_reader.go).
var MrsMagic = [4]byte{'M', 'R', 'S', 1}

// Behavior bytes (constant/provider RuleBehavior.Byte).
const (
	mrsDomain byte = 0
	mrsIPCIDR byte = 1
)

var errMrsClassical = errors.New("classical behavior does not support mrs")

// maxMrsSize bounds the decompressed size of a .mrs file.
const maxMrsSize = 512 << 20

func (pv *Provider) loadMrs(data []byte) (err error) {
	var want byte
	switch pv.Def.Behavior {
	case "domain":
		want = mrsDomain
	case "ipcidr":
		want = mrsIPCIDR
	default:
		return errMrsClassical
	}
	dec, err := zstd.NewReader(bytes.NewReader(data), zstd.WithDecoderMaxMemory(maxMrsSize))
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(dec, maxMrsSize+1))
	dec.Close()
	if err != nil {
		return err
	}
	if len(raw) > maxMrsSize {
		return errors.New("mrs file too large")
	}
	zr := bytes.NewReader(raw)

	var header [4]byte
	if _, err := io.ReadFull(zr, header[:]); err != nil {
		return err
	}
	if header != MrsMagic {
		return errors.New("invalid mrs magic bytes")
	}
	var behavior [1]byte
	if _, err := io.ReadFull(zr, behavior[:]); err != nil {
		return err
	}
	if behavior[0] != want {
		return fmt.Errorf("mrs behavior %d does not match %q", behavior[0], pv.Def.Behavior)
	}
	var count, extra int64
	if err := binary.Read(zr, binary.BigEndian, &count); err != nil {
		return err
	}
	if err := binary.Read(zr, binary.BigEndian, &extra); err != nil {
		return err
	}
	if extra < 0 {
		return errors.New("invalid mrs extra length")
	}
	if extra > int64(zr.Len()) {
		return errors.New("invalid mrs extra length")
	}
	if _, err := io.CopyN(io.Discard, zr, extra); err != nil {
		return err
	}
	// mihomo's readers allocate slices sized by the lengths stored in the
	// file; reject lengths the remaining data cannot hold before calling
	// them, and turn any other panic on corrupt data into an error.
	if err := checkMrsBody(want, raw[len(raw)-zr.Len():]); err != nil {
		return err
	}
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("corrupt mrs data: %v", p)
		}
	}()
	pv.Count = int(count)
	if want == mrsDomain {
		pv.Domains, err = trie.ReadDomainSetBin(zr)
	} else {
		pv.CIDRs, err = cidr.ReadIpCidrSet(zr)
	}
	return err
}

// checkMrsBody validates the segment lengths of the serialized set
// (component/trie/domain_set_bin.go: version, then leaves []uint64,
// labelBitmap []uint64, labels []byte; component/cidr/ipcidr_set_bin.go:
// version, then ranges of two 16-byte addresses).
func checkMrsBody(behavior byte, b []byte) error {
	if len(b) < 1 || b[0] != 1 {
		return errors.New("invalid mrs set version")
	}
	b = b[1:]
	elems := []int64{8, 8, 1}
	if behavior == mrsIPCIDR {
		elems = []int64{32}
	}
	for _, size := range elems {
		if len(b) < 8 {
			return io.ErrUnexpectedEOF
		}
		n := int64(binary.BigEndian.Uint64(b[:8]))
		b = b[8:]
		if n < 1 || n > int64(len(b))/size {
			return errors.New("invalid mrs segment length")
		}
		b = b[n*size:]
	}
	return nil
}

// MatchDomain reports whether a domain-behavior provider contains domain.
// For classical providers only the pure domain entries are considered
// (used for nameserver-policy "rule-set:" keys).
func (pv *Provider) MatchDomain(domain string) model.Tri {
	if pv == nil || !pv.Loaded {
		return model.Unknown
	}
	switch pv.Def.Behavior {
	case "domain":
		if pv.Domains.Has(domain) {
			return model.Yes
		}
	case "classical":
		for _, r := range pv.Rules {
			if ruleparse.IsDomainType(r.Type) && r.Type != "GEOSITE" && MatchDomainRule(r, domain) == model.Yes {
				return model.Yes
			}
		}
	}
	return model.No
}
