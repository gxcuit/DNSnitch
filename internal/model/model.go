// Package model holds the plain data structures shared by every other
// package. It must not import any internal package.
package model

// Severity of a finding. Higher values are more severe.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Error
)

// String returns the English enum used in JSON output.
func (s Severity) String() string {
	switch s {
	case Error:
		return "error"
	case High:
		return "high"
	case Medium:
		return "medium"
	case Low:
		return "low"
	default:
		return "info"
	}
}

// Severities lists all severities from most to least severe.
var Severities = []Severity{Error, High, Medium, Low, Info}

// Location roles, used by the report to label each location.
const (
	RoleTrigger      = "trigger"       // rule that triggers local resolution
	RoleTriggerEntry = "trigger-entry" // entry inside a rule-set / logic rule that triggers
	RoleAffected     = "affected"      // rule whose domains get resolved
	RoleResolver     = "resolver"      // DNS server that receives the query
	RoleConfig       = "config"        // the offending config item itself
	RoleRelated      = "related"       // supporting context
)

// Location points at a place in the config or a rule-set file.
type Location struct {
	File string `json:"file"`
	Line int    `json:"line"` // 1-based; 0 = unknown
	Path string `json:"path,omitempty"`
	Text string `json:"text,omitempty"`
	Role string `json:"role,omitempty"`
	// Resolver is set on "affected" locations: which resolver receives the
	// queries for the domains of that location.
	Resolver *ResolverInfo `json:"resolver,omitempty"`
}

// Resolver source codes for ResolverInfo.Source.
const (
	ResolverSystem             = "system"              // mihomo DNS disabled
	ResolverPolicy             = "policy"              // a nameserver-policy entry
	ResolverFallback           = "fallback"            // fallback only (fallback-filter hit)
	ResolverNameserver         = "nameserver"          // nameserver
	ResolverNameserverFallback = "nameserver+fallback" // nameserver ∪ fallback
)

// ResolverInfo summarizes the resolver selected for a set of domains.
type ResolverInfo struct {
	Level     string `json:"level"`  // plain / cn / foreign / safe
	Source    string `json:"source"` // one of the Resolver* codes
	PolicyKey string `json:"policy_key,omitempty"`
}

// WithRole returns a copy of l with the given role.
func (l Location) WithRole(role string) Location {
	l.Role = role
	return l
}

// Args are template parameters for user-facing text. Values are config
// text or language-neutral codes; the report layer turns them into prose.
type Args map[string]string

// Note is an assumption or remark attached to a finding, rendered by the
// report layer from Key.
type Note struct {
	Key  string
	Args Args
}

// Finding is one check result. Message / fix / note text is produced by the
// report layer from ID + Args so that all prose lives in one place.
type Finding struct {
	ID        string
	Severity  Severity
	Args      Args
	Locations []Location
	Notes     []Note
}

// Tri is a three-valued match result.
type Tri int

const (
	No Tri = iota
	Yes
	Unknown
)

// PolicyClass is the classification of a proxy / group / built-in policy.
type PolicyClass int

const (
	PolicyDirect PolicyClass = iota
	PolicyProxy
	PolicyReject
	PolicyPass
)

// String returns a language-neutral code.
func (c PolicyClass) String() string {
	switch c {
	case PolicyProxy:
		return "proxy"
	case PolicyReject:
		return "reject"
	case PolicyPass:
		return "pass"
	default:
		return "direct"
	}
}

// Rule is a parsed rule line (top-level, sub-rule, classical entry or a
// logic sub-rule).
type Rule struct {
	Index     int // position in its list
	Raw       string
	Type      string // upper case
	Payload   string
	Target    string // empty for classical entries and logic sub-rules
	Params    []string
	NoResolve bool
	Src       bool
	Subs      []Rule // logic rule children
	Err       string // parse error, if any
	Loc       Location
	// Span is set on logic sub-rules only: the byte range [start, end) of
	// the sub-rule text between its parentheses, as an offset into the Raw
	// of the top-level rule (also for nested sub-rules). Raw[Span[1]] is
	// the closing parenthesis. Zero for top-level rules.
	Span [2]int
}

// RuleProvider is a rule-providers entry.
type RuleProvider struct {
	Name        string
	Type        string // file / http / inline
	Behavior    string // domain / ipcidr / classical
	Format      string // yaml / text / mrs
	Path        string
	URL         string
	Payload     []string
	PayloadLocs []Location
	HasPayload  bool
	Loc         Location
}

// NameRef is a name with the location where it appears.
type NameRef struct {
	Name string
	Loc  Location
}

// ProxyGroup is a proxy-groups entry.
type ProxyGroup struct {
	Name       string
	Type       string
	Members    []NameRef
	Use        []string
	IncludeAll bool // include-all / include-all-proxies / include-all-providers
	Loc        Location
}

// Grade is the safety grade of a DNS server.
type Grade int

const (
	GradePlain Grade = iota
	GradeEncrypted
	GradeViaProxy
	GradeSafe
)

// Region of an encrypted, directly-connected DNS server.
type Region int

const (
	RegionUnknown Region = iota
	RegionCN
	RegionForeign
)

// DNSServer is one DNS server entry.
type DNSServer struct {
	Raw          string
	Scheme       string // normalized scheme; "" never after parsing
	Host         string // host without port, IPv6 without brackets
	ProxyName    string // #name fragment, if any
	Invalid      bool   // unsupported scheme or malformed
	Grade        Grade
	Region       Region
	ViaRules     bool // graded "via proxy" because of respect-rules / #RULES
	ProxyMissing bool // #name refers to a policy that does not exist
	Loc          Location
}

// DNSList is a list-valued DNS key.
type DNSList struct {
	Present bool
	Servers []DNSServer
	Loc     Location // location of the key
}

// PolicyEntry is one nameserver-policy entry.
type PolicyEntry struct {
	Key     string
	Subkeys []string // e.g. "geosite:cn", "rule-set:x", "+.lan"
	Servers []DNSServer
	Loc     Location
}

// FallbackFilter holds the parts of dns.fallback-filter that matter here.
type FallbackFilter struct {
	Domain    []string
	Geosite   []string
	Loc       Location
	HasDomain bool
}

// DNSConfig is the dns section.
type DNSConfig struct {
	Present                     bool
	Loc                         Location
	Enable                      bool
	EnableLoc                   Location
	RespectRules                bool
	RespectRulesLoc             Location
	FallbackLazyQuery           bool
	Nameserver                  DNSList
	Fallback                    DNSList
	DefaultNameserver           DNSList
	ProxyServerNameserver       DNSList
	DirectNameserver            DNSList
	NameserverPolicy            []PolicyEntry
	ProxyServerNameserverPolicy []PolicyEntry
	FallbackFilter              FallbackFilter
}

// UnknownKey is a key not recognized by mihomo.
type UnknownKey struct {
	Section string // "" for top level, "dns", "dns.fallback-filter"
	Key     string
	Loc     Location
	Anchor  bool // the value defines a YAML anchor: a helper key, not a typo
}

// HostEntry is a key of the hosts section.
type HostEntry struct {
	Pattern string
	Loc     Location
}

// Config is the analysed subset of a mihomo config file.
type Config struct {
	File           string
	Proxies        []NameRef
	ProxyGroups    []ProxyGroup
	ProxyProviders []NameRef
	RuleProviders  []RuleProvider
	Rules          []Rule
	RulesLoc       Location
	SubRules       map[string][]Rule
	Hosts          []HostEntry
	DNS            DNSConfig
	UnknownKeys    []UnknownKey
}

// RuleProvider returns the provider with the given name.
func (c *Config) RuleProvider(name string) *RuleProvider {
	for i := range c.RuleProviders {
		if c.RuleProviders[i].Name == name {
			return &c.RuleProviders[i]
		}
	}
	return nil
}
