package ruledata

import (
	"errors"

	"dnsleak/internal/model"
)

// Reason codes for GeoSite lookups.
const (
	ReasonGeoSiteMissing = "geosite-missing" // <home>/GeoSite.dat does not exist
	ReasonGeoSiteError   = "geosite-error"   // GeoSite.dat cannot be read / decoded
	ReasonGeoSiteNoList  = "geosite-no-list" // the list is not in GeoSite.dat
)

// Store caches provider contents and GeoSite data for one config.
type Store struct {
	Home      string
	cfg       *model.Config
	providers map[string]*Provider
	geo       *GeoSite
	geoErr    error
	geoTried  bool
}

// NewStore creates a store; nothing is read until requested.
func NewStore(cfg *model.Config, home string) *Store {
	return &Store{Home: home, cfg: cfg, providers: map[string]*Provider{}}
}

// Provider returns the loaded provider. If it is not defined in the
// config, a Provider with Reason ReasonNotDefined and nil Def is returned.
func (s *Store) Provider(name string) *Provider {
	if p, ok := s.providers[name]; ok {
		return p
	}
	var p *Provider
	if def := s.cfg.RuleProvider(name); def != nil {
		p = LoadProvider(def, s.Home)
	} else {
		p = &Provider{Reason: ReasonNotDefined}
	}
	s.providers[name] = p
	return p
}

// GeoSite returns the GeoSite data, opening it on first use.
func (s *Store) GeoSite() (*GeoSite, error) {
	if !s.geoTried {
		s.geoTried = true
		s.geo, s.geoErr = OpenGeoSite(s.Home)
	}
	return s.geo, s.geoErr
}

// MatchGeoSite matches domain against geosite list name. When the result
// is Unknown, reason tells why.
func (s *Store) MatchGeoSite(name, domain string) (model.Tri, string) {
	g, err := s.GeoSite()
	if err != nil {
		if errors.Is(err, ErrGeoSiteMissing) {
			return model.Unknown, ReasonGeoSiteMissing
		}
		return model.Unknown, ReasonGeoSiteError
	}
	site, ok, err := g.Site(name)
	if err != nil {
		return model.Unknown, ReasonGeoSiteError
	}
	if !ok {
		return model.Unknown, ReasonGeoSiteNoList
	}
	if site.Match(domain) {
		return model.Yes, ""
	}
	return model.No, ""
}
