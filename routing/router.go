package routing

import (
	"fmt"
	"path/filepath"

	"github.com/itsmatinhimself/mattlab/config"
)

// matcher is implemented by both DomainList and GeoIPMatcher.
type matcher interface {
	Match(host string) bool
}

// Router resolves hostnames to outbound tags based on the config routes.
type Router struct {
	routes     []routeEntry
	defaultTag string
}

type routeEntry struct {
	m   matcher
	tag string
}

// NewRouter creates a Router from config. cfgDir is used to resolve
// relative domain file paths.
func NewRouter(routes []config.Route, defaultTag string, cfgDir string) (*Router, error) {
	r := &Router{defaultTag: defaultTag}

	for _, rt := range routes {
		var m matcher
		var err error

		switch {
		case rt.Domains != "":
			domainPath := filepath.Join(cfgDir, rt.Domains)
			m, err = LoadDomainList(domainPath)
			if err != nil {
				return nil, fmt.Errorf("load domain list %q: %w", rt.Domains, err)
			}
		case rt.GeoIP != "" && rt.GeoCode != "":
			geoPath := filepath.Join(cfgDir, rt.GeoIP)
			m, err = LoadGeoIP(geoPath, rt.GeoCode)
			if err != nil {
				return nil, fmt.Errorf("load geoip %q code %q: %w", rt.GeoIP, rt.GeoCode, err)
			}
		}

		r.routes = append(r.routes, routeEntry{m: m, tag: rt.Outbound})
	}

	return r, nil
}

// Classify returns the outbound tag for a hostname.
// First match wins. Falls back to defaultTag.
func (r *Router) Classify(hostname string) string {
	for _, re := range r.routes {
		if re.m.Match(hostname) {
			return re.tag
		}
	}
	return r.defaultTag
}
