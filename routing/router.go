package routing

import (
	"path/filepath"

	"github.com/itsmatinhimself/mattlab/config"
)

// Router resolves hostnames to outbound tags based on the config routes.
type Router struct {
	routes     []routeEntry
	defaultTag string
}

type routeEntry struct {
	list *DomainList
	tag  string
}

// NewRouter creates a Router from config. cfgDir is used to resolve
// relative domain file paths.
func NewRouter(routes []config.Route, defaultTag string, cfgDir string) (*Router, error) {
	r := &Router{defaultTag: defaultTag}

	for _, rt := range routes {
		domainPath := filepath.Join(cfgDir, rt.Domains)
		dl, err := LoadDomainList(domainPath)
		if err != nil {
			return nil, err
		}
		r.routes = append(r.routes, routeEntry{list: dl, tag: rt.Outbound})
	}

	return r, nil
}

// Classify returns the outbound tag for a hostname.
// First match wins. Falls back to defaultTag.
func (r *Router) Classify(hostname string) string {
	for _, re := range r.routes {
		if re.list.Match(hostname) {
			return re.tag
		}
	}
	return r.defaultTag
}
