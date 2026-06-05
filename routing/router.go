package routing

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/itsmatinhimself/mattlab/config"
)

// matcher is implemented by both DomainList and GeoIPMatcher.
type matcher interface {
	Match(host string) bool
}

type ipMatcher interface {
	MatchIP(ip net.IP) bool
}

// Router resolves hostnames to outbound tags based on the config routes.
type Router struct {
	routes         []routeEntry
	defaultTag     string
	resolver       *net.Resolver
	resolveTimeout time.Duration
	cacheMu        sync.Mutex
	ipCache        map[string]ipCacheEntry
}

type routeEntry struct {
	m   matcher
	ipm ipMatcher
	tag string
}

type ipCacheEntry struct {
	ips     []net.IP
	expires time.Time
}

// NewRouter creates a Router from config. cfgDir is used to resolve
// relative domain file paths.
func NewRouter(routes []config.Route, defaultTag string, cfgDir string) (*Router, error) {
	r := &Router{
		defaultTag:     defaultTag,
		resolver:       net.DefaultResolver,
		resolveTimeout: 2 * time.Second,
		ipCache:        make(map[string]ipCacheEntry),
	}
	binaryFiles := make(map[string][]byte)
	readBinary := func(path string) ([]byte, error) {
		if data, ok := binaryFiles[path]; ok {
			return data, nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		binaryFiles[path] = data
		return data, nil
	}

	for _, rt := range routes {
		var m matcher
		var ipm ipMatcher
		var err error

		switch {
		case rt.Domains != "":
			domainPath := filepath.Join(cfgDir, rt.Domains)
			m, err = LoadDomainList(domainPath)
			if err != nil {
				return nil, fmt.Errorf("load domain list %q: %w", rt.Domains, err)
			}
			if dl := m.(*DomainList); dl.HasIPRules() {
				ipm = dl
			}
		case rt.GeoSite != "" && rt.GeoCode != "":
			geoPath := filepath.Join(cfgDir, rt.GeoSite)
			var data []byte
			data, err = readBinary(geoPath)
			if err == nil {
				m, err = loadGeoSite(data, geoPath, rt.GeoCode)
			}
			if err != nil {
				return nil, fmt.Errorf("load geosite %q code %q: %w", rt.GeoSite, rt.GeoCode, err)
			}
		case rt.GeoIP != "" && rt.GeoCode != "":
			geoPath := filepath.Join(cfgDir, rt.GeoIP)
			var data []byte
			data, err = readBinary(geoPath)
			if err == nil {
				m, err = loadGeoIP(data, geoPath, rt.GeoCode)
			}
			if err != nil {
				return nil, fmt.Errorf("load geoip %q code %q: %w", rt.GeoIP, rt.GeoCode, err)
			}
			ipm = m.(*GeoIPMatcher)
		}

		r.routes = append(r.routes, routeEntry{m: m, ipm: ipm, tag: rt.Outbound})
	}

	return r, nil
}

// Classify returns the outbound tag for a hostname.
// First match wins. Falls back to defaultTag.
func (r *Router) Classify(hostname string) string {
	hostname = normalizeHost(hostname)
	var resolved []net.IP
	resolvedHost := false

	for _, re := range r.routes {
		if re.m.Match(hostname) {
			return re.tag
		}
		if re.ipm == nil {
			continue
		}
		if ip := net.ParseIP(hostname); ip != nil {
			if re.ipm.MatchIP(ip) {
				return re.tag
			}
			continue
		}
		if !resolvedHost {
			resolved = r.resolve(hostname)
			resolvedHost = true
		}
		for _, ip := range resolved {
			if re.ipm.MatchIP(ip) {
				return re.tag
			}
		}
	}
	return r.defaultTag
}

func (r *Router) resolve(hostname string) []net.IP {
	now := time.Now()
	r.cacheMu.Lock()
	if entry, ok := r.ipCache[hostname]; ok && now.Before(entry.expires) {
		r.cacheMu.Unlock()
		return entry.ips
	}
	r.cacheMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), r.resolveTimeout)
	defer cancel()
	addrs, err := r.resolver.LookupIPAddr(ctx, hostname)

	ttl := 30 * time.Second
	ips := make([]net.IP, 0, len(addrs))
	if err == nil {
		ttl = 5 * time.Minute
		for _, addr := range addrs {
			ips = append(ips, addr.IP)
		}
	}

	r.cacheMu.Lock()
	r.ipCache[hostname] = ipCacheEntry{ips: ips, expires: now.Add(ttl)}
	r.cacheMu.Unlock()
	return ips
}

func normalizeHost(hostname string) string {
	hostname = strings.TrimSpace(hostname)
	if host, _, err := net.SplitHostPort(hostname); err == nil {
		hostname = host
	}
	return strings.ToLower(strings.Trim(strings.TrimRight(hostname, "."), "[]"))
}
