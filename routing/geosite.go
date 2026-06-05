package routing

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// GeoSiteMatcher matches hostnames against one category loaded from an
// Xray/V2Ray geosite.dat file.
type GeoSiteMatcher struct {
	full    map[string]bool
	domains []string
	plain   []string
	regex   []*regexp.Regexp
}

// LoadGeoSite reads an Xray/V2Ray geosite.dat file and returns the requested
// category matcher (case-insensitive, e.g. "google" or "category-ads-all").
func LoadGeoSite(path, code string) (*GeoSiteMatcher, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read geosite: %w", err)
	}
	return loadGeoSite(data, path, code)
}

func loadGeoSite(data []byte, source, code string) (*GeoSiteMatcher, error) {
	target := strings.ToUpper(code)
	pos := 0
	for pos < len(data) {
		tag, n := pbVarint(data[pos:])
		if n == 0 {
			break
		}
		pos += n
		if tag>>3 == 1 && tag&7 == 2 {
			length, n := pbVarint(data[pos:])
			if n == 0 {
				break
			}
			pos += n
			end := pos + int(length)
			if end > len(data) {
				break
			}
			matcher, matched, err := parseGeoSiteEntry(data[pos:end], target)
			pos = end
			if err != nil {
				return nil, err
			}
			if matched {
				return matcher, nil
			}
			continue
		}
		pos += pbSkip(data[pos:], int(tag&7))
	}
	return nil, fmt.Errorf("geosite: code %q not found in %s", code, source)
}

// Match checks the hostname against full, domain-suffix, substring, and regex
// rules from the geosite category.
func (m *GeoSiteMatcher) Match(host string) bool {
	host = strings.ToLower(strings.TrimRight(host, "."))
	if m.full[host] {
		return true
	}
	for _, domain := range m.domains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	for _, plain := range m.plain {
		if strings.Contains(host, plain) {
			return true
		}
	}
	for _, re := range m.regex {
		if re.MatchString(host) {
			return true
		}
	}
	return false
}

func parseGeoSiteEntry(data []byte, target string) (*GeoSiteMatcher, bool, error) {
	var code string
	var domainBlobs [][]byte
	pos := 0
	for pos < len(data) {
		tag, n := pbVarint(data[pos:])
		if n == 0 {
			break
		}
		pos += n
		field, wire := int(tag>>3), int(tag&7)
		if wire != 2 {
			pos += pbSkip(data[pos:], wire)
			continue
		}
		length, n := pbVarint(data[pos:])
		if n == 0 {
			break
		}
		pos += n
		end := pos + int(length)
		if end > len(data) {
			break
		}
		blob := data[pos:end]
		pos = end

		switch field {
		case 1:
			code = strings.ToUpper(string(blob))
		case 2:
			domainBlobs = append(domainBlobs, blob)
		}
	}
	if code != target {
		return nil, false, nil
	}

	matcher := &GeoSiteMatcher{full: make(map[string]bool)}
	for _, blob := range domainBlobs {
		if err := matcher.addDomain(blob); err != nil {
			return nil, false, fmt.Errorf("geosite %q: %w", code, err)
		}
	}
	return matcher, true, nil
}

func (m *GeoSiteMatcher) addDomain(data []byte) error {
	var kind uint64
	var value string
	pos := 0
	for pos < len(data) {
		tag, n := pbVarint(data[pos:])
		if n == 0 {
			break
		}
		pos += n
		field, wire := int(tag>>3), int(tag&7)
		switch {
		case field == 1 && wire == 0:
			kind, n = pbVarint(data[pos:])
			if n == 0 {
				return fmt.Errorf("invalid domain type")
			}
			pos += n
		case field == 2 && wire == 2:
			length, n := pbVarint(data[pos:])
			if n == 0 {
				return fmt.Errorf("invalid domain value")
			}
			pos += n
			end := pos + int(length)
			if end > len(data) {
				return fmt.Errorf("domain value exceeds record")
			}
			value = strings.ToLower(string(data[pos:end]))
			pos = end
		default:
			pos += pbSkip(data[pos:], wire)
		}
	}

	switch kind {
	case 0: // Plain: substring
		m.plain = append(m.plain, value)
	case 1: // Regex
		re, err := regexp.Compile(value)
		if err != nil {
			return fmt.Errorf("compile regex %q: %w", value, err)
		}
		m.regex = append(m.regex, re)
	case 2: // Domain: hostname or any subdomain
		m.domains = append(m.domains, strings.TrimPrefix(value, "."))
	case 3: // Full hostname
		m.full[value] = true
	default:
		return fmt.Errorf("unknown domain type %d", kind)
	}
	return nil
}
