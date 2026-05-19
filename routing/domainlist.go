package routing

import (
	"bufio"
	"net"
	"os"
	"strings"
)

// DomainList holds parsed rules loaded from a .txt file.
type DomainList struct {
	Exact    map[string]bool
	Suffixes []string
	Keywords []string
	CIDRs    []*net.IPNet // IP range matching (e.g. 151.101.0.0/16)
}

// LoadDomainList reads a domain list file.
// Format: one rule per line.
//
//	"example.com"      → exact match
//	".example.com"     → suffix match (matches *.example.com AND example.com)
//	"~keyword"         → keyword/contains match
//	"1.2.3.0/24"       → CIDR range match (IPv4 or IPv6)
//	Empty lines and lines starting with # are ignored.
func LoadDomainList(path string) (*DomainList, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	dl := &DomainList{
		Exact: make(map[string]bool),
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.ToLower(line)

		if strings.HasPrefix(line, "~") {
			dl.Keywords = append(dl.Keywords, line[1:])
		} else if strings.Contains(line, "/") {
			// Try CIDR
			_, ipNet, err := net.ParseCIDR(line)
			if err == nil {
				dl.CIDRs = append(dl.CIDRs, ipNet)
				continue
			}
			// Not a valid CIDR — fall through to exact match
			dl.Exact[line] = true
		} else if strings.HasPrefix(line, ".") {
			dl.Suffixes = append(dl.Suffixes, line)
			// ".youtube.com" also matches "youtube.com"
			dl.Exact[line[1:]] = true
		} else {
			dl.Exact[line] = true
		}
	}

	return dl, scanner.Err()
}

// Match checks if a hostname or IP matches any rule in the list.
func (dl *DomainList) Match(hostname string) bool {
	h := strings.ToLower(strings.TrimRight(hostname, "."))

	if dl.Exact[h] {
		return true
	}
	for _, s := range dl.Suffixes {
		if strings.HasSuffix(h, s) {
			return true
		}
	}
	for _, kw := range dl.Keywords {
		if strings.Contains(h, kw) {
			return true
		}
	}
	// CIDR check — only applies when the input is a bare IP address
	if len(dl.CIDRs) > 0 {
		if ip := net.ParseIP(h); ip != nil {
			for _, cidr := range dl.CIDRs {
				if cidr.Contains(ip) {
					return true
				}
			}
		}
	}
	return false
}
