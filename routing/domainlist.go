package routing

import (
	"bufio"
	"os"
	"strings"
)

// Rule represents a single domain matching rule.
type Rule struct {
	Exact   string // exact match (e.g. "youtube.com")
	Suffix  string // suffix match (e.g. ".youtube.com")
	Keyword string // keyword/contains match (e.g. "blogspot")
}

// DomainList holds parsed rules loaded from a .txt file.
type DomainList struct {
	Exact    map[string]bool
	Suffixes []string
	Keywords []string
}

// LoadDomainList reads a domain list file.
// Format: one rule per line.
//   - "example.com"  → exact match
//   - ".example.com" → suffix match (matches *.example.com AND example.com)
//   - "~keyword"     → keyword/contains match
//   - Empty lines and lines starting with # are ignored.
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

// Match checks if a hostname matches any rule in the list.
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
	return false
}
