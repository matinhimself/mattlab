package routing

import (
	"fmt"
	"net"
	"os"
	"strings"
)

// GeoIPMatcher matches bare IP addresses against CIDR ranges loaded from a
// V2Ray/Xray geoip.dat file for a specific country/provider code.
type GeoIPMatcher struct {
	nets []*net.IPNet
}

// LoadGeoIP reads a V2Ray/Xray geoip.dat file and returns a GeoIPMatcher for
// the given code (case-insensitive, e.g. "fastly", "CN").
func LoadGeoIP(path, code string) (*GeoIPMatcher, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read geoip: %w", err)
	}

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
			nets, matched, err := parseGeoIPEntry(data[pos:end], target)
			pos = end
			if err != nil || !matched {
				continue
			}
			return &GeoIPMatcher{nets: nets}, nil
		}
		pos += pbSkip(data[pos:], int(tag&7))
	}
	return nil, fmt.Errorf("geoip: code %q not found in %s", code, path)
}

// Match returns true if host is a bare IP address contained in one of the
// loaded CIDR ranges.
func (m *GeoIPMatcher) Match(host string) bool {
	ip := net.ParseIP(strings.TrimRight(host, "."))
	if ip == nil {
		return false
	}
	for _, n := range m.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// parseGeoIPEntry parses one GeoIP proto message and returns its CIDR list if
// its country_code matches target.
func parseGeoIPEntry(data []byte, target string) ([]*net.IPNet, bool, error) {
	var code string
	var nets []*net.IPNet
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
			if ipNet := parseCIDR(blob); ipNet != nil {
				nets = append(nets, ipNet)
			}
		}
	}
	return nets, code == target, nil
}

// parseCIDR parses one CIDR proto message.
func parseCIDR(data []byte) *net.IPNet {
	var ip []byte
	var prefix uint32
	pos := 0
	for pos < len(data) {
		tag, n := pbVarint(data[pos:])
		if n == 0 {
			break
		}
		pos += n
		field, wire := int(tag>>3), int(tag&7)
		switch {
		case field == 1 && wire == 2:
			length, n := pbVarint(data[pos:])
			if n == 0 {
				return nil
			}
			pos += n
			end := pos + int(length)
			if end > len(data) {
				return nil
			}
			ip = make([]byte, length)
			copy(ip, data[pos:end])
			pos = end
		case field == 2 && wire == 0:
			v, n := pbVarint(data[pos:])
			if n == 0 {
				return nil
			}
			prefix = uint32(v)
			pos += n
		default:
			pos += pbSkip(data[pos:], wire)
		}
	}
	bits := 32
	if len(ip) == 16 {
		bits = 128
	} else if len(ip) != 4 {
		return nil
	}
	return &net.IPNet{IP: net.IP(ip), Mask: net.CIDRMask(int(prefix), bits)}
}

// pbVarint decodes a protobuf varint and returns (value, bytesRead).
func pbVarint(b []byte) (uint64, int) {
	var v uint64
	for i, c := range b {
		if i >= 10 {
			return 0, 0
		}
		v |= uint64(c&0x7f) << (7 * uint(i))
		if c&0x80 == 0 {
			return v, i + 1
		}
	}
	return 0, 0
}

// pbSkip returns the byte length of a protobuf field body given its wire type.
func pbSkip(b []byte, wire int) int {
	switch wire {
	case 0:
		_, n := pbVarint(b)
		return n
	case 1:
		return 8
	case 2:
		l, n := pbVarint(b)
		if n == 0 {
			return 0
		}
		return n + int(l)
	case 5:
		return 4
	}
	return 0
}
