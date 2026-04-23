package tlsutil

import "encoding/binary"

// ParseSNI extracts the Server Name Indication hostname from a TLS
// ClientHello record. Returns empty string if not found or data is
// malformed.
func ParseSNI(data []byte) string {
	// TLS record header: type(1) version(2) length(2)
	if len(data) < 5 || data[0] != 0x16 {
		return ""
	}
	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recordLen {
		return ""
	}

	off := 5
	// Handshake header: type(1) length(3)
	if off >= len(data) || data[off] != 0x01 { // ClientHello
		return ""
	}
	off += 4 // skip handshake type(1) + length(3)

	// Client version(2) + random(32)
	off += 2 + 32
	if off >= len(data) {
		return ""
	}

	// Session ID: length(1) + data
	off += 1 + int(data[off])
	if off+2 > len(data) {
		return ""
	}

	// Cipher suites: length(2) + data
	csLen := int(binary.BigEndian.Uint16(data[off : off+2]))
	off += 2 + csLen
	if off >= len(data) {
		return ""
	}

	// Compression methods: length(1) + data
	off += 1 + int(data[off])
	if off+2 > len(data) {
		return ""
	}

	// Extensions: length(2) + data
	extLen := int(binary.BigEndian.Uint16(data[off : off+2]))
	off += 2
	extEnd := off + extLen

	for off < extEnd && off+4 <= len(data) {
		etype := int(binary.BigEndian.Uint16(data[off : off+2]))
		elen := int(binary.BigEndian.Uint16(data[off+2 : off+4]))
		off += 4

		if etype == 0x0000 { // SNI extension
			if off+5 > len(data) {
				break
			}
			// SNI list: total_length(2) + type(1) + name_length(2) + name
			nameLen := int(binary.BigEndian.Uint16(data[off+3 : off+5]))
			end := off + 5 + nameLen
			if end > len(data) {
				end = len(data)
			}
			return string(data[off+5 : end])
		}
		off += elen
	}

	return ""
}
