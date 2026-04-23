package relay

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"fmt"
	"io"
	"strings"
)

// Decode decodes body according to Content-Encoding.
// Multi-layer encoding is supported (e.g. "gzip, br").
// Returns original bytes if decoding fails.
func Decode(body []byte, encoding string) []byte {
	if len(body) == 0 {
		return body
	}
	enc := strings.TrimSpace(strings.ToLower(encoding))
	if enc == "" || enc == "identity" {
		return body
	}

	// Multi-coding: "gzip, br" means br(gzip(data))
	if strings.Contains(enc, ",") {
		layers := strings.Split(enc, ",")
		for i := len(layers) - 1; i >= 0; i-- {
			layer := strings.TrimSpace(layers[i])
			if layer != "" {
				body = Decode(body, layer)
			}
		}
		return body
	}

	switch enc {
	case "gzip":
		r, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return body
		}
		defer r.Close()
		out, err := io.ReadAll(r)
		if err != nil {
			return body
		}
		return out

	case "deflate":
		r := flate.NewReader(bytes.NewReader(body))
		defer r.Close()
		out, err := io.ReadAll(r)
		if err != nil {
			return body
		}
		return out

	case "br":
		// Brotli: use optional dependency
		if dec := getBrotliDecoder(); dec != nil {
			return dec(body)
		}
		return body

	case "zstd":
		// Zstandard: use optional dependency
		if dec := getZstdDecoder(); dec != nil {
			return dec(body)
		}
		return body

	default:
		return body
	}
}

// SupportedEncodings returns the Accept-Encoding header value listing
// encodings this client can handle.
func SupportedEncodings() string {
	encs := []string{"gzip", "deflate"}
	if hasBrotli() {
		encs = append(encs, "br")
	}
	if hasZstd() {
		encs = append(encs, "zstd")
	}
	return strings.Join(encs, ", ")
}

// Optional brotli/zstd support detected at init time.
var (
	brotliAvailable bool
	zstdAvailable   bool
)

func init() {
	brotliAvailable = probeBrotli()
	zstdAvailable = probeZstd()
}

func hasBrotli() bool { return brotliAvailable }
func hasZstd() bool   { return zstdAvailable }

// probeBrotli checks if the brotli package is importable.
func probeBrotli() bool {
	// Will be replaced by build-time dependency if available
	return false
}

func getBrotliDecoder() func([]byte) []byte {
	return nil
}

func probeZstd() bool {
	return false
}

func getZstdDecoder() func([]byte) []byte {
	return nil
}

// Ensure fmt is used
var _ = fmt.Sprintf
