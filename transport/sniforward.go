package transport

import (
	"context"
	"fmt"
	"net"
)

// SNIForwardTransport dials a fixed CDN address via raw TCP and returns the
// connection unwrapped, so the caller's own TLS handshake (with its original
// SNI) passes through to the CDN untouched. The CDN then routes the request
// to the real destination based on that SNI — no MITM required.
type SNIForwardTransport struct {
	frontAddr string // host:port of the CDN edge to connect to
}

// NewSNIForward creates a new SNIForwardTransport targeting frontAddr.
func NewSNIForward(frontAddr string) *SNIForwardTransport {
	return &SNIForwardTransport{frontAddr: frontAddr}
}

func (s *SNIForwardTransport) Dial(ctx context.Context, _, _ string) (net.Conn, error) {
	d := &net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", s.frontAddr)
	if err != nil {
		return nil, fmt.Errorf("sni_forward tcp dial: %w", err)
	}
	return conn, nil
}

func (s *SNIForwardTransport) Name() string {
	return fmt.Sprintf("sni_forward(%s)", s.frontAddr)
}

func (s *SNIForwardTransport) Close() error { return nil }
