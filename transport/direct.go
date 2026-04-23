package transport

import (
	"context"
	"net"
)

// DirectTransport dials the real destination directly.
type DirectTransport struct{}

// NewDirect creates a new DirectTransport.
func NewDirect() *DirectTransport {
	return &DirectTransport{}
}

func (d *DirectTransport) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{}
	return dialer.DialContext(ctx, network, addr)
}

func (d *DirectTransport) Name() string { return "direct" }

func (d *DirectTransport) Close() error { return nil }
