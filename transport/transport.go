package transport

import (
	"context"
	"net"
)

// Transport is the interface for outbound connections.
type Transport interface {
	// Dial returns a connection to the destination through this transport.
	Dial(ctx context.Context, network, addr string) (net.Conn, error)

	// Name returns a human-readable label for logging.
	Name() string

	// Close releases resources (connection pools, H2 sessions, etc).
	Close() error
}
