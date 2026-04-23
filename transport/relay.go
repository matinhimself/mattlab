package transport

import (
	"context"
	"fmt"
	"net"

	"github.com/itsmatinhimself/mattlab/relay"
)

// RelayTransport wraps a relay.Client and uses it to send HTTP requests
// through the Apps Script relay. It does not establish a traditional
// connection; instead, the proxy reads full HTTP requests and relays them.
type RelayTransport struct {
	client *relay.Client
}

// NewRelay creates a new RelayTransport.
func NewRelay(client *relay.Client) *RelayTransport {
	return &RelayTransport{client: client}
}

// Client returns the underlying relay client for direct use.
func (r *RelayTransport) Client() *relay.Client {
	return r.client
}

// Relay sends a request through the relay. This is the primary API
// for relay transport since it doesn't pipe bytes like other transports.
func (r *RelayTransport) Relay(ctx context.Context, method, targetURL string,
	headers map[string]string, body []byte) ([]byte, error) {
	return r.client.Relay(ctx, method, targetURL, headers, body)
}

// Dial is not used in the traditional sense for relay transport.
// It returns an error because relay uses request/response, not streaming.
func (r *RelayTransport) Dial(_ context.Context, _, _ string) (net.Conn, error) {
	return nil, fmt.Errorf("relay transport does not support Dial; use Relay() instead")
}

func (r *RelayTransport) Name() string { return "relay" }

func (r *RelayTransport) Close() error {
	return r.client.Close()
}
