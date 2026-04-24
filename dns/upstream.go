package dns

import (
	"context"
	"fmt"

	"github.com/miekg/dns"
)

// UpstreamResolver forwards queries to a plain DNS server.
type UpstreamResolver struct {
	addr   string // e.g. "8.8.8.8:53"
	client *dns.Client
}

// NewUpstreamResolver creates a resolver that forwards to addr via UDP (with TCP fallback).
func NewUpstreamResolver(addr string) *UpstreamResolver {
	return &UpstreamResolver{
		addr:   addr,
		client: &dns.Client{Net: "udp"},
	}
}

// Resolve sends the query upstream. Falls back to TCP on truncation.
func (u *UpstreamResolver) Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	resp, _, err := u.client.ExchangeContext(ctx, req, u.addr)
	if err != nil {
		return nil, fmt.Errorf("upstream udp: %w", err)
	}

	// Retry over TCP if truncated
	if resp.Truncated {
		tcpClient := &dns.Client{Net: "tcp"}
		resp, _, err = tcpClient.ExchangeContext(ctx, req, u.addr)
		if err != nil {
			return nil, fmt.Errorf("upstream tcp fallback: %w", err)
		}
	}

	return resp, nil
}
