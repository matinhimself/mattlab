package dns

import (
	"context"
	"log"

	"github.com/miekg/dns"
)

// DoHHandler forwards all DNS queries through a DoH resolver.
type DoHHandler struct {
	resolver *DoHResolver
}

// NewDoHHandler creates a handler that resolves all queries via DoH.
func NewDoHHandler(resolver *DoHResolver) *DoHHandler {
	return &DoHHandler{resolver: resolver}
}

func (h *DoHHandler) ServeDNS(ctx context.Context, req *dns.Msg) *dns.Msg {
	resp, err := h.resolver.Resolve(ctx, req)
	if err != nil {
		log.Printf("dns doh error: %v", err)
		return servfail(req)
	}
	return resp
}
