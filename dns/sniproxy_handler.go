package dns

import (
	"context"
	"log"
	"net"
	"strings"

	"github.com/itsmatinhimself/mattlab/routing"
	"github.com/miekg/dns"
)

// SNIProxyHandler intercepts A queries for routed domains and returns the proxy IP.
// All other queries are forwarded upstream.
type SNIProxyHandler struct {
	router     *routing.Router
	proxyIP    net.IP
	upstream   *UpstreamResolver
	defaultTag string
}

// NewSNIProxyHandler creates a handler for SNI proxy DNS mode.
func NewSNIProxyHandler(router *routing.Router, proxyIP net.IP, upstream *UpstreamResolver, defaultTag string) *SNIProxyHandler {
	return &SNIProxyHandler{
		router:     router,
		proxyIP:    proxyIP,
		upstream:   upstream,
		defaultTag: defaultTag,
	}
}

func (h *SNIProxyHandler) ServeDNS(ctx context.Context, req *dns.Msg) *dns.Msg {
	if len(req.Question) == 0 {
		return servfail(req)
	}

	q := req.Question[0]

	// Only intercept A record queries
	if q.Qtype != dns.TypeA {
		return h.forward(ctx, req)
	}

	domain := strings.TrimSuffix(q.Name, ".")
	tag := h.router.Classify(domain)

	// If the domain is routed through a non-default, non-direct, non-block outbound,
	// return the proxy IP so the client connects to us.
	if tag != h.defaultTag && tag != "direct" && tag != "block" {
		log.Printf("dns: %s → proxy (%s)", domain, tag)
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Authoritative = true
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    60,
			},
			A: h.proxyIP,
		})
		return resp
	}

	return h.forward(ctx, req)
}

func (h *SNIProxyHandler) forward(ctx context.Context, req *dns.Msg) *dns.Msg {
	resp, err := h.upstream.Resolve(ctx, req)
	if err != nil {
		log.Printf("dns upstream error: %v", err)
		return servfail(req)
	}
	return resp
}

func servfail(req *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Rcode = dns.RcodeServerFailure
	return resp
}
