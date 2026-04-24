package dns

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/itsmatinhimself/mattlab/transport"
	"github.com/miekg/dns"
)

// DoHResolver sends DNS queries over HTTPS (RFC 8484) using a domain-fronting transport.
type DoHResolver struct {
	dohURL string
	client *http.Client
}

// NewDoHResolver creates a DoH resolver that routes traffic through the given transport.
func NewDoHResolver(dohURL string, t transport.Transport) *DoHResolver {
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return t.Dial(ctx, network, addr)
			},
		},
	}
	return &DoHResolver{
		dohURL: dohURL,
		client: httpClient,
	}
}

// Resolve sends the query as a DNS wire-format POST to the DoH endpoint.
func (d *DoHResolver) Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	wire, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("doh pack: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, d.dohURL, nil)
	if err != nil {
		return nil, fmt.Errorf("doh request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")
	httpReq.Body = io.NopCloser(bytesReader(wire))
	httpReq.ContentLength = int64(len(wire))

	resp, err := d.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("doh http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("doh read body: %w", err)
	}

	dnsResp := new(dns.Msg)
	if err := dnsResp.Unpack(body); err != nil {
		return nil, fmt.Errorf("doh unpack: %w", err)
	}

	return dnsResp, nil
}

type bytesReaderWrapper struct {
	data []byte
	pos  int
}

func bytesReader(b []byte) *bytesReaderWrapper {
	return &bytesReaderWrapper{data: b}
}

func (r *bytesReaderWrapper) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
