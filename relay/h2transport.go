package relay

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// H2Transport provides a persistent HTTP/2 connection with stream multiplexing.
// Uses http2.ClientConn for full protocol compliance (HPACK, flow control, SETTINGS).
type H2Transport struct {
	connectHost string
	sniHost     string

	mu        sync.Mutex
	conn      net.Conn
	cc        *http2.ClientConn
	transport *http2.Transport
	connected bool
}

func NewH2Transport(connectHost, sniHost string) *H2Transport {
	return &H2Transport{
		connectHost: connectHost,
		sniHost:     sniHost,
		transport:   &http2.Transport{},
	}
}

func (t *H2Transport) IsConnected() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.connected && t.cc != nil && t.cc.CanTakeNewRequest()
}

func (t *H2Transport) Connect(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.connected && t.cc != nil && t.cc.CanTakeNewRequest() {
		return nil
	}

	dialer := &net.Dialer{Timeout: 15 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", t.connectHost+":443")
	if err != nil {
		return fmt.Errorf("h2 tcp dial: %w", err)
	}

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         t.sniHost,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	})

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return fmt.Errorf("h2 tls handshake: %w", err)
	}

	if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
		tlsConn.Close()
		return fmt.Errorf("h2 ALPN negotiation failed")
	}

	cc, err := t.transport.NewClientConn(tlsConn)
	if err != nil {
		tlsConn.Close()
		return fmt.Errorf("h2 client conn init: %w", err)
	}

	t.conn = tlsConn
	t.cc = cc
	t.connected = true

	log.Printf("H2 connected -> %s (SNI=%s)", t.connectHost, t.sniHost)
	return nil
}

// Request sends an HTTP/2 request and follows redirects on the same connection.
func (t *H2Transport) Request(ctx context.Context, method, path, host string,
	headers map[string]string, body []byte, timeout time.Duration,
	maxRedirects int) (int, map[string]string, []byte, error) {

	if !t.IsConnected() {
		if err := t.Connect(ctx); err != nil {
			return 0, nil, nil, err
		}
	}

	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	curMethod := method
	curPath := path
	curQuery := ""
	curHost := host
	curBody := body
	curHeaders := headers

	for i := 0; i <= maxRedirects; i++ {
		reqURL := url.URL{
			Scheme:   "https",
			Host:     curHost,
			Path:     curPath,
			RawQuery: curQuery,
		}

		var bodyReader io.Reader
		if len(curBody) > 0 {
			bodyReader = bytes.NewReader(curBody)
		}

		req, err := http.NewRequestWithContext(ctx, curMethod, reqURL.String(), bodyReader)
		if err != nil {
			return 0, nil, nil, fmt.Errorf("create request: %w", err)
		}

		req.Host = curHost
		req.Header.Set("Accept-Encoding", SupportedEncodings())
		for k, v := range curHeaders {
			req.Header.Set(k, v)
		}

		resp, err := t.cc.RoundTrip(req)
		if err != nil {
			t.mu.Lock()
			t.connected = false
			t.mu.Unlock()
			return 0, nil, nil, fmt.Errorf("h2 roundtrip: %w", err)
		}

		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return 0, nil, nil, fmt.Errorf("read body: %w", err)
		}

		// Follow redirects on the same H2 connection
		if resp.StatusCode >= 301 && resp.StatusCode <= 308 {
			loc := resp.Header.Get("Location")
			if loc != "" {
				parsedLoc, err := url.Parse(loc)
				if err == nil {
					curMethod = "GET"
					curPath = parsedLoc.Path
					curQuery = parsedLoc.RawQuery
					if parsedLoc.Host != "" {
						curHost = parsedLoc.Host
					}
					curBody = nil
					curHeaders = nil
					log.Printf("H2 redirect -> host=%s path=%s query=%s", curHost, curPath, curQuery[:min(40, len(curQuery))])
					continue
				}
			}
		}

		outHeaders := make(map[string]string)
		for k, v := range resp.Header {
			if len(v) > 0 {
				outHeaders[strings.ToLower(k)] = v[0]
			}
		}

		if enc, ok := outHeaders["content-encoding"]; ok && enc != "" {
			respBody = Decode(respBody, enc)
			delete(outHeaders, "content-encoding")
		}

		return resp.StatusCode, outHeaders, respBody, nil
	}

	return 0, nil, nil, fmt.Errorf("too many redirects")
}

// Reconnect closes and re-establishes the connection.
func (t *H2Transport) Reconnect(ctx context.Context) error {
	t.Close()
	return t.Connect(ctx)
}

// Ping sends an HTTP/2 PING frame via a lightweight request.
func (t *H2Transport) Ping() error {
	if !t.IsConnected() {
		return fmt.Errorf("not connected")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "https://ping/", nil)
	if err != nil {
		return err
	}
	req.Host = "ping"
	resp, err := t.cc.RoundTrip(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// Close shuts down the H2 transport.
func (t *H2Transport) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.connected = false
	if t.cc != nil {
		t.cc.Close()
		t.cc = nil
	}
	if t.conn != nil {
		t.conn.Close()
		t.conn = nil
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
