package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/itsmatinhimself/mattlab/internal"
	"github.com/itsmatinhimself/mattlab/routing"
	"github.com/itsmatinhimself/mattlab/tlsutil"
	"github.com/itsmatinhimself/mattlab/transport"
)

// HTTPProxy handles HTTP CONNECT and plain HTTP proxy requests.
type HTTPProxy struct {
	addr       string
	router     *routing.Router
	mitm       *tlsutil.MITMManager
	transports map[string]transport.Transport
	listener   net.Listener
}

// NewHTTPProxy creates a new HTTP proxy.
func NewHTTPProxy(addr string, router *routing.Router, mitm *tlsutil.MITMManager,
	transports map[string]transport.Transport) *HTTPProxy {
	return &HTTPProxy{
		addr:       addr,
		router:     router,
		mitm:       mitm,
		transports: transports,
	}
}

// Start begins listening.
func (h *HTTPProxy) Start() error {
	var err error
	h.listener, err = net.Listen("tcp", h.addr)
	if err != nil {
		return fmt.Errorf("http proxy listen: %w", err)
	}
	log.Printf("HTTP proxy on %s", h.addr)
	return nil
}

// Serve accepts connections.
func (h *HTTPProxy) Serve() error {
	for {
		conn, err := h.listener.Accept()
		if err != nil {
			return err
		}
		go h.handle(conn)
	}
}

// Stop closes the listener.
func (h *HTTPProxy) Stop() {
	if h.listener != nil {
		h.listener.Close()
	}
}

func (h *HTTPProxy) handle(conn net.Conn) {
	defer safeClose(conn)
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	br := bufio.NewReader(conn)

	firstLine, err := br.ReadString('\n')
	if err != nil {
		return
	}
	firstLine = strings.TrimRight(firstLine, "\r\n")
	parts := strings.SplitN(firstLine, " ", 3)
	if len(parts) < 2 {
		return
	}

	method := parts[0]

	if method == "CONNECT" {
		h.handleCONNECT(conn, br, parts[1])
	} else {
		h.handleHTTP(conn, br, firstLine)
	}
}

func (h *HTTPProxy) handleCONNECT(conn net.Conn, br *bufio.Reader, target string) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		portStr = "443"
	}
	port, _ := strconv.Atoi(portStr)
	if port == 0 {
		port = 443
	}

	// Drain remaining CONNECT headers that br may have buffered.
	// The client won't send the TLS ClientHello until it receives our 200,
	// so br should only contain leftover HTTP headers at this point.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}

	tag := h.router.Classify(host)
	log.Printf("[http] CONNECT %s:%d -> %s", host, port, tag)

	t, ok := h.transports[tag]
	if !ok {
		conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
		return
	}

	// Send 200 to client — only NOW does the client send its TLS ClientHello
	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	conn.SetDeadline(time.Time{})

	ctx, cancel := context.WithTimeout(context.Background(), internal.ClientIdleTimeout)
	defer cancel()

	obType := outboundType(t)
	switch obType {
	case "block":
		// Already sent 200, just close
		return
	case "direct":
		h.doDirectTunnel(ctx, conn, host, port)
	case "domain_front":
		h.doDomainFrontTunnel(ctx, conn, br, host, port, t)
	case "relay":
		h.doRelayTunnel(ctx, conn, br, host, port, t)
	default:
		h.doDirectTunnel(ctx, conn, host, port)
	}
}

func (h *HTTPProxy) handleHTTP(conn net.Conn, br *bufio.Reader, requestLine string) {
	// Read remaining headers
	headers := make(map[string]string)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if idx := strings.Index(line, ":"); idx > 0 {
			headers[strings.TrimSpace(line[:idx])] = strings.TrimSpace(line[idx+1:])
		}
	}

	parts := strings.SplitN(requestLine, " ", 3)
	method := parts[0]
	targetURL := parts[1]

	host := headers["Host"]
	if host == "" {
		if u, _, err := net.SplitHostPort(targetURL); err == nil {
			host = u
		} else {
			host = targetURL
		}
	}

	tag := h.router.Classify(host)
	log.Printf("[http] %s %s -> %s", method, targetURL, tag)

	t, ok := h.transports[tag]
	if !ok {
		conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
		return
	}

	// Read body
	var body []byte
	if cl, ok := headers["Content-Length"]; ok {
		if length, err := strconv.Atoi(cl); err == nil && length > 0 {
			body = make([]byte, length)
			if _, err := io.ReadFull(br, body); err != nil {
				return
			}
		}
	}

	obType := outboundType(t)
	switch obType {
	case "block":
		conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
	case "relay":
		rt := t.(*transport.RelayTransport)
		resp, err := rt.Relay(context.Background(), method, targetURL, headers, body)
		if err != nil {
			conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}
		conn.Write(resp)
	default:
		h.forwardHTTP(conn, method, targetURL, headers, body, host)
	}
}

// hop-by-hop headers that must not be forwarded.
var hopByHopHeaders = map[string]bool{
	"connection":          true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailers":            true,
	"transfer-encoding":   true,
	"upgrade":             true,
}

func (h *HTTPProxy) forwardHTTP(conn net.Conn, method, targetURL string,
	headers map[string]string, body []byte, host string) {

	parsed, err := url.Parse(targetURL)
	if err != nil {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	// Determine host:port
	upstreamHost := parsed.Host
	if upstreamHost == "" {
		upstreamHost = host
	}
	targetAddr := upstreamHost
	if !strings.Contains(targetAddr, ":") {
		if parsed.Scheme == "https" {
			targetAddr += ":443"
		} else {
			targetAddr += ":80"
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), internal.TCPConnectTimeout)
	defer cancel()

	var upstream net.Conn
	if parsed.Scheme == "https" {
		// Use the transport's Dial to respect routing (domain fronting, etc.)
		t, ok := h.transports[h.router.Classify(host)]
		if !ok {
			t = h.transports["direct"]
		}
		var dialErr error
		upstream, dialErr = t.Dial(ctx, "tcp", targetAddr)
		if dialErr != nil {
			log.Printf("[http] upstream dial failed for %s: %v", targetAddr, dialErr)
			conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}
	} else {
		var dialErr error
		upstream, dialErr = net.DialTimeout("tcp", targetAddr, internal.TCPConnectTimeout)
		if dialErr != nil {
			log.Printf("[http] upstream dial failed for %s: %v", targetAddr, dialErr)
			conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}
	}
	defer safeClose(upstream)

	// Build request path (absolute URL -> path + query)
	reqPath := parsed.Path
	if parsed.RawQuery != "" {
		reqPath += "?" + parsed.RawQuery
	}
	if reqPath == "" {
		reqPath = "/"
	}

	// Build outgoing request
	var req strings.Builder
	req.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", method, reqPath))
	req.WriteString(fmt.Sprintf("Host: %s\r\n", upstreamHost))

	// Forward headers, skipping hop-by-hop
	for k, v := range headers {
		if hopByHopHeaders[strings.ToLower(k)] {
			continue
		}
		req.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}

	if _, ok := headers["Content-Length"]; !ok && len(body) > 0 {
		req.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
	}
	req.WriteString("\r\n")

	upstream.SetDeadline(time.Time{})
	if _, err := upstream.Write([]byte(req.String())); err != nil {
		return
	}
	if len(body) > 0 {
		if _, err := upstream.Write(body); err != nil {
			return
		}
	}

	// Pipe the upstream response back to client
	upstream.SetReadDeadline(time.Now().Add(30 * time.Second))
	conn.SetDeadline(time.Time{})
	_, err = io.Copy(conn, upstream)
	if err != nil {
		log.Printf("[http] pipe error for %s: %v", host, err)
	}
}

func (h *HTTPProxy) doDirectTunnel(ctx context.Context, conn net.Conn, host string, port int) {
	upstream, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), internal.TCPConnectTimeout)
	if err != nil {
		log.Printf("[http] direct tunnel failed for %s: %v", host, err)
		return
	}
	defer safeClose(upstream)
	Pipe(ctx, conn, upstream)
}

func (h *HTTPProxy) doDomainFrontTunnel(ctx context.Context, conn net.Conn, br *bufio.Reader, host string, port int, t transport.Transport) {
	tlsConfig := h.mitm.GetTLSConfig(host)
	if tlsConfig == nil {
		log.Printf("[http] failed to get TLS config for %s", host)
		return
	}

	// br may have buffered TLS handshake bytes from the client;
	// drain them so tls.Server can read the ClientHello.
	var tlsRaw net.Conn = conn
	if bc := newBufferedConnFromReader(conn, br); bc != nil {
		tlsRaw = bc
	}

	tlsConn := tls.Server(tlsRaw, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		log.Printf("[http] MITM failed for %s: %v", host, err)
		return
	}
	defer safeClose(tlsConn)

	upstream, err := t.Dial(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		log.Printf("[http] domain_front dial failed for %s: %v", host, err)
		return
	}
	defer safeClose(upstream)

	Pipe(ctx, tlsConn, upstream)
}

func (h *HTTPProxy) doRelayTunnel(ctx context.Context, conn net.Conn, br *bufio.Reader, host string, port int, t transport.Transport) {
	tlsConfig := h.mitm.GetTLSConfig(host)
	if tlsConfig == nil {
		return
	}

	// br may have buffered TLS handshake bytes from the client
	var tlsRaw net.Conn = conn
	if bc := newBufferedConnFromReader(conn, br); bc != nil {
		tlsRaw = bc
	}

	tlsConn := tls.Server(tlsRaw, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return
	}
	defer safeClose(tlsConn)

	tlsBr := bufio.NewReader(tlsConn)
	rt := t.(*transport.RelayTransport)

	for {
		if err := ctx.Err(); err != nil {
			return
		}

		tlsConn.SetReadDeadline(time.Now().Add(internal.ClientIdleTimeout))

		firstLine, err := tlsBr.ReadString('\n')
		if err != nil {
			return
		}
		firstLine = strings.TrimRight(firstLine, "\r\n")
		if firstLine == "" {
			return
		}

		parts := strings.SplitN(firstLine, " ", 3)
		if len(parts) < 2 {
			return
		}
		method := parts[0]
		path := parts[1]

		headers := make(map[string]string)
		for {
			line, err := tlsBr.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if line == "" {
				break
			}
			if idx := strings.Index(line, ":"); idx > 0 {
				headers[strings.TrimSpace(line[:idx])] = strings.TrimSpace(line[idx+1:])
			}
		}

		var body []byte
		if cl, ok := headers["Content-Length"]; ok {
			if length, err := strconv.Atoi(cl); err == nil && length > 0 {
				body = make([]byte, length)
				if _, err := io.ReadFull(tlsBr, body); err != nil {
					return
				}
			}
		}

		h := headers["Host"]
		if h == "" {
			h = host
		}
		targetURL := fmt.Sprintf("https://%s%s", h, path)

		resp, err := rt.Relay(ctx, method, targetURL, headers, body)
		if err != nil {
			return
		}

		tlsConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		tlsConn.Write(resp)
	}
}
