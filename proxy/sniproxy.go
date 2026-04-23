package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/itsmatinhimself/mattlab/internal"
	"github.com/itsmatinhimself/mattlab/routing"
	"github.com/itsmatinhimself/mattlab/tlsutil"
	"github.com/itsmatinhimself/mattlab/transport"
)

// SNIProxy listens for TLS connections, extracts the SNI, and routes
// traffic based on the hostname.
type SNIProxy struct {
	addr       string
	router     *routing.Router
	mitm       *tlsutil.MITMManager
	transports map[string]transport.Transport
	listener   net.Listener
}

// NewSNIProxy creates a new SNI proxy server.
func NewSNIProxy(addr string, router *routing.Router, mitm *tlsutil.MITMManager,
	transports map[string]transport.Transport) *SNIProxy {
	return &SNIProxy{
		addr:       addr,
		router:     router,
		mitm:       mitm,
		transports: transports,
	}
}

// Start begins listening for connections.
func (s *SNIProxy) Start() error {
	var err error
	s.listener, err = net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("sni proxy listen: %w", err)
	}
	log.Printf("SNI proxy on %s", s.addr)
	return nil
}

// Serve accepts connections in a loop.
func (s *SNIProxy) Serve() error {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return err
		}
		go s.handle(conn)
	}
}

// Stop closes the listener.
func (s *SNIProxy) Stop() {
	if s.listener != nil {
		s.listener.Close()
	}
}

func (s *SNIProxy) handle(conn net.Conn) {
	defer safeClose(conn)

	conn.SetReadDeadline(time.Now().Add(internal.SNIPeekTimeout))

	peekBuf := make([]byte, internal.SNIPeekSize)
	n, err := conn.Read(peekBuf)
	if err != nil || n == 0 {
		return
	}
	peekData := peekBuf[:n]
	conn.SetReadDeadline(time.Time{})

	sni := tlsutil.ParseSNI(peekData)
	if sni == "" {
		return
	}

	tag := s.router.Classify(sni)
	log.Printf("[sni] %s -> %s", sni, tag)

	t, ok := s.transports[tag]
	if !ok {
		log.Printf("[sni] no transport for tag %q", tag)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), internal.ClientIdleTimeout)
	defer cancel()

	switch tag {
	case "block":
		return
	case "direct":
		s.handleDirect(ctx, conn, peekData, sni)
	default:
		obType := outboundType(t)
		switch obType {
		case "domain_front":
			s.handleDomainFront(ctx, conn, peekData, sni, t)
		case "relay":
			s.handleRelay(ctx, conn, peekData, sni, t)
		default:
			s.handleDirect(ctx, conn, peekData, sni)
		}
	}
}

func (s *SNIProxy) handleDirect(ctx context.Context, conn net.Conn, peekData []byte, sni string) {
	t := s.transports["direct"]
	if t == nil {
		return
	}

	upstream, err := t.Dial(ctx, "tcp", sni+":443")
	if err != nil {
		log.Printf("[sni] direct dial failed for %s: %v", sni, err)
		return
	}
	defer safeClose(upstream)

	upstream.Write(peekData)
	Pipe(ctx, conn, upstream)
}

func (s *SNIProxy) handleDomainFront(ctx context.Context, conn net.Conn, peekData []byte, sni string, t transport.Transport) {
	tlsConfig := s.mitm.GetTLSConfig(sni)
	if tlsConfig == nil {
		log.Printf("[sni] failed to get TLS config for %s", sni)
		return
	}

	// Re-inject the peeked ClientHello so tls.Server can read it
	bc := newBufferedConn(conn, peekData)
	tlsConn := tls.Server(bc, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		log.Printf("[sni] MITM failed for %s: %v", sni, err)
		return
	}
	defer safeClose(tlsConn)

	upstream, err := t.Dial(ctx, "tcp", sni+":443")
	if err != nil {
		log.Printf("[sni] domain_front dial failed for %s: %v", sni, err)
		return
	}
	defer safeClose(upstream)

	log.Printf("[sni] domain_front pipe: %s", sni)
	Pipe(ctx, tlsConn, upstream)
}

func (s *SNIProxy) handleRelay(ctx context.Context, conn net.Conn, peekData []byte, sni string, t transport.Transport) {
	tlsConfig := s.mitm.GetTLSConfig(sni)
	if tlsConfig == nil {
		log.Printf("[sni] failed to get TLS config for %s", sni)
		return
	}

	// Re-inject the peeked ClientHello so tls.Server can read it
	bc := newBufferedConn(conn, peekData)
	tlsConn := tls.Server(bc, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		log.Printf("[sni] relay MITM failed for %s: %v", sni, err)
		return
	}
	defer safeClose(tlsConn)

	rt, ok := t.(*transport.RelayTransport)
	if !ok {
		log.Printf("[sni] transport for %s is not a relay transport", sni)
		return
	}

	br := bufio.NewReader(tlsConn)
	for {
		if err := ctx.Err(); err != nil {
			return
		}

		tlsConn.SetReadDeadline(time.Now().Add(internal.ClientIdleTimeout))

		firstLine, err := br.ReadString('\n')
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

		var body []byte
		if cl, ok := headers["Content-Length"]; ok {
			if length, err := strconv.Atoi(cl); err == nil && length > 0 {
				body = make([]byte, length)
				if _, err := io.ReadFull(br, body); err != nil {
					return
				}
			}
		}

		host := headers["Host"]
		if host == "" {
			host = sni
		}
		targetURL := fmt.Sprintf("https://%s%s", host, path)

		resp, err := rt.Relay(ctx, method, targetURL, headers, body)
		if err != nil {
			log.Printf("[sni] relay error for %s: %v", targetURL, err)
			return
		}

		tlsConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		tlsConn.Write(resp)
	}
}

func outboundType(t transport.Transport) string {
	switch t.(type) {
	case *transport.DirectTransport:
		return "direct"
	case *transport.BlockTransport:
		return "block"
	case *transport.DomainFrontTransport:
		return "domain_front"
	case *transport.RelayTransport:
		return "relay"
	default:
		return "unknown"
	}
}
