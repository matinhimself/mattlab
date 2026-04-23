package proxy

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/itsmatinhimself/mattlab/internal"
	"github.com/itsmatinhimself/mattlab/routing"
	"github.com/itsmatinhimself/mattlab/tlsutil"
	"github.com/itsmatinhimself/mattlab/transport"
)

// SOCKS5Proxy implements a basic SOCKS5 server.
type SOCKS5Proxy struct {
	addr       string
	router     *routing.Router
	mitm       *tlsutil.MITMManager
	transports map[string]transport.Transport
	listener   net.Listener
}

// NewSOCKS5Proxy creates a new SOCKS5 proxy.
func NewSOCKS5Proxy(addr string, router *routing.Router, mitm *tlsutil.MITMManager,
	transports map[string]transport.Transport) *SOCKS5Proxy {
	return &SOCKS5Proxy{
		addr:       addr,
		router:     router,
		mitm:       mitm,
		transports: transports,
	}
}

// Start begins listening.
func (s *SOCKS5Proxy) Start() error {
	var err error
	s.listener, err = net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("socks5 listen: %w", err)
	}
	log.Printf("SOCKS5 on %s", s.addr)
	return nil
}

// Serve accepts connections.
func (s *SOCKS5Proxy) Serve() error {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return err
		}
		go s.handle(conn)
	}
}

// Stop closes the listener.
func (s *SOCKS5Proxy) Stop() {
	if s.listener != nil {
		s.listener.Close()
	}
}

func (s *SOCKS5Proxy) handle(conn net.Conn) {
	defer safeClose(conn)
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))

	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	if header[0] != 0x05 {
		return
	}
	methods := make([]byte, header[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	conn.Write([]byte{0x05, 0x00})

	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}
	if req[0] != 0x05 || req[1] != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var host string
	switch req[3] {
	case 0x01:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return
		}
		host = string(domain)
	case 0x04:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf)

	tag := s.router.Classify(host)
	log.Printf("[socks5] %s:%d -> %s", host, port, tag)

	t, ok := s.transports[tag]
	if !ok {
		conn.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	conn.SetDeadline(time.Time{})

	ctx, cancel := context.WithTimeout(context.Background(), internal.ClientIdleTimeout)
	defer cancel()

	obType := outboundType(t)
	switch obType {
	case "block":
		return
	case "direct":
		s.doDirect(ctx, conn, host, int(port))
	case "domain_front":
		s.doDomainFront(ctx, conn, host, int(port), t)
	case "relay":
		s.doRelay(ctx, conn, host, int(port), t)
	default:
		s.doDirect(ctx, conn, host, int(port))
	}
}

func (s *SOCKS5Proxy) doDirect(ctx context.Context, conn net.Conn, host string, port int) {
	upstream, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), internal.TCPConnectTimeout)
	if err != nil {
		return
	}
	defer safeClose(upstream)
	Pipe(ctx, conn, upstream)
}

func (s *SOCKS5Proxy) doDomainFront(ctx context.Context, conn net.Conn, host string, port int, t transport.Transport) {
	tlsConfig := s.mitm.GetTLSConfig(host)
	if tlsConfig == nil {
		return
	}

	tlsConn := tls.Server(conn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return
	}
	defer safeClose(tlsConn)

	upstream, err := t.Dial(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return
	}
	defer safeClose(upstream)

	Pipe(ctx, tlsConn, upstream)
}

func (s *SOCKS5Proxy) doRelay(ctx context.Context, conn net.Conn, host string, port int, t transport.Transport) {
	tlsConfig := s.mitm.GetTLSConfig(host)
	if tlsConfig == nil {
		return
	}

	tlsConn := tls.Server(conn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return
	}
	defer safeClose(tlsConn)

	rt, ok := t.(*transport.RelayTransport)
	if !ok {
		return
	}

	// Read and relay HTTP requests over the decrypted SOCKS5 tunnel
	handleRelayLoop(ctx, tlsConn, host, rt)
}
