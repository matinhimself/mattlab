package dns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	"github.com/itsmatinhimself/mattlab/internal"
	"github.com/miekg/dns"
)

// Handler processes a DNS query and returns a response.
type Handler interface {
	ServeDNS(ctx context.Context, req *dns.Msg) *dns.Msg
}

// Server listens on UDP and TCP for DNS queries, with optional DoT (DNS over TLS).
type Server struct {
	addr    string
	handler Handler

	udpConn   *net.UDPConn
	tcpLn     net.Listener
	tlsConfig *tls.Config
	dotPort   int
	dotLn     net.Listener
	wg        sync.WaitGroup
	done      chan struct{}
}

// NewServer creates a DNS server bound to addr (e.g. "0.0.0.0:53").
func NewServer(addr string, handler Handler) *Server {
	return &Server{
		addr:    addr,
		handler: handler,
		done:    make(chan struct{}),
	}
}

// NewServerWithDoT creates a DNS server with an additional DoT (RFC 7858) listener.
func NewServerWithDoT(addr string, dotPort int, handler Handler, tlsConfig *tls.Config) *Server {
	return &Server{
		addr:      addr,
		handler:   handler,
		tlsConfig: tlsConfig,
		dotPort:   dotPort,
		done:      make(chan struct{}),
	}
}

// Start binds UDP and TCP listeners.
func (s *Server) Start() error {
	udpAddr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return fmt.Errorf("dns: resolve udp addr: %w", err)
	}
	s.udpConn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("dns: listen udp: %w", err)
	}

	s.tcpLn, err = net.Listen("tcp", s.addr)
	if err != nil {
		s.udpConn.Close()
		return fmt.Errorf("dns: listen tcp: %w", err)
	}

	log.Printf("DNS server listening on %s (UDP+TCP)", s.addr)

	// Start DoT listener if TLS config is provided
	if s.tlsConfig != nil {
		host, _, err := net.SplitHostPort(s.addr)
		if err != nil {
			host = "0.0.0.0"
		}
		dotAddr := fmt.Sprintf("%s:%d", host, s.dotPort)
		inner, err := net.Listen("tcp", dotAddr)
		if err != nil {
			s.udpConn.Close()
			s.tcpLn.Close()
			return fmt.Errorf("dns: listen dot: %w", err)
		}
		s.dotLn = tls.NewListener(inner, s.tlsConfig)
		log.Printf("DNS-over-TLS listening on %s", dotAddr)
	}

	return nil
}

// Serve runs the UDP, TCP, and (optionally) DoT accept loops. Blocks until Stop is called.
func (s *Server) Serve() {
	n := 2
	if s.dotLn != nil {
		n = 3
	}
	s.wg.Add(n)
	go s.serveUDP()
	go s.serveTCP()
	if s.dotLn != nil {
		go s.serveDoT()
	}
	s.wg.Wait()
}

// Stop closes listeners and waits for goroutines to finish.
func (s *Server) Stop() {
	close(s.done)
	if s.udpConn != nil {
		s.udpConn.Close()
	}
	if s.tcpLn != nil {
		s.tcpLn.Close()
	}
	if s.dotLn != nil {
		s.dotLn.Close()
	}
	s.wg.Wait()
}

func (s *Server) serveUDP() {
	defer s.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, raddr, err := s.udpConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				log.Printf("dns udp read: %v", err)
				continue
			}
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go s.handleUDP(pkt, raddr)
	}
}

func (s *Server) handleUDP(pkt []byte, raddr *net.UDPAddr) {
	req := new(dns.Msg)
	if err := req.Unpack(pkt); err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), internal.DNSUpstreamTimeout)
	defer cancel()

	resp := s.handler.ServeDNS(ctx, req)
	if resp == nil {
		return
	}

	out, err := resp.Pack()
	if err != nil {
		return
	}
	s.udpConn.WriteToUDP(out, raddr)
}

func (s *Server) serveTCP() {
	defer s.wg.Done()
	for {
		conn, err := s.tcpLn.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				log.Printf("dns tcp accept: %v", err)
				continue
			}
		}
		go s.handleTCP(conn)
	}
}

func (s *Server) serveDoT() {
	defer s.wg.Done()
	for {
		conn, err := s.dotLn.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				log.Printf("dns dot accept: %v", err)
				continue
			}
		}
		go s.handleTCP(conn) // DoT uses the same 2-byte length prefix framing as TCP (RFC 7858)
	}
}

func (s *Server) handleTCP(conn net.Conn) {
	defer conn.Close()

	// Read 2-byte length prefix (RFC 1035 §4.2.2)
	var length uint16
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		return
	}
	if length == 0 || length > 65535 {
		return
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}

	req := new(dns.Msg)
	if err := req.Unpack(buf); err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), internal.DNSUpstreamTimeout)
	defer cancel()

	resp := s.handler.ServeDNS(ctx, req)
	if resp == nil {
		return
	}

	out, err := resp.Pack()
	if err != nil {
		return
	}

	// Write 2-byte length prefix + response
	var respLen [2]byte
	binary.BigEndian.PutUint16(respLen[:], uint16(len(out)))
	conn.Write(respLen[:])
	conn.Write(out)
}
