package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
)

// DomainFrontTransport connects to a target IP with a fronted SNI hostname.
type DomainFrontTransport struct {
	targetIP   string
	targetPort int
	frontSNI   string
}

// NewDomainFront creates a new DomainFrontTransport.
func NewDomainFront(targetIP string, targetPort int, frontSNI string) *DomainFrontTransport {
	return &DomainFrontTransport{
		targetIP:   targetIP,
		targetPort: targetPort,
		frontSNI:   frontSNI,
	}
}

func (df *DomainFrontTransport) Dial(ctx context.Context, _, _ string) (net.Conn, error) {
	addr := fmt.Sprintf("%s:%d", df.targetIP, df.targetPort)
	dialer := &net.Dialer{}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("domain_front tcp dial: %w", err)
	}

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         df.frontSNI,
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	})

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("domain_front tls handshake: %w", err)
	}

	return tlsConn, nil
}

func (df *DomainFrontTransport) Name() string {
	return fmt.Sprintf("domain_front(%s→%s)", df.frontSNI, df.targetIP)
}

func (df *DomainFrontTransport) Close() error { return nil }
