package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	utls "github.com/refraction-networking/utls"
)

// DomainFrontTransport dials a list of CDN edge addresses in order, stopping
// at the first success. If frontSNI is empty each address is used as its own
// SNI — matching the Psiphon patch behaviour (sniServerName = ipAddress when
// no custom SNI is set). If frontSNI is non-empty it is used for every address.
type DomainFrontTransport struct {
	targetAddrs []string
	targetPort  int
	frontSNI    string
	fingerprint string // "chrome" = Chrome-83, "chrome120", "chrome133", "firefox", ...
}

// NewDomainFront creates a new DomainFrontTransport.
func NewDomainFront(targetAddrs []string, targetPort int, frontSNI, fingerprint string) *DomainFrontTransport {
	return &DomainFrontTransport{
		targetAddrs: targetAddrs,
		targetPort:  targetPort,
		frontSNI:    frontSNI,
		fingerprint: fingerprint,
	}
}

func (df *DomainFrontTransport) Dial(ctx context.Context, _, _ string) (net.Conn, error) {
	return df.DialWithALPN(ctx, "")
}

// DialWithALPN tries each configured target address in order.
func (df *DomainFrontTransport) DialWithALPN(ctx context.Context, alpn string) (net.Conn, error) {
	return df.dialAddrs(ctx, df.targetAddrs, alpn)
}

// DialForwardWithALPN tries the original CONNECT destination first when it is
// a hostname (not a bare IP). Akamai CDN domain names resolve to non-blocked
// edge IPs via DNS, so dialling the hostname directly succeeds even when the
// hardcoded Psiphon IPs are blocked. Falls back to the configured target_ips
// list if the original destination fails or is a bare IP.
func (df *DomainFrontTransport) DialForwardWithALPN(ctx context.Context, origAddr, alpn string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(origAddr)
	if err == nil && net.ParseIP(host) == nil {
		// It's a hostname — try it directly first with our fingerprint.
		sni := df.frontSNI
		if sni == "" {
			sni = host
		}
		conn, dialErr := df.dialTCPAddr(ctx, host+":"+portStr, sni, alpn)
		if dialErr == nil {
			return conn, nil
		}
		log.Printf("[transport] domain_front: original dest %s failed, trying configured IPs: %v", origAddr, dialErr)
	}
	return df.dialAddrs(ctx, df.targetAddrs, alpn)
}

func (df *DomainFrontTransport) dialAddrs(ctx context.Context, addrs []string, alpn string) (net.Conn, error) {
	var lastErr error
	for _, target := range addrs {
		sni := df.frontSNI
		if sni == "" {
			sni = target
		}
		conn, err := df.dialOne(ctx, target, sni, alpn)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		log.Printf("[transport] domain_front: %s failed, trying next: %v", target, err)
	}
	return nil, lastErr
}

func (df *DomainFrontTransport) dialOne(ctx context.Context, target, sni, alpn string) (net.Conn, error) {
	return df.dialTCPAddr(ctx, fmt.Sprintf("%s:%d", target, df.targetPort), sni, alpn)
}

func (df *DomainFrontTransport) dialTCPAddr(ctx context.Context, addr, sni, alpn string) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("domain_front tcp dial %s: %w", addr, err)
	}
	log.Printf("[transport] domain_front: TCP ok → %s (fp=%s SNI=%s ALPN=%q)", addr, df.fingerprint, sni, alpn)

	if df.fingerprint != "" {
		return df.utlsHandshake(ctx, conn, sni, alpn)
	}
	return df.stdHandshake(ctx, conn, sni, alpn)
}

func (df *DomainFrontTransport) stdHandshake(ctx context.Context, conn net.Conn, sni, alpn string) (net.Conn, error) {
	protos := []string{"http/1.1"}
	if alpn != "" {
		protos = []string{alpn}
	}
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		NextProtos:         protos,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("domain_front tls handshake (SNI=%s): %w", sni, err)
	}
	cs := tlsConn.ConnectionState()
	log.Printf("[transport] domain_front: TLS ok SNI=%s negotiated=%s", sni, cs.NegotiatedProtocol)
	return tlsConn, nil
}

func (df *DomainFrontTransport) utlsHandshake(ctx context.Context, conn net.Conn, sni, alpn string) (net.Conn, error) {
	helloID := helloIDFromString(df.fingerprint)
	cfg := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	}
	if alpn != "" {
		cfg.NextProtos = []string{alpn}
	}
	uconn := utls.UClient(conn, cfg, helloID)

	if err := uconn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("domain_front utls handshake (fp=%s SNI=%s): %w", df.fingerprint, sni, err)
	}
	cs := uconn.ConnectionState()
	log.Printf("[transport] domain_front: uTLS ok fp=%s SNI=%s negotiated=%s", df.fingerprint, sni, cs.NegotiatedProtocol)
	return uconn, nil
}

func helloIDFromString(fp string) utls.ClientHelloID {
	switch fp {
	case "chrome120":
		return utls.HelloChrome_120
	case "chrome133":
		return utls.HelloChrome_133
	case "firefox":
		return utls.HelloFirefox_Auto
	case "safari":
		return utls.HelloSafari_Auto
	case "edge":
		return utls.HelloEdge_Auto
	case "random":
		return utls.HelloRandomized
	default: // "chrome" — Chrome-83, matching Psiphon's TLSProfile in FrontedMeekDialOverrides
		return utls.HelloChrome_83
	}
}

// MITMALPNs returns the ALPN protocols to advertise in the MITM inbound TLS.
// Fastly uses h2+http/1.1; Akamai (and everything else) uses http/1.1 only.
func (df *DomainFrontTransport) MITMALPNs() []string {
	if df.frontSNI == "pypi.org" || df.frontSNI == "fastly.com" {
		return []string{"h2", "http/1.1"}
	}
	return []string{"http/1.1"}
}

func (df *DomainFrontTransport) Name() string {
	var target string
	if len(df.targetAddrs) == 1 {
		target = df.targetAddrs[0]
	} else if len(df.targetAddrs) > 1 {
		target = fmt.Sprintf("%s+%d more", df.targetAddrs[0], len(df.targetAddrs)-1)
	}
	sni := df.frontSNI
	if sni == "" {
		sni = "<per-ip>"
	}
	fp := df.fingerprint
	if fp == "" {
		fp = "go-tls"
	}
	return fmt.Sprintf("domain_front(%s→%s, fp:%s)", sni, target, fp)
}

func (df *DomainFrontTransport) TargetAddrs() []string { return df.targetAddrs }

func (df *DomainFrontTransport) Close() error { return nil }

