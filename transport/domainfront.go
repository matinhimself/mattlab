package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
)

// DomainFrontConfig configures MITM TLS repacking through one or more CDN
// addresses. A fixed FrontSNI fronts all attempts; an empty FrontSNI uses the
// attempted address itself.
type DomainFrontConfig struct {
	TargetAddrs             []string
	TargetPort              int
	FrontSNI                string
	Fingerprint             string
	ALPN                    []string
	VerifyNames             []string
	DialOriginalDestination bool
	DialConcurrency         int
	DialFallbackDelay       time.Duration
}

// DomainFrontTransport terminates client TLS and opens a fronted upstream TLS
// connection. Attempts are staggered and raced so an unreachable address does
// not hold up the full fallback list.
type DomainFrontTransport struct {
	targetAddrs             []string
	targetPort              int
	frontSNI                string
	fingerprint             string
	alpns                   []string
	verifyNames             []string
	dialOriginalDestination bool
	dialConcurrency         int
	dialFallbackDelay       time.Duration
	preferredTarget         atomic.Int64
}

type dialAttempt struct {
	addr           string
	sni            string
	originalHost   string
	preferredIndex int
}

type dialResult struct {
	attempt dialAttempt
	conn    net.Conn
	err     error
}

// NewDomainFront creates a domain-front transport.
func NewDomainFront(cfg DomainFrontConfig) *DomainFrontTransport {
	if cfg.TargetPort == 0 {
		cfg.TargetPort = 443
	}
	if len(cfg.ALPN) == 0 {
		cfg.ALPN = []string{"http/1.1"}
	}
	if cfg.DialConcurrency < 1 {
		cfg.DialConcurrency = 1
	}
	if cfg.DialFallbackDelay < 0 {
		cfg.DialFallbackDelay = 0
	}

	df := &DomainFrontTransport{
		targetAddrs:             append([]string(nil), cfg.TargetAddrs...),
		targetPort:              cfg.TargetPort,
		frontSNI:                cfg.FrontSNI,
		fingerprint:             cfg.Fingerprint,
		alpns:                   append([]string(nil), cfg.ALPN...),
		verifyNames:             append([]string(nil), cfg.VerifyNames...),
		dialOriginalDestination: cfg.DialOriginalDestination,
		dialConcurrency:         cfg.DialConcurrency,
		dialFallbackDelay:       cfg.DialFallbackDelay,
	}
	df.preferredTarget.Store(-1)
	return df
}

func (df *DomainFrontTransport) Dial(ctx context.Context, _, _ string) (net.Conn, error) {
	return df.DialWithALPN(ctx, "")
}

// DialWithALPN races the configured fallback addresses.
func (df *DomainFrontTransport) DialWithALPN(ctx context.Context, alpn string) (net.Conn, error) {
	return df.dialAttempts(ctx, df.configuredAttempts(""), alpn)
}

// DialForwardWithALPN optionally tries the original CONNECT destination before
// the configured fallback targets. This matches Xray profiles which preserve
// the original destination while replacing SNI, while still allowing profiles
// such as Fastly to dial only an explicit redirect target.
func (df *DomainFrontTransport) DialForwardWithALPN(ctx context.Context, origAddr, alpn string) (net.Conn, error) {
	attempts := make([]dialAttempt, 0, len(df.targetAddrs)+1)
	if df.dialOriginalDestination {
		host, _, err := net.SplitHostPort(origAddr)
		if err == nil {
			attempts = append(attempts, dialAttempt{
				addr:           origAddr,
				sni:            df.sniFor(host),
				originalHost:   host,
				preferredIndex: -1,
			})
		}
	}
	attempts = append(attempts, df.configuredAttempts(hostFromAddr(origAddr))...)
	return df.dialAttempts(ctx, dedupeAttempts(attempts), alpn)
}

func (df *DomainFrontTransport) configuredAttempts(originalHost string) []dialAttempt {
	attempts := make([]dialAttempt, 0, len(df.targetAddrs))
	preferred := int(df.preferredTarget.Load())
	if preferred >= 0 && preferred < len(df.targetAddrs) {
		attempts = append(attempts, df.configuredAttempt(preferred, originalHost))
	}
	for i := range df.targetAddrs {
		if i != preferred {
			attempts = append(attempts, df.configuredAttempt(i, originalHost))
		}
	}
	return attempts
}

func (df *DomainFrontTransport) configuredAttempt(index int, originalHost string) dialAttempt {
	target := df.targetAddrs[index]
	return dialAttempt{
		addr:           net.JoinHostPort(target, strconv.Itoa(df.targetPort)),
		sni:            df.sniFor(target),
		originalHost:   originalHost,
		preferredIndex: index,
	}
}

func (df *DomainFrontTransport) sniFor(target string) string {
	if df.frontSNI != "" {
		return df.frontSNI
	}
	return target
}

func (df *DomainFrontTransport) dialAttempts(ctx context.Context, attempts []dialAttempt, alpn string) (net.Conn, error) {
	if len(attempts) == 0 {
		return nil, fmt.Errorf("domain_front has no dial targets")
	}

	dialCtx, cancel := context.WithCancel(ctx)
	results := make(chan dialResult, len(attempts))
	var wg sync.WaitGroup
	active := 0
	next := 0

	launch := func() {
		attempt := attempts[next]
		next++
		active++
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := df.dialTCPAddr(dialCtx, attempt.addr, attempt.sni, attempt.originalHost, alpn)
			results <- dialResult{attempt: attempt, conn: conn, err: err}
		}()
	}
	cleanup := func() {
		cancel()
		go func() {
			wg.Wait()
			close(results)
			for result := range results {
				if result.conn != nil {
					result.conn.Close()
				}
			}
		}()
	}

	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()
	var timerC <-chan time.Time
	schedule := func() {
		timerC = nil
		if next >= len(attempts) || active >= df.dialConcurrency {
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(df.dialFallbackDelay)
		timerC = timer.C
	}

	launch()
	schedule()

	var errs []error
	for active > 0 {
		select {
		case <-ctx.Done():
			cleanup()
			return nil, ctx.Err()
		case <-timerC:
			launch()
			schedule()
		case result := <-results:
			active--
			if result.err == nil {
				if result.attempt.preferredIndex >= 0 {
					df.preferredTarget.Store(int64(result.attempt.preferredIndex))
				}
				cleanup()
				return result.conn, nil
			}
			errs = append(errs, result.err)
			log.Printf("[transport] domain_front: %s failed: %v", result.attempt.addr, result.err)
			if next < len(attempts) && active < df.dialConcurrency {
				launch()
			}
			schedule()
		}
	}

	cleanup()
	return nil, errors.Join(errs...)
}

func (df *DomainFrontTransport) dialTCPAddr(ctx context.Context, addr, sni, originalHost, alpn string) (net.Conn, error) {
	dialer := &net.Dialer{FallbackDelay: df.dialFallbackDelay}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("domain_front tcp dial %s: %w", addr, err)
	}
	log.Printf("[transport] domain_front: TCP ok -> %s (fp=%s SNI=%s ALPN=%q)", addr, df.fingerprint, sni, alpn)

	if df.fingerprint != "" {
		return df.utlsHandshake(ctx, conn, sni, originalHost, alpn)
	}
	return df.stdHandshake(ctx, conn, sni, originalHost, alpn)
}

func (df *DomainFrontTransport) stdHandshake(ctx context.Context, conn net.Conn, sni, originalHost, alpn string) (net.Conn, error) {
	protos := df.upstreamALPNs(alpn)
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		NextProtos:         protos,
		VerifyConnection:   df.verifyConnection(originalHost),
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("domain_front tls handshake (SNI=%s): %w", sni, err)
	}
	cs := tlsConn.ConnectionState()
	log.Printf("[transport] domain_front: TLS ok SNI=%s negotiated=%s", sni, cs.NegotiatedProtocol)
	return tlsConn, nil
}

func (df *DomainFrontTransport) utlsHandshake(ctx context.Context, conn net.Conn, sni, originalHost, alpn string) (net.Conn, error) {
	cfg := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		NextProtos:         df.upstreamALPNs(alpn),
		VerifyConnection:   df.verifyUTLSConnection(originalHost),
	}
	uconn := utls.UClient(conn, cfg, helloIDFromString(df.fingerprint))

	if err := uconn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("domain_front utls handshake (fp=%s SNI=%s): %w", df.fingerprint, sni, err)
	}
	cs := uconn.ConnectionState()
	log.Printf("[transport] domain_front: uTLS ok fp=%s SNI=%s negotiated=%s", df.fingerprint, sni, cs.NegotiatedProtocol)
	return uconn, nil
}

func (df *DomainFrontTransport) upstreamALPNs(alpn string) []string {
	if alpn != "" {
		return []string{alpn}
	}
	return append([]string(nil), df.alpns...)
}

// verifyConnection returns nil for legacy profiles with no verify_names. New
// profiles should provide explicit names so a fronted connection still checks
// the public certificate chain.
func (df *DomainFrontTransport) verifyConnection(originalHost string) func(tls.ConnectionState) error {
	names := df.expandedVerifyNames(originalHost)
	if len(names) == 0 {
		return nil
	}
	return func(state tls.ConnectionState) error {
		return verifyPeerCertByNames(state.PeerCertificates, names)
	}
}

func (df *DomainFrontTransport) verifyUTLSConnection(originalHost string) func(utls.ConnectionState) error {
	names := df.expandedVerifyNames(originalHost)
	if len(names) == 0 {
		return nil
	}
	return func(state utls.ConnectionState) error {
		return verifyPeerCertByNames(state.PeerCertificates, names)
	}
}

func (df *DomainFrontTransport) expandedVerifyNames(originalHost string) []string {
	names := make([]string, 0, len(df.verifyNames))
	seen := make(map[string]bool, len(df.verifyNames))
	for _, name := range df.verifyNames {
		if strings.EqualFold(name, "from_mitm") || strings.EqualFold(name, "frommitm") {
			name = originalHost
		}
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	return names
}

func verifyPeerCertByNames(peerCertificates []*x509.Certificate, names []string) error {
	if len(peerCertificates) == 0 {
		return fmt.Errorf("domain_front peer did not provide a certificate")
	}

	intermediates := x509.NewCertPool()
	for _, cert := range peerCertificates[1:] {
		intermediates.AddCert(cert)
	}

	var errs []error
	for _, name := range names {
		_, err := peerCertificates[0].Verify(x509.VerifyOptions{
			DNSName:       name,
			Intermediates: intermediates,
		})
		if err == nil {
			return nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", name, err))
	}
	return fmt.Errorf("domain_front certificate did not match verify_names: %w", errors.Join(errs...))
}

func dedupeAttempts(attempts []dialAttempt) []dialAttempt {
	seen := make(map[string]bool, len(attempts))
	result := make([]dialAttempt, 0, len(attempts))
	for _, attempt := range attempts {
		key := attempt.addr + "\x00" + attempt.sni
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, attempt)
	}
	return result
}

func hostFromAddr(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return host
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
	default:
		return utls.HelloChrome_83
	}
}

// MITMALPNs returns the protocols advertised by the local TLS endpoint.
func (df *DomainFrontTransport) MITMALPNs() []string {
	return append([]string(nil), df.alpns...)
}

func (df *DomainFrontTransport) Name() string {
	var target string
	if len(df.targetAddrs) == 1 {
		target = df.targetAddrs[0]
	} else if len(df.targetAddrs) > 1 {
		target = fmt.Sprintf("%s+%d more", df.targetAddrs[0], len(df.targetAddrs)-1)
	}
	if target == "" {
		target = "<original-destination>"
	}
	sni := df.frontSNI
	if sni == "" {
		sni = "<per-target>"
	}
	fp := df.fingerprint
	if fp == "" {
		fp = "go-tls"
	}
	return fmt.Sprintf("domain_front(%s->%s, fp:%s)", sni, target, fp)
}

func (df *DomainFrontTransport) TargetAddrs() []string {
	return append([]string(nil), df.targetAddrs...)
}

func (df *DomainFrontTransport) Close() error { return nil }
