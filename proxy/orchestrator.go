package proxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/itsmatinhimself/mattlab/config"
	mattdns "github.com/itsmatinhimself/mattlab/dns"
	"github.com/itsmatinhimself/mattlab/relay"
	"github.com/itsmatinhimself/mattlab/routing"
	"github.com/itsmatinhimself/mattlab/tlsutil"
	"github.com/itsmatinhimself/mattlab/transport"
)

// Orchestrator creates transports, starts servers, and manages shutdown.
type Orchestrator struct {
	cfg        *config.Config
	cfgDir     string
	mitm       *tlsutil.MITMManager
	router     *routing.Router
	transports map[string]transport.Transport

	sniProxy   *SNIProxy
	httpProxy  *HTTPProxy
	socks5     *SOCKS5Proxy
	certServer *CertServer
	dnsServer  *mattdns.Server
}

// NewOrchestrator creates a new orchestrator from config.
func NewOrchestrator(cfg *config.Config, cfgDir string) (*Orchestrator, error) {
	o := &Orchestrator{
		cfg:        cfg,
		cfgDir:     cfgDir,
		transports: make(map[string]transport.Transport),
	}

	// Create router
	router, err := routing.NewRouter(cfg.Routes, cfg.DefaultOutbound, cfgDir)
	if err != nil {
		return nil, fmt.Errorf("create router: %w", err)
	}
	o.router = router

	// Create MITM manager
	mitm, err := tlsutil.NewMITMManager(filepath.Join(cfgDir, ".mattlab_ca"))
	if err != nil {
		return nil, fmt.Errorf("create MITM manager: %w", err)
	}
	o.mitm = mitm

	// Create transports
	for i := range cfg.Outbounds {
		ob := &cfg.Outbounds[i]
		switch ob.Type {
		case "direct":
			o.transports[ob.Tag] = transport.NewDirect()
		case "block":
			o.transports[ob.Tag] = transport.NewBlock()
		case "domain_front":
			o.transports[ob.Tag] = transport.NewDomainFront(
				ob.TargetIP, ob.TargetPort, ob.FrontSNI,
			)
		case "relay":
			client := relay.NewClient(
				ob.TargetIP, ob.TargetPort, ob.FrontSNI,
				ob.ScriptIDs, ob.AuthKey, ob.RelayDomain, ob.Format,
				ob.BatchEnabled, ob.H2Enabled,
			)
			o.transports[ob.Tag] = transport.NewRelay(client)
		}
	}

	return o, nil
}

// Run starts all components and blocks until interrupted.
func (o *Orchestrator) Run() error {
	ctx := context.Background()

	// Warm relay clients
	for tag, t := range o.transports {
		if rt, ok := t.(*transport.RelayTransport); ok {
			log.Printf("Warming relay connections for %s...", tag)
			rt.Client().Warm(ctx)
		}
	}

	// Start servers
	if o.cfg.Inbounds.SNIProxy.Enabled {
		o.sniProxy = NewSNIProxy(
			fmt.Sprintf("%s:%d", o.cfg.ListenHost, o.cfg.Inbounds.SNIProxy.Port),
			o.router, o.mitm, o.transports,
		)
		if err := o.sniProxy.Start(); err != nil {
			return err
		}
		go o.sniProxy.Serve()
	}

	if o.cfg.Inbounds.HTTPProxy.Enabled {
		o.httpProxy = NewHTTPProxy(
			fmt.Sprintf("%s:%d", o.cfg.ListenHost, o.cfg.Inbounds.HTTPProxy.Port),
			o.router, o.mitm, o.transports,
		)
		if err := o.httpProxy.Start(); err != nil {
			return err
		}
		go o.httpProxy.Serve()
	}

	if o.cfg.Inbounds.SOCKS5.Enabled {
		o.socks5 = NewSOCKS5Proxy(
			fmt.Sprintf("%s:%d", o.cfg.ListenHost, o.cfg.Inbounds.SOCKS5.Port),
			o.router, o.mitm, o.transports,
		)
		if err := o.socks5.Start(); err != nil {
			return err
		}
		go o.socks5.Serve()
	}

	if o.cfg.Inbounds.CertServer.Enabled {
		o.certServer = NewCertServer(
			o.cfg.ListenHost, o.cfg.Inbounds.CertServer.Port,
			o.cfg.Inbounds.HTTPProxy.Port,
			o.mitm.CACertPath(),
		)
		if err := o.certServer.Start(); err != nil {
			return err
		}
		go o.certServer.Serve()
	}

	if o.cfg.Inbounds.DNSServer.Enabled {
		dnsCfg := &o.cfg.Inbounds.DNSServer
		addr := fmt.Sprintf("%s:%d", o.cfg.ListenHost, dnsCfg.Port)

		var handler mattdns.Handler
		switch dnsCfg.Mode {
		case "sniproxy":
			listenIP := o.cfg.ListenHost
			if listenIP == "" || listenIP == "0.0.0.0" {
				detected, err := getOutboundIP()
				if err != nil {
					return fmt.Errorf("dns: cannot detect outbound IP: %w", err)
				}
				listenIP = detected
			}
			proxyIP := net.ParseIP(listenIP)
			if proxyIP == nil {
				return fmt.Errorf("dns: invalid listen IP: %s", listenIP)
			}
			upstream := mattdns.NewUpstreamResolver(dnsCfg.UpstreamDNS)
			handler = mattdns.NewSNIProxyHandler(o.router, proxyIP, upstream, o.cfg.DefaultOutbound)
		case "doh":
			t, ok := o.transports[dnsCfg.DoHOutbound]
			if !ok {
				return fmt.Errorf("dns doh_outbound %q not found", dnsCfg.DoHOutbound)
			}
			resolver := mattdns.NewDoHResolver(dnsCfg.DoHURL, t)
			handler = mattdns.NewDoHHandler(resolver)
		}

		// Generate TLS config for DoT using the MITM CA (cert will have IP SAN)
		dotIP := o.cfg.ListenHost
		if dotIP == "" || dotIP == "0.0.0.0" {
			if ip, err := getOutboundIP(); err == nil {
				dotIP = ip
			}
		}
		dotTLS := o.mitm.GetTLSConfig(dotIP)

		o.dnsServer = mattdns.NewServerWithDoT(addr, dnsCfg.DoTPort, handler, dotTLS)
		if err := o.dnsServer.Start(); err != nil {
			return err
		}
		go o.dnsServer.Serve()

		// Tell cert server to offer the iOS profile with DNS settings
		if o.certServer != nil {
			o.certServer.SetDNS(dotIP, dnsCfg.Port, dnsCfg.DoTPort)
		}
	}

	o.printBanner()

	// Wait for signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	fmt.Println() // newline after ^C

	o.shutdown()
	return nil
}

func getOutboundIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80") // no traffic actually sent
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}

func (o *Orchestrator) printBanner() {
	lines := []string{
		"",
		"  Mattlab Proxy",
		"  ==============",
	}

	for _, ob := range o.cfg.Outbounds {
		switch ob.Type {
		case "domain_front":
			lines = append(lines, fmt.Sprintf("  Outbound:   %s (domain_front → %s)", ob.Tag, ob.FrontSNI))
		case "relay":
			lines = append(lines, fmt.Sprintf("  Outbound:   %s (relay, %d script(s))", ob.Tag, len(ob.ScriptIDs)))
		default:
			lines = append(lines, fmt.Sprintf("  Outbound:   %s (%s)", ob.Tag, ob.Type))
		}
	}

	host := o.cfg.ListenHost
	if host == "0.0.0.0" || host == "" {
		if ip, err := getOutboundIP(); err == nil {
			host = ip
		}
	}

	if o.cfg.Inbounds.SNIProxy.Enabled {
		lines = append(lines, fmt.Sprintf("  SNI Proxy:  %s:%d", host, o.cfg.Inbounds.SNIProxy.Port))
	}
	if o.cfg.Inbounds.HTTPProxy.Enabled {
		lines = append(lines, fmt.Sprintf("  HTTP Proxy: %s:%d", host, o.cfg.Inbounds.HTTPProxy.Port))
	}
	if o.cfg.Inbounds.SOCKS5.Enabled {
		lines = append(lines, fmt.Sprintf("  SOCKS5:     %s:%d", host, o.cfg.Inbounds.SOCKS5.Port))
	}
	if o.cfg.Inbounds.DNSServer.Enabled {
		lines = append(lines, fmt.Sprintf("  DNS Server: %s:%d (%s), DoT :%d", host, o.cfg.Inbounds.DNSServer.Port, o.cfg.Inbounds.DNSServer.Mode, o.cfg.Inbounds.DNSServer.DoTPort))
	}
	if o.cfg.Inbounds.CertServer.Enabled {
		lines = append(lines, fmt.Sprintf("  Setup:      http://%s:%d  ← open on phone to install certs", host, o.cfg.Inbounds.CertServer.Port))
	}
	lines = append(lines, "", "  Press Ctrl+C to stop.", "")

	for _, line := range lines {
		fmt.Println(line)
	}
}

func (o *Orchestrator) shutdown() {
	log.Println("Shutting down...")

	shutdownTimeout := 3 * time.Second

	if o.dnsServer != nil {
		o.dnsServer.Stop()
	}
	if o.certServer != nil {
		o.certServer.Stop()
	}
	if o.httpProxy != nil {
		o.httpProxy.Stop()
	}
	if o.socks5 != nil {
		o.socks5.Stop()
	}
	if o.sniProxy != nil {
		o.sniProxy.Stop()
	}

	// Close transports with timeout
	done := make(chan struct{})
	go func() {
		for _, t := range o.transports {
			t.Close()
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(shutdownTimeout):
		log.Println("Transport close timed out")
	}

	log.Println("Stopped.")
}
