package proxy

import (
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	qrcode "github.com/skip2/go-qrcode"
)

// CertServer serves the CA certificate and installation instructions.
type CertServer struct {
	addr       string
	httpPort   int
	caCertPath string
	dnsIP      string // proxy IP for DNS profile (empty = no DNS)
	dnsPort    int
	dotPort    int // DNS-over-TLS port
	listener   net.Listener
}

// NewCertServer creates a new cert download server.
func NewCertServer(addr string, port int, httpPort int, caCertPath string) *CertServer {
	return &CertServer{
		addr:       fmt.Sprintf("%s:%d", addr, port),
		httpPort:   httpPort,
		caCertPath: caCertPath,
	}
}

// SetDNS enables the iOS profile with DNS settings pointing to the proxy.
func (c *CertServer) SetDNS(ip string, port, dotPort int) {
	c.dnsIP = ip
	c.dnsPort = port
	c.dotPort = dotPort
}

// Start begins listening.
func (c *CertServer) Start() error {
	var err error
	c.listener, err = net.Listen("tcp", c.addr)
	if err != nil {
		return fmt.Errorf("cert server listen: %w", err)
	}
	log.Printf("Cert server on http://%s", c.addr)
	return nil
}

// Serve accepts connections.
func (c *CertServer) Serve() error {
	for {
		conn, err := c.listener.Accept()
		if err != nil {
			return err
		}
		go c.handle(conn)
	}
}

// Stop closes the listener.
func (c *CertServer) Stop() {
	if c.listener != nil {
		c.listener.Close()
	}
}

func (c *CertServer) handle(conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	request := string(buf[:n])

	lines := strings.Split(request, "\r\n")
	if len(lines) == 0 {
		return
	}

	path := "/"
	if parts := strings.SplitN(lines[0], " ", 3); len(parts) >= 2 {
		path = parts[1]
	}

	switch path {
	case "/ca.crt":
		c.serveCert(conn)
	case "/mattlab.mobileconfig":
		c.serveProfile(conn)
	default:
		c.serveHTML(conn)
	}
}

func (c *CertServer) serveCert(conn net.Conn) {
	data, err := os.ReadFile(c.caCertPath)
	if err != nil {
		conn.Write([]byte("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n"))
		return
	}

	resp := fmt.Sprintf("HTTP/1.1 200 OK\r\n"+
		"Content-Type: application/x-x509-ca-cert\r\n"+
		"Content-Disposition: attachment; filename=\"mattlab_ca.crt\"\r\n"+
		"Content-Length: %d\r\n"+
		"Connection: close\r\n"+
		"\r\n", len(data))

	conn.Write([]byte(resp))
	conn.Write(data)
}

func (c *CertServer) serveProfile(conn net.Conn) {
	certPEM, err := os.ReadFile(c.caCertPath)
	if err != nil {
		conn.Write([]byte("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n"))
		return
	}

	// Decode PEM to DER for the mobileconfig payload
	block, _ := pem.Decode(certPEM)
	if block == nil {
		conn.Write([]byte("HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n"))
		return
	}
	certB64 := base64.StdEncoding.EncodeToString(block.Bytes)

	// Build optional DoT DNS payload
	dnsPayload := ""
	if c.dnsIP != "" && c.dotPort > 0 {
		serverPortXML := ""
		if c.dotPort != 853 {
			serverPortXML = fmt.Sprintf(`
			<key>ServerPort</key>
			<integer>%d</integer>`, c.dotPort)
		}
		dnsPayload = fmt.Sprintf(`
		<dict>
			<key>PayloadType</key>
			<string>com.apple.dnsSettings.managed</string>
			<key>PayloadIdentifier</key>
			<string>com.mattlab.profile.dns</string>
			<key>PayloadUUID</key>
			<string>A1B2C3D4-E5F6-7890-ABCD-EF1234567891</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
			<key>PayloadDisplayName</key>
			<string>Mattlab DNS</string>
			<key>DNSSettings</key>
			<dict>
				<key>DNSProtocol</key>
				<string>TLS</string>
				<key>ServerAddresses</key>
				<array>
					<string>%s</string>
				</array>
				<key>ServerName</key>
				<string>%s</string>%s
			</dict>
		</dict>`, c.dnsIP, c.dnsIP, serverPortXML)
	}

	profileDesc := "Installs Mattlab CA certificate for proxy trust."
	if dnsPayload != "" {
		profileDesc = "Installs Mattlab CA certificate and configures DNS-over-TLS."
	}

	profile := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadIdentifier</key>
			<string>com.mattlab.profile.cert</string>
			<key>PayloadUUID</key>
			<string>A1B2C3D4-E5F6-7890-ABCD-EF1234567890</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
			<key>PayloadDisplayName</key>
			<string>Mattlab CA Certificate</string>
			<key>PayloadContent</key>
			<data>%s</data>
		</dict>%s
	</array>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadIdentifier</key>
	<string>com.mattlab.profile</string>
	<key>PayloadUUID</key>
	<string>A1B2C3D4-E5F6-7890-ABCD-EF1234567892</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
	<key>PayloadDisplayName</key>
	<string>Mattlab Proxy</string>
	<key>PayloadDescription</key>
	<string>%s</string>
	<key>PayloadOrganization</key>
	<string>Mattlab</string>
</dict>
</plist>`, certB64, dnsPayload, profileDesc)

	resp := fmt.Sprintf("HTTP/1.1 200 OK\r\n"+
		"Content-Type: application/x-apple-aspen-config\r\n"+
		"Content-Disposition: attachment; filename=\"mattlab.mobileconfig\"\r\n"+
		"Content-Length: %d\r\n"+
		"Connection: close\r\n"+
		"\r\n", len(profile))

	conn.Write([]byte(resp))
	conn.Write([]byte(profile))
}

func (c *CertServer) serveHTML(conn net.Conn) {
	host, port, _ := net.SplitHostPort(c.addr)
	if host == "" || host == "0.0.0.0" {
		if c.dnsIP != "" {
			host = c.dnsIP
		} else if conn.LocalAddr() != nil {
			host, _, _ = net.SplitHostPort(conn.LocalAddr().String())
		}
	}

	profileDesc := "This profile installs the CA certificate so your phone trusts the proxy."
	if c.dnsIP != "" && c.dotPort > 0 {
		profileDesc = "This profile installs the CA certificate and configures encrypted DNS (DNS-over-TLS) automatically."
	}

	profileSection := fmt.Sprintf(`
<h2>iPhone — Install Profile</h2>
<p>%s</p>
<a class="btn btn-green" href="/mattlab.mobileconfig">Install iPhone Profile</a>
<ol>
  <li>Tap the button above</li>
  <li>Open <b>Settings &rarr; General &rarr; VPN &amp; Device Management</b></li>
  <li>Tap <b>Mattlab Proxy</b> and tap <b>Install</b></li>
  <li>Go to <b>Settings &rarr; General &rarr; About &rarr; Certificate Trust Settings</b></li>
  <li>Enable full trust for <b>Mattlab CA</b></li>
</ol>`, profileDesc)

	dnsSection := ""
	if c.dnsIP != "" {
		profileSection += fmt.Sprintf(`
<h3>Set DNS (manual)</h3>
<ol>
  <li>Open <b>Settings &rarr; Wi-Fi</b></li>
  <li>Tap the <b>(i)</b> next to your network</li>
  <li>Tap <b>Configure DNS &rarr; Manual</b></li>
  <li>Delete existing servers, add <b>%s</b></li>
  <li>Tap <b>Save</b></li>
</ol>`, c.dnsIP)
		dnsSection = fmt.Sprintf(`
<div class="note">
  <b>DNS Server:</b> %s:%d<br>
  Set this as your DNS on any device for transparent proxying.
</div>`, c.dnsIP, c.dnsPort)
	}
	profileSection += "\n<hr>"

	// Generate QR code as base64 PNG
	pageURL := fmt.Sprintf("http://%s:%s/", host, port)
	qrImg := ""
	if png, err := qrcode.Encode(pageURL, qrcode.Medium, 200); err == nil {
		qrImg = fmt.Sprintf(`<div style="text-align:center;margin:20px 0">
<img src="data:image/png;base64,%s" alt="QR" style="width:200px;height:200px"><br>
<small>Scan to open this page on another device</small>
</div>`, base64.StdEncoding.EncodeToString(png))
	}

	html := fmt.Sprintf(htmlTemplate, qrImg, profileSection, dnsSection, host, c.httpPort)

	resp := fmt.Sprintf("HTTP/1.1 200 OK\r\n"+
		"Content-Type: text/html; charset=utf-8\r\n"+
		"Content-Length: %d\r\n"+
		"Connection: close\r\n"+
		"\r\n", len(html))

	conn.Write([]byte(resp))
	conn.Write([]byte(html))
}

const htmlTemplate = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mattlab - Setup</title>
<style>
  body { font-family: -apple-system, sans-serif; max-width: 500px; margin: 40px auto; padding: 0 20px; color: #333; }
  h1 { font-size: 1.5em; }
  h2 { margin-top: 28px; }
  hr { border: none; border-top: 1px solid #ddd; margin: 28px 0; }
  .btn { display: inline-block; padding: 14px 28px; background: #007AFF; color: #fff;
         text-decoration: none; border-radius: 10px; font-size: 1.1em; margin: 10px 0; }
  .btn:hover { background: #0056b3; }
  .btn-green { background: #34C759; }
  .btn-green:hover { background: #2da44e; }
  ol { line-height: 2; }
  .note { background: #f0f0f0; padding: 12px; border-radius: 8px; font-size: 0.9em; }
</style>
</head>
<body>
<h1>Mattlab Proxy</h1>
%s%s
<h2>Certificate Only</h2>
<p>For Android, macOS, or other devices.</p>
<p>Download and trust this certificate to use the proxy.</p>
<a class="btn" href="/ca.crt">Download Certificate</a>

<h2>iOS (manual)</h2>
<ol>
  <li>Tap the button above to download the certificate</li>
  <li>Open <b>Settings &rarr; General &rarr; VPN &amp; Device Management</b></li>
  <li>Tap the downloaded profile and tap <b>Install</b></li>
  <li>Go to <b>Settings &rarr; General &rarr; About &rarr; Certificate Trust Settings</b></li>
  <li>Enable full trust for the Mattlab certificate</li>
</ol>

<h2>Android</h2>
<ol>
  <li>Tap the button above to download</li>
  <li>Open <b>Settings &rarr; Security &rarr; Install from storage</b></li>
  <li>Select the downloaded <b>.crt</b> file</li>
</ol>

<h2>macOS</h2>
<ol>
  <li>Download and double-click the certificate</li>
  <li>It opens in Keychain Access &rarr; double-click it</li>
  <li>Expand <b>Trust</b> &rarr; set to <b>Always Trust</b></li>
</ol>

%s
<div class="note">
  <b>WiFi Proxy Setup:</b><br>
  Set HTTP Proxy on your device to <b>%s:%d</b>
</div>
</body>
</html>
`
