package proxy

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
)

// CertServer serves the CA certificate and installation instructions.
type CertServer struct {
	addr       string
	httpPort   int
	caCertPath string
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

	if path == "/ca.crt" {
		c.serveCert(conn)
	} else {
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

func (c *CertServer) serveHTML(conn net.Conn) {
	host, _, _ := net.SplitHostPort(c.addr)
	html := fmt.Sprintf(htmlTemplate, host, c.httpPort)

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
<title>Mattlab - Install CA Certificate</title>
<style>
  body { font-family: -apple-system, sans-serif; max-width: 500px; margin: 40px auto; padding: 0 20px; color: #333; }
  h1 { font-size: 1.5em; }
  .btn { display: inline-block; padding: 14px 28px; background: #007AFF; color: #fff;
         text-decoration: none; border-radius: 10px; font-size: 1.1em; margin: 10px 0; }
  .btn:hover { background: #0056b3; }
  ol { line-height: 2; }
  .note { background: #f0f0f0; padding: 12px; border-radius: 8px; font-size: 0.9em; }
</style>
</head>
<body>
<h1>Mattlab Proxy Certificate</h1>
<p>Download and trust this certificate to use the proxy.</p>
<a class="btn" href="/ca.crt">Download Certificate</a>

<h2>iOS / iPhone</h2>
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

<div class="note">
  <b>WiFi Proxy Setup:</b><br>
  Set HTTP Proxy on your device to <b>%s:%d</b>
</div>
</body>
</html>
`
