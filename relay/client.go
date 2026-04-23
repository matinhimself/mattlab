package relay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/itsmatinhimself/mattlab/internal"
)

// Client is an Apps Script relay client with connection pooling, batching,
// coalescing, and H2 support.
type Client struct {
	connectHost  string
	sniHost      string
	httpHost     string
	scriptIDs    []string
	authKey      string
	format       string // "form" or "json"
	batchEnabled bool
	h2Enabled    bool

	// H1 connection pool
	pool   []*poolConn
	poolMu sync.Mutex
	sem    chan struct{}
	warmed atomic.Bool

	// H2 transport
	h2       *H2Transport
	h2Active atomic.Bool

	// Batching
	batchMu      sync.Mutex
	batchPending []batchEntry
	batchTimer   *time.Timer

	// Coalescing
	coalesceMu sync.Mutex
	coalesce   map[string][]coalesceWaiter

	// Script ID round-robin
	scriptIdx atomic.Uint64

	// Background goroutines
	bgCtx    context.Context
	bgCancel context.CancelFunc
}

type poolConn struct {
	conn    net.Conn
	reader  *bufio.Reader
	created time.Time
}

type batchEntry struct {
	payload *Payload
	result  chan batchResult
}

type batchResult struct {
	data []byte
	err  error
}

type coalesceWaiter struct {
	result chan []byte
}

// NewClient creates a new relay client.
func NewClient(connectHost string, targetPort int, frontSNI string,
	scriptIDs []string, authKey, relayDomain, format string,
	batchEnabled, h2Enabled bool) *Client {

	c := &Client{
		connectHost:  connectHost,
		sniHost:      frontSNI,
		httpHost:     relayDomain,
		scriptIDs:    scriptIDs,
		authKey:      authKey,
		format:       format,
		batchEnabled: batchEnabled,
		h2Enabled:    h2Enabled,
		sem:          make(chan struct{}, internal.SemaphoreMax),
		coalesce:     make(map[string][]coalesceWaiter),
	}

	c.bgCtx, c.bgCancel = context.WithCancel(context.Background())

	if h2Enabled {
		c.h2 = NewH2Transport(connectHost, frontSNI)
	}

	return c
}

// Warm pre-opens connection pools and H2 session.
func (c *Client) Warm(ctx context.Context) {
	if c.warmed.Load() {
		return
	}
	c.warmed.Store(true)

	// Warm H1 pool
	var wg sync.WaitGroup
	for i := 0; i < internal.WarmPoolCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if conn, err := c.dialTLS(ctx); err == nil {
				c.releaseConn(conn)
			}
		}()
	}
	wg.Wait()

	// Warm H2
	if c.h2Enabled && c.h2 != nil {
		if err := c.h2.Connect(ctx); err == nil {
			c.h2Active.Store(true)
			log.Println("H2 multiplexing active")
			go c.keepaliveLoop()
		} else {
			log.Printf("H2 connect failed (%v), using H1 pool", err)
		}
	}

	// Start pool maintenance
	go c.poolMaintenance()
}

// Relay sends an HTTP request through the relay and returns raw HTTP response bytes.
func (c *Client) Relay(ctx context.Context, method, targetURL string,
	headers map[string]string, body []byte) ([]byte, error) {

	// Build payload
	var payload *Payload
	if c.format == "form" {
		payload = BuildFormPayload(method, targetURL, headers, body)
	} else {
		payload = BuildJSONPayload(method, targetURL, headers, body, c.authKey)
	}

	// Stateful requests go direct (no batching/coalescing)
	if isStatefulRequest(method, targetURL, headers, body) {
		return c.relayWithRetry(ctx, payload)
	}

	// Coalesce concurrent identical GETs (no Range header)
	hasRange := false
	for k := range headers {
		if strings.EqualFold(k, "range") {
			hasRange = true
			break
		}
	}

	if method == "GET" && len(body) == 0 && !hasRange {
		return c.coalescedSubmit(ctx, targetURL, payload)
	}

	return c.batchSubmit(ctx, payload)
}

// Close shuts down the client and all connections.
func (c *Client) Close() error {
	c.bgCancel()

	c.poolMu.Lock()
	for _, pc := range c.pool {
		pc.conn.Close()
	}
	c.pool = nil
	c.poolMu.Unlock()

	if c.h2 != nil {
		c.h2.Close()
	}

	return nil
}

// ── Connection pool ─────────────────────────────────────────────

func (c *Client) dialTLS(ctx context.Context) (*poolConn, error) {
	dialer := &net.Dialer{Timeout: internal.TLSConnectTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", c.connectHost+":443")
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         c.sniHost,
		InsecureSkipVerify: true,
	})

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}

	return &poolConn{
		conn:    tlsConn,
		reader:  bufio.NewReaderSize(tlsConn, 65536),
		created: time.Now(),
	}, nil
}

func (c *Client) acquireConn(ctx context.Context) (*poolConn, error) {
	// Try pool first
	c.poolMu.Lock()
	now := time.Now()
	for i := len(c.pool) - 1; i >= 0; i-- {
		pc := c.pool[i]
		if now.Sub(pc.created) < internal.ConnTTL {
			c.pool = append(c.pool[:i], c.pool[i+1:]...)
			c.poolMu.Unlock()
			return pc, nil
		}
		pc.conn.Close()
		c.pool = append(c.pool[:i], c.pool[i+1:]...)
	}
	c.poolMu.Unlock()

	// Dial new
	return c.dialTLS(ctx)
}

func (c *Client) releaseConn(pc *poolConn) {
	if time.Since(pc.created) >= internal.ConnTTL {
		pc.conn.Close()
		return
	}

	c.poolMu.Lock()
	if len(c.pool) < internal.PoolMax {
		c.pool = append(c.pool, pc)
	} else {
		pc.conn.Close()
	}
	c.poolMu.Unlock()
}

func (c *Client) poolMaintenance() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.bgCtx.Done():
			return
		case <-ticker.C:
			c.pruneAndRefill()
		}
	}
}

func (c *Client) pruneAndRefill() {
	now := time.Now()

	c.poolMu.Lock()
	var alive []*poolConn
	for _, pc := range c.pool {
		if now.Sub(pc.created) < internal.ConnTTL {
			alive = append(alive, pc)
		} else {
			pc.conn.Close()
		}
	}
	c.pool = alive
	needed := internal.PoolMinIdle - len(alive)
	c.poolMu.Unlock()

	for i := 0; i < needed && i < 5; i++ {
		if pc, err := c.dialTLS(c.bgCtx); err == nil {
			c.releaseConn(pc)
		}
	}
}

// ── Script ID selection ─────────────────────────────────────────

func (c *Client) execPath(targetURL string) string {
	var sid string
	if len(c.scriptIDs) == 1 {
		sid = c.scriptIDs[0]
	} else if targetURL != "" {
		// Hash-based selection
		u, _ := url.Parse(targetURL)
		host := ""
		if u != nil {
			host = strings.ToLower(strings.TrimRight(u.Hostname(), "."))
		}
		digest := sha1.Sum([]byte(host))
		idx := binary.BigEndian.Uint32(digest[:4]) % uint32(len(c.scriptIDs))
		sid = c.scriptIDs[idx]
	} else {
		// Round-robin
		idx := c.scriptIdx.Add(1) % uint64(len(c.scriptIDs))
		sid = c.scriptIDs[idx]
	}
	return fmt.Sprintf("/macros/s/%s/exec", sid)
}

// ── Core relay ──────────────────────────────────────────────────

func (c *Client) relayWithRetry(ctx context.Context, payload *Payload) ([]byte, error) {
	// Try H2 first
	if c.h2Enabled && c.h2Active.Load() && c.h2.IsConnected() {
		result, err := c.relayH2(ctx, payload)
		if err == nil {
			return result, nil
		}
		log.Printf("H2 relay failed: %v, falling back to H1", err)
	}

	// H1 with retry
	c.sem <- struct{}{}
	defer func() { <-c.sem }()

	result, err := c.relayH1(ctx, payload)
	if err != nil {
		// Flush pool and retry once
		c.poolMu.Lock()
		for _, pc := range c.pool {
			pc.conn.Close()
		}
		c.pool = nil
		c.poolMu.Unlock()

		return c.relayH1(ctx, payload)
	}
	return result, nil
}

func (c *Client) relayH2(ctx context.Context, payload *Payload) ([]byte, error) {
	path := c.execPath(payload.TargetURL)

	status, respHeaders, respBody, err := c.h2.Request(ctx, "POST", path, c.httpHost,
		map[string]string{"content-type": payload.ContentType}, payload.Body, internal.RelayTimeout, 5)
	if err != nil {
		return nil, fmt.Errorf("h2 request: %w", err)
	}

	log.Printf("H2 relay response: status=%d path=%s bodyLen=%d location=%s",
		status, path, len(respBody), respHeaders["location"])

	if len(respBody) > 0 && len(respBody) < 500 {
		log.Printf("H2 relay body: %s", string(respBody))
	}

	if status >= 400 {
		return nil, fmt.Errorf("h2 status %d", status)
	}
	return ParseRelayResponse(respBody, payload.Format)
}

func (c *Client) relayH1(ctx context.Context, payload *Payload) ([]byte, error) {
	pc, err := c.acquireConn(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire connection: %w", err)
	}

	path := c.execPath(payload.TargetURL)

	// Build HTTP request
	req := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Content-Type: %s\r\n"+
		"Content-Length: %d\r\n"+
		"Accept-Encoding: gzip\r\n"+
		"Connection: keep-alive\r\n"+
		"\r\n", path, c.httpHost, payload.ContentType, len(payload.Body))

	if _, err := pc.conn.Write([]byte(req)); err != nil {
		pc.conn.Close()
		return nil, err
	}
	if _, err := pc.conn.Write(payload.Body); err != nil {
		pc.conn.Close()
		return nil, err
	}

	// Read response
	status, respHeaders, respBody, err := c.readHTTPResponse(pc.reader)
	if err != nil {
		pc.conn.Close()
		return nil, err
	}

	// Follow redirects
	for i := 0; i < 5; i++ {
		if status < 301 || status > 308 {
			break
		}
		location := respHeaders["location"]
		if location == "" {
			break
		}

		parsed, err := url.Parse(location)
		if err != nil {
			break
		}
		rpath := parsed.Path
		if parsed.RawQuery != "" {
			rpath += "?" + parsed.RawQuery
		}

		req = fmt.Sprintf("GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Accept-Encoding: gzip\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n", rpath, c.httpHost)

		if _, err := pc.conn.Write([]byte(req)); err != nil {
			pc.conn.Close()
			return nil, err
		}

		status, respHeaders, respBody, err = c.readHTTPResponse(pc.reader)
		if err != nil {
			pc.conn.Close()
			return nil, err
		}
	}

	// Decode content-encoding
	if enc, ok := respHeaders["content-encoding"]; ok {
		respBody = Decode(respBody, enc)
	}

	c.releaseConn(pc)

	// Parse the relay JSON response into raw HTTP bytes
	return ParseRelayResponse(respBody, payload.Format)
}

func (c *Client) readHTTPResponse(r *bufio.Reader) (int, map[string]string, []byte, error) {
	// Read header section
	var headerBuf bytes.Buffer
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			return 0, nil, nil, err
		}
		headerBuf.Write(line)
		if bytes.HasSuffix(line, []byte("\r\n\r\n")) || line[0] == '\n' {
			break
		}
		if headerBuf.Len() > 65536 {
			return 0, nil, nil, fmt.Errorf("response headers too large")
		}
	}

	headerSection := headerBuf.String()
	lines := strings.Split(strings.TrimRight(headerSection, "\r\n"), "\r\n")
	if len(lines) == 0 {
		return 0, nil, nil, fmt.Errorf("empty response")
	}

	// Parse status
	status := 0
	if parts := strings.SplitN(lines[0], " ", 3); len(parts) >= 2 {
		fmt.Sscanf(parts[1], "%d", &status)
	}

	// Parse headers
	headers := make(map[string]string)
	for _, line := range lines[1:] {
		if idx := strings.Index(line, ":"); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			val := strings.TrimSpace(line[idx+1:])
			headers[strings.ToLower(key)] = val
		}
	}

	// Read body
	var body bytes.Buffer
	if cl, ok := headers["content-length"]; ok {
		var contentLen int
		fmt.Sscanf(cl, "%d", &contentLen)
		if contentLen > 0 {
			_, err := io.CopyN(&body, r, int64(contentLen))
			if err != nil {
				return status, headers, nil, err
			}
		}
	} else if strings.Contains(headers["transfer-encoding"], "chunked") {
		for {
			chunkLine, err := r.ReadBytes('\n')
			if err != nil {
				break
			}
			sizeStr := strings.TrimSpace(strings.Split(strings.TrimSpace(string(chunkLine)), ";")[0])
			var chunkSize int
			fmt.Sscanf(sizeStr, "%x", &chunkSize)
			if chunkSize == 0 {
				break
			}
			chunk := make([]byte, chunkSize)
			if _, err := io.ReadFull(r, chunk); err != nil {
				break
			}
			body.Write(chunk)
			r.ReadBytes('\n') // trailing CRLF
		}
	}

	return status, headers, body.Bytes(), nil
}

// ── Coalescing ──────────────────────────────────────────────────

func (c *Client) coalescedSubmit(ctx context.Context, targetURL string, payload *Payload) ([]byte, error) {
	c.coalesceMu.Lock()
	if waiters, ok := c.coalesce[targetURL]; ok {
		ch := make(chan []byte, 1)
		c.coalesce[targetURL] = append(waiters, coalesceWaiter{result: ch})
		c.coalesceMu.Unlock()
		select {
		case data := <-ch:
			return data, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	c.coalesce[targetURL] = nil
	c.coalesceMu.Unlock()

	result, err := c.batchSubmit(ctx, payload)

	c.coalesceMu.Lock()
	waiters := c.coalesce[targetURL]
	delete(c.coalesce, targetURL)
	c.coalesceMu.Unlock()

	if err != nil {
		for _, w := range waiters {
			w.result <- errorResponse(502, err.Error())
		}
		return nil, err
	}

	for _, w := range waiters {
		w.result <- result
	}
	return result, nil
}

// ── Batching ────────────────────────────────────────────────────

func (c *Client) batchSubmit(ctx context.Context, payload *Payload) ([]byte, error) {
	if !c.batchEnabled {
		return c.relayWithRetry(ctx, payload)
	}

	ch := make(chan batchResult, 1)
	entry := batchEntry{payload: payload, result: ch}

	c.batchMu.Lock()
	c.batchPending = append(c.batchPending, entry)
	if len(c.batchPending) >= internal.BatchMax {
		batch := c.batchPending
		c.batchPending = nil
		if c.batchTimer != nil {
			c.batchTimer.Stop()
			c.batchTimer = nil
		}
		c.batchMu.Unlock()
		go c.batchSend(batch)
	} else if c.batchTimer == nil {
		c.batchTimer = time.AfterFunc(internal.BatchWindowMacro, func() {
			c.batchMu.Lock()
			batch := c.batchPending
			c.batchPending = nil
			c.batchTimer = nil
			c.batchMu.Unlock()
			if len(batch) > 0 {
				go c.batchSend(batch)
			}
		})
		c.batchMu.Unlock()
	} else {
		c.batchMu.Unlock()
	}

	select {
	case r := <-ch:
		return r.data, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *Client) batchSend(batch []batchEntry) {
	for _, entry := range batch {
		result, err := c.relayWithRetry(context.Background(), entry.payload)
		if err != nil {
			entry.result <- batchResult{data: errorResponse(502, err.Error()), err: err}
		} else {
			entry.result <- batchResult{data: result}
		}
	}
}

// ── Keepalive ───────────────────────────────────────────────────

func (c *Client) keepaliveLoop() {
	ticker := time.NewTicker(240 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.bgCtx.Done():
			return
		case <-ticker.C:
			if c.h2 == nil || !c.h2.IsConnected() {
				if err := c.h2.Reconnect(c.bgCtx); err != nil {
					continue
				}
			}
			// H2 PING would go here in a full implementation
		}
	}
}

// ── Stateful detection ──────────────────────────────────────────

func isStatefulRequest(method, targetURL string, headers map[string]string, body []byte) bool {
	if method != "GET" && method != "HEAD" || len(body) > 0 {
		return true
	}

	for _, name := range internal.StatefulHeaderNames {
		for k := range headers {
			if strings.EqualFold(k, name) {
				return true
			}
		}
	}

	if accept, ok := getHeader(headers, "accept"); ok {
		al := strings.ToLower(accept)
		if strings.Contains(al, "text/html") || strings.Contains(al, "application/json") {
			return true
		}
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return true
	}
	path := strings.ToLower(u.Path)

	// If path ends with a static extension, it's stateless
	for _, ext := range internal.StaticExts {
		if strings.HasSuffix(path, ext) {
			return false
		}
	}

	// Non-static path is stateful
	return path != "/" && !strings.Contains(path, ".")
}

func getHeader(headers map[string]string, name string) (string, bool) {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}

// Decode is re-exported for convenience.
func decodeBody(body []byte, encoding string) []byte {
	return Decode(body, encoding)
}

// EncodeBase64 is a helper for base64 encoding.
func encodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}
