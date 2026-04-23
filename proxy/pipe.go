package proxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/itsmatinhimself/mattlab/internal"
	"github.com/itsmatinhimself/mattlab/transport"
)

// bufferedConn wraps a net.Conn but first replays bytes drained from a
// bufio.Reader (or raw peek buffer), then reads from the underlying Conn.
// This is critical when a bufio.Reader has consumed TLS handshake bytes
// that a subsequent tls.Server/tls.Client needs to see.
type bufferedConn struct {
	net.Conn
	reader io.Reader
}

func newBufferedConn(conn net.Conn, extra []byte) *bufferedConn {
	return &bufferedConn{
		Conn:   conn,
		reader: io.MultiReader(bytes.NewReader(extra), conn),
	}
}

func newBufferedConnFromReader(conn net.Conn, br *bufio.Reader) *bufferedConn {
	n := br.Buffered()
	if n == 0 {
		return nil
	}
	buf, _ := br.Peek(n)
	return &bufferedConn{
		Conn:   conn,
		reader: io.MultiReader(bytes.NewReader(buf), conn),
	}
}

func (bc *bufferedConn) Read(p []byte) (int, error) {
	return bc.reader.Read(p)
}

// Pipe performs bidirectional copying between two connections.
func Pipe(ctx context.Context, a, b net.Conn) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			cancel()
			a.Close()
			b.Close()
		})
	}

	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(b, a)
		errCh <- err
		closeBoth()
	}()
	go func() {
		_, err := io.Copy(a, b)
		errCh <- err
		closeBoth()
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// safeClose closes a connection. Errors from closing an already-closed
// connection are expected (Pipe's closeBoth may have closed it first).
func safeClose(conn net.Conn) {
	if conn != nil {
		conn.Close()
	}
}

// handleRelayLoop reads HTTP requests from a TLS connection and relays
// each through the relay transport. Shared by SNI proxy, HTTP proxy, and SOCKS5.
func handleRelayLoop(ctx context.Context, tlsConn net.Conn, defaultHost string, rt *transport.RelayTransport) {
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
			host = defaultHost
		}
		targetURL := fmt.Sprintf("https://%s%s", host, path)

		resp, err := rt.Relay(ctx, method, targetURL, headers, body)
		if err != nil {
			log.Printf("[relay] error for %s: %v", targetURL, err)
			return
		}

		tlsConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		tlsConn.Write(resp)
	}
}
