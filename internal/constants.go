package internal

import "time"

// Size caps
const (
	MaxRequestBodyBytes  = 100 * 1024 * 1024 // 100 MB
	MaxResponseBodyBytes = 200 * 1024 * 1024 // 200 MB
	MaxHeaderBytes       = 64 * 1024         // 64 KB
)

// Timeouts
const (
	ClientIdleTimeout  = 120 * time.Second
	RelayTimeout       = 25 * time.Second
	TLSConnectTimeout  = 15 * time.Second
	TCPConnectTimeout  = 10 * time.Second
	DNSUpstreamTimeout = 5 * time.Second
)

// Connection pool (HTTP/1.1 to Apps Script)
const (
	PoolMax       = 50
	PoolMinIdle   = 15
	ConnTTL       = 45 * time.Second
	SemaphoreMax  = 50
	WarmPoolCount = 30
)

// Batch windows
const (
	BatchWindowMicro = 5 * time.Millisecond
	BatchWindowMacro = 50 * time.Millisecond
	BatchMax         = 50
)

// SNI proxy
const (
	SNIPeekTimeout = 5 * time.Second
	SNIPeekSize    = 65536
	RelayBufSize   = 65536
)

// Stateful-request hints (for relay batching decisions)
var StatefulHeaderNames = []string{
	"cookie", "authorization", "proxy-authorization",
	"origin", "referer", "if-none-match", "if-modified-since",
	"cache-control", "pragma",
}

// Static file extensions (requests for these are considered stateless)
var StaticExts = []string{
	".css", ".js", ".mjs", ".woff", ".woff2", ".ttf", ".eot",
	".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
	".mp3", ".mp4", ".webm", ".wasm", ".avif",
}
