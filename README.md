# mattlab

A Go proxy that routes traffic through domain fronting and Google Apps Script relays to bypass DPI/SNI-based filtering.

## How It Works

```
Client
  │
  ├── :8080 ──► Cert Server 
  │
  ├── :443  ──► SNI Proxy ──┐
  ├── :8085 ──► HTTP Proxy ─┤
  └── :1080 ──► SOCKS5 ─────┤
                             │
                  extract hostname
                             │
                             ▼
                          Router
                  (first-match on .txt files)
                             │
                             ▼
                   Outbound Transport
                   ┌──────────────────┐
                   │ domain_front     │  TLS to target IP with a fake SNI
                   │ relay            │  HTTP via Google Apps Script
                   │ direct           │  plain TCP
                   │ block            │  drop connection
                   └──────────────────┘
```

Traffic enters through one of four inbound servers (SNI proxy, HTTP CONNECT, SOCKS5). The router extracts the target hostname and matches it against domain list files (first match wins, falls back to `default_outbound`). Matched traffic is sent through the corresponding outbound transport:

- **domain_front** — TLS connection to a target IP using a fronted SNI hostname (e.g. connect to a Google IP with `SNI: google.com`). The proxy MITMs the client-side TLS, then re-encrypts upstream with the front SNI.
- **relay** — HTTP requests are forwarded through Google Apps Script endpoints over a domain-fronted connection. Supports H1 connection pooling, H2 multiplexing, request batching, and response coalescing.
- **direct** — plain TCP, no MITM.
- **block** — immediately closes the connection.

## Build & Run

```bash
# build
make build

# run
./mattlab -c config.json
```

Cross-compile all platforms:

```bash
make release
```

## Configuration

Config is a single JSON file. Domain lists are `.txt` files referenced by relative path from the config file directory.

```json
{
  "listen_host": "0.0.0.0",
  "log_level": "info",

  "inbounds": {
    "sni_proxy":   { "enabled": false, "port": 443 },
    "http_proxy":  { "enabled": true,  "port": 8085 },
    "socks5":      { "enabled": true,  "port": 1080 },
    "cert_server": { "enabled": true,  "port": 8080 }
  },

  "outbounds": [
    {
      "tag": "google-front",
      "type": "domain_front",
      "target_ip": "216.239.38.120",
      "target_port": 443,
      "front_sni": "google.com"
    },
    {
      "tag": "gas-relay",
      "type": "relay",
      "target_ip": "216.239.38.120",
      "target_port": 443,
      "front_sni": "google.com",
      "script_ids": ["YOUR_SCRIPT_ID"],
      "auth_key": "",
      "relay_domain": "script.google.com",
      "format": "json",
      "batch_enabled": true,
      "h2_enabled": true
    },
    { "tag": "direct", "type": "direct" },
    { "tag": "block",  "type": "block" }
  ],

  "routes": [
    { "domains": "domains/google.txt", "outbound": "google-front" },
    { "domains": "domains/local.txt",  "outbound": "direct" }
  ],

  "default_outbound": "direct"
}
```

**Key fields:**

- `inbounds` — enable/disable each proxy server and set its port
- `outbounds` — define transport targets; `domain_front` requires `target_ip` + `front_sni`, `relay` additionally requires `script_ids`
- `routes` — ordered list mapping domain list files to outbound tags; first match wins
- `default_outbound` — final - fallback for unmatched domains

**Domain list format** (one rule per line):

```
# exact match
youtube.com

# suffix match (matches *.youtube.com)
.youtube.com

# keyword match (any domain containing "blogspot")
~blogspot
```

## Acknowledgements

- [MasterHttpRelayVPN](https://github.com/masterking32/MasterHttpRelayVPN/) 