# mattlab

A Go proxy that routes traffic through domain fronting and Google Apps Script relays to bypass DPI/SNI-based filtering.

## How It Works

```
Client
  │
  ├── :8080 ──► Cert Server
  │
  ├── :443  ──► SNI Proxy ──┐
  ├── :10808 ─► HTTP Proxy ─┤
  └── :10809 ─► SOCKS5 ─────┤
                             │
                  extract hostname
                             │
                             ▼
                          Router
                  (domain lists, IP lists, GeoIP)
                             │
                             ▼
                   Outbound Transport
                   ┌──────────────────┐
                   │ domain_front     │  MITM + CDN edge re-dial (uTLS)
                   │ sni_forward      │  raw TCP pass-through via CDN edge
                   │ relay            │  HTTP via Google Apps Script
                   │ direct           │  plain TCP
                   │ block            │  drop connection
                   └──────────────────┘
```

Traffic enters through one of the inbound servers (SNI proxy, HTTP CONNECT, SOCKS5, DNS). The router extracts the target hostname/IP and matches it against domain list files or GeoIP rules (first match wins, falls back to `default_outbound`). Matched traffic is sent through the corresponding outbound transport.

### Transports

- **domain_front** — Intercepts client-side TLS (MITM), then re-dials a CDN edge with a Chrome uTLS fingerprint. Tries multiple target addresses in order; if the address is a hostname, DNS resolution picks a local non-blocked edge. ALPN negotiated in the MITM phase is passed through to the CDN connection.
- **sni_forward** — Raw TCP tunnel through a CDN edge. No MITM, no certificate required on the client. The client's original TLS handshake (including SNI) passes through unchanged; the CDN routes it to the correct origin.
- **relay** — HTTP requests forwarded through Google Apps Script endpoints over a domain-fronted connection. Supports H1 pooling, H2 multiplexing, request batching, and response coalescing.
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

Config is a single JSON file. Domain lists and GeoIP files are referenced by relative path from the config file directory.

```json
{
  "listen_host": "0.0.0.0",
  "log_level": "info",

  "inbounds": {
    "sni_proxy":   { "enabled": false, "port": 443 },
    "http_proxy":  { "enabled": true,  "port": 10808 },
    "socks5":      { "enabled": true,  "port": 10809 },
    "cert_server": { "enabled": true,  "port": 8080 },
    "dns_server":  { "enabled": false, "port": 53 }
  },

  "outbounds": [
    {
      "tag": "akamai-mitm",
      "type": "domain_front",
      "target_ips": [
        "a248.e.akamai.net",
        "23.215.0.206"
      ],
      "target_port": 443,
      "front_sni": "",
      "fingerprint": "chrome"
    },
    {
      "tag": "fastly-mitm",
      "type": "domain_front",
      "target_ips": ["pypi.org"],
      "target_port": 443,
      "front_sni": "pypi.org",
      "fingerprint": "chrome"
    },
    {
      "tag": "cdn-forward",
      "type": "sni_forward",
      "front_addr": "92.123.102.43:443"
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
    { "domains": "domains/psiphon-akamai.txt",     "outbound": "akamai-mitm" },
    { "domains": "domains/psiphon-akamai-ips.txt", "outbound": "akamai-mitm" },
    { "geoip":   "geoip.dat", "geocode": "FASTLY", "outbound": "fastly-mitm" },
    { "domains": "domains/local.txt",              "outbound": "direct" }
  ],

  "default_outbound": "direct"
}
```

### Outbound fields

| Field | Type | Description |
|---|---|---|
| `tag` | string | Unique name referenced by routes |
| `type` | string | `domain_front`, `sni_forward`, `relay`, `direct`, `block` |
| `target_ips` | string[] | CDN edge addresses to try in order (hostnames DNS-resolved at dial time) |
| `target_ip` | string | Single CDN edge address (legacy; use `target_ips`) |
| `target_port` | int | CDN edge port (default 443) |
| `front_sni` | string | TLS SNI sent to CDN. Empty = use each target address as its own SNI |
| `fingerprint` | string | uTLS fingerprint: `chrome` (Chrome-83), `chrome120`, `chrome133`, `firefox`, `safari`, `edge`, `random` |
| `front_addr` | string | `host:port` of CDN edge for `sni_forward` |
| `script_ids` | string[] | Google Apps Script IDs for `relay` |

### Route fields

Routes are evaluated in order; first match wins.

| Field | Description |
|---|---|
| `domains` | Path to a domain list `.txt` file |
| `geoip` + `geocode` | Path to a GeoIP `.dat` file and the code to match (e.g. `"FASTLY"`) |
| `outbound` | Tag of the outbound to use |

### Domain list format

```
# exact match
youtube.com

# suffix match (matches *.youtube.com AND youtube.com)
.youtube.com

# keyword/contains match
~blogspot

# CIDR range (IPv4 or IPv6)
23.215.0.0/16

# exact IP
92.123.102.43
```

### DNS server

```json
"dns_server": {
  "enabled": true,
  "port": 53,
  "dot_port": 853,
  "mode": "sniproxy",
  "upstream_dns": "8.8.8.8:53"
}
```

Modes: `sniproxy` (resolve upstream, reply with the proxy IP for routed domains) or `doh` (DNS-over-HTTPS via a configured outbound).

## Psiphon + Akamai CDN Fronting

mattlab can act as a MITM proxy for [Psiphon](https://psiphon.ca/) clients modified to route through it (see `PsiphonOverMITM/`). It intercepts Psiphon's fronted-meek connections, re-dials Akamai CDN edges with a Chrome-83 uTLS fingerprint, and passes the negotiated ALPN through — matching what Psiphon's `FrontedMeekDialOverrides` expects.

When hardcoded Akamai IPs are TCP-blocked, mattlab falls back to CDN hostnames (e.g. `a248.e.akamai.net`) which DNS-resolve to locally-reachable edge IPs.

## Acknowledgements

- [MasterHttpRelayVPN](https://github.com/masterking32/MasterHttpRelayVPN/)
- [@patterniha](https://github.com/patterniha) — Xray domain fronting config reference
