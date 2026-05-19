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

## Psiphon + Akamai/Fastly CDN Fronting

mattlab replaces Xray in the [MITM-DomainFronting](https://github.com/patterniha/MITM-DomainFronting) approach for Psiphon. It requires a patched Psiphon client (see `PsiphonOverMITM/`) that uses mattlab as its upstream proxy.

### How it works

```
Psiphon (patched)
  │  upstream proxy: 127.0.0.1:10808
  ▼
mattlab HTTP/SOCKS5 proxy
  │  MITM: terminates client TLS, re-dials CDN with Chrome-83 uTLS
  │
  ├── ~akamai hostnames  ──► akamai-mitm ──► Akamai CDN edge ──► Psiphon meek server
  ├── Akamai IPs (9x)   ──► akamai-mitm ──► (same, via DNS fallback)
  ├── Fastly IPs        ──► fastly-mitm ──► Fastly CDN (pypi.org front) ──► Psiphon meek server
  └── everything else   ──► direct
```

Psiphon's `FrontedMeekDialOverrides` (injected by the patch) tells tunnel-core to use Chrome-83 TLS profile, per-IP SNI, and `http/1.1` ALPN for Akamai and `h2`+`http/1.1` for Fastly. mattlab matches this exactly.

### Handling blocked CDN IPs

Psiphon hardcodes 9 specific Akamai edge IPs. When these are TCP-blocked (common in Iran), mattlab tries CDN hostnames first (`a248.e.akamai.net`, `a.akamaized.net`) which DNS-resolve to locally-reachable Akamai edges. The meek `Host:` header inside the tunnel routes the request to Psiphon's origin regardless of which edge is used.

### Certificate setup

mattlab auto-generates a local CA on first run (stored in `.mattlab_ca/` next to the config). Install the CA on the device:

- **Windows/Android:** open `http://<host>:8080` in a browser — the cert server serves the CA cert and an iOS/Android profile for download.
- mattlab signs per-domain certs on the fly; no manual cert management needed.

### Recommended config for Psiphon use

```json
{
  "inbounds": {
    "http_proxy":  { "enabled": true, "port": 10808 },
    "socks5":      { "enabled": true, "port": 10809 },
    "cert_server": { "enabled": true, "port": 8080  }
  },
  "outbounds": [
    {
      "tag": "akamai-mitm",
      "type": "domain_front",
      "target_ips": [
        "a248.e.akamai.net",
        "a.akamaized.net",
        "23.215.0.206", "23.215.0.203",
        "23.212.250.91", "23.212.250.78",
        "23.12.147.13",  "23.12.147.29",
        "23.73.207.8",   "23.73.207.15",
        "92.123.102.43"
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
    { "tag": "direct", "type": "direct" }
  ],
  "routes": [
    { "domains": "domains/psiphon-akamai.txt",     "outbound": "akamai-mitm" },
    { "domains": "domains/psiphon-akamai-ips.txt", "outbound": "akamai-mitm" },
    { "geoip": "geoip.dat", "geocode": "FASTLY",   "outbound": "fastly-mitm" }
  ],
  "default_outbound": "direct"
}
```

Then set Psiphon's upstream proxy to `127.0.0.1:10808` (HTTP) or `127.0.0.1:10809` (SOCKS5).

### Domain lists

| File | Matches | Routes to |
|---|---|---|
| `domains/psiphon-akamai.txt` | any hostname containing `akamai` | `akamai-mitm` |
| `domains/psiphon-akamai-ips.txt` | the 9 specific Psiphon Akamai IPs | `akamai-mitm` |
| GeoIP `FASTLY` | Fastly IP ranges | `fastly-mitm` |

## Acknowledgements

- [MasterHttpRelayVPN](https://github.com/masterking32/MasterHttpRelayVPN/)
- [@patterniha](https://github.com/patterniha) — Xray domain fronting config reference
