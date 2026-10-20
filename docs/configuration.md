# Configuration

See [quick start](overview.md#quick-start) for a complete standalone setup and
[deployment](deployment.md) for transparent interception.

Copy `examples/sometimes.toml` to `sometimes.toml`, replace the upstream host and credentials, and restrict access to that file.
The program never prints the parsed configuration. `RUST_LOG=debug` enables detailed diagnostics.

## Upstream

The upstream must support TLS with HTTP/2 ALPN, HTTP/2 CONNECT, and Basic proxy authentication.
Set `upstream.username` and `upstream.password` to the server credentials. Certificate and hostname verification are required.

`upstream.host` accepts a hostname or IP without a port. IPv6 uses the unbracketed form, such as `2001:db8::1`.
`upstream.port` defaults to `443` and can be overridden with a nonzero port, such as `8443`.

The hostname is used for TLS SNI and certificate verification by default. `server_name` overrides it when connecting to
a fixed IP. The upstream hostname is resolved through the configured bootstrap DNS servers. Resolved addresses are
retried on connection failure. The configured connection deadline bounds the entire operation, including capacity waits,
DNS resolution, TCP, TLS, CONNECT, and retries. Set this deadline with the top-level `connect_timeout_secs` (default 15).

Padding is required by default. Set `require_padding = false` only to deliberately permit a standard H2 CONNECT proxy
that does not advertise padding.

Tunnel payload is sent only after CONNECT succeeds and padding negotiation completes. TCP half-close is supported.
Tunnel payload is not replayed, and failed proxy connections never fall back to direct egress.
The top-level `idle_timeout_secs` (default 300) sets the tunnel idle deadline.

## Outbound mark

The optional **top-level** `outbound_mark = 21327` applies to all outbound TCP sockets (NaiveProxy and direct)
and direct DNS UDP sockets. When omitted, these sockets do not set `SO_MARK`, so a standalone HTTP/SOCKS proxy needs
no capability to mark sockets. A TPROXY listener requires a nonzero `outbound_mark`.
The configured value must match the bypass mark in the nftables rules; setting it requires `CAP_NET_ADMIN`
(or the appropriate socket-mark capability on supported kernels).

Do not omit the mark while host-level interception rules can capture the client's outbound traffic,
even if all configured listeners are HTTP or SOCKS. Set it when loading `examples/dns-redirect.nft` so direct DNS upstream
and bootstrap queries bypass the redirect. The program cannot detect external firewall rules.

## Explicit proxy listeners

Listeners use separate `host`, `port`, and `protocol` fields. `host` is a local IP address.

```toml
[[listeners]]
host = "127.0.0.1"
port = 8080
protocol = "http"

[[listeners]]
host = "127.0.0.1"
port = 1080
protocol = "socks"
```

| Inbound | Supported behavior |
| --- | --- |
| HTTP/1 | Absolute `http://` targets, streaming bodies, chunked uploads, `100 Continue`, CONNECT, cross-destination keep-alive |
| HTTP/2 | Cleartext prior knowledge (h2c), concurrent independently routed requests, and ordinary CONNECT |
| SOCKS5 | No-auth TCP CONNECT with domain, IPv4, or IPv6 targets |

HTTP requests are forwarded to origins as HTTP/1.1 with origin-form targets; the target authority supplies `Host`.
Hop-by-hop headers and proxy credentials are removed.

`max_connections` bounds simultaneous inbound connections and, independently, active explicit outbound requests;
each has its own budget of this size. HTTP/2 accepts at most 32 simultaneous streams per client connection.
If the egress budget is full, HTTP requests receive 503. Domain-only reject rules can run before DNS resolution;
earlier IP-dependent rules still require resolution to preserve rule order.

TLS listener termination, HTTP/1 h2c Upgrade negotiation, extended CONNECT, WebSocket Upgrade, SOCKS authentication,
BIND, and UDP ASSOCIATE are not enabled.

HTTP returns 400 for unsupported request targets, 403 for rejected routes, 502 for connection failures,
and 504 for connection or response-header deadlines. CONNECT and SOCKS relays have bidirectional idle deadlines;
ordinary HTTP does not impose a separate deadline on response-body streaming.

These listeners are unauthenticated. Bind them to loopback or a trusted interface.

## DNS

For HTTP/SOCKS listeners, a domain whose routing decision is definitively `proxy` is passed to the NaiveProxy server
for remote resolution; the client does not resolve it locally. `direct` routes and rules requiring a target IP still
use the system resolver. The Naive upstream hostname is resolved with the configured bootstrap DNS servers through
marked direct sockets; it does not use the system resolver.

Where DNS leakage matters for other local lookups, configure an appropriate system DNS policy or enable the local DNS
service with `examples/dns-redirect.nft` and route its upstream through the proxy. The template redirects local UDP/TCP
port 53 to the DNS listener on port 1053; marked upstream sockets bypass it. Keep DNS disabled unless the listener
address and redirect rules agree. Custom DoH/DoT resolvers remain outside this service.

DNS request rules choose an upstream; then the upstream hostname/IP and port are evaluated by `routing.rules`.
A `proxy` result uses NaiveProxy with TCP DNS, while `direct` uses a socket marked with `outbound_mark` when configured.
A named upstream definitively routed to `proxy` is resolved by the remote server, without local bootstrap.
`bootstrap` lookups for direct routes or IP-dependent rules still use direct sockets marked with `outbound_mark`
when configured. UDP DNS cannot use NaiveProxy; a `tcp+udp` upstream uses TCP when routing selects `proxy`.

`dns.max_tcp_connections` limits concurrent TCP DNS clients per listening address (default 64), separately from the proxy's
`max_connections`. Once full, the listener waits for a connection to finish before accepting another.
`dns.tcp_idle_timeout_secs` (default 30) bounds stalled client reads and writes; active upstream queries use `dns.timeout_ms`.
Positive DNS responses are cached until the shortest resource-record TTL expires; TTLs in cached replies decrease with time.
Truncated responses, errors, and zero-TTL records are not cached. Negative answers are not cached.
Named DNS upstream addresses are also cached up to their shortest response TTL.

## Sniffing and routing

Sniffing is enabled by default, with a total deadline of 500 ms and a 16 KiB read limit.
Configure `[sniff]` with `enabled`, `timeout_ms`, and `max_bytes` (1..=65536).
EOF, malformed or unknown protocols, incomplete headers, byte limits, and timeouts produce no domain
without changing the forwarded data. Socket I/O errors fail the flow.

TLS ClientHello SNI supports TCP and TLS record fragmentation. HTTP/1 `Host` is case-insensitive,
optional ports are removed, domains are lowercased, and one trailing dot is removed.
Duplicate `Host` fields are not used for routing. ECH's encrypted inner name cannot be inspected.
See [compatibility and limits](overview.md#compatibility-and-limits) for unsupported protocols and features.

```toml
[routing]
default = "proxy"

[[routing.rules]]
domain = ["blocked.example"]
action = "reject"

[[routing.rules]]
domain_suffix = ["example.com"]
ports = [443, 8443]
action = "direct"

[[routing.rules]]
ip_cidr = ["203.0.113.0/24", "2001:db8::/32"]
action = "proxy"
```

Rules use the first match, otherwise `routing.default` (default `proxy`). Different condition types are ANDed;
entries in each list are ORed. Empty lists impose no constraint. A rule must have at least one nonempty condition.
`domain` is exact; `domain_suffix` matches that name and its subdomains, not `notexample.com`.
Wildcards are unsupported. With no sniffed domain, domain conditions do not match; IP and port conditions still apply.

`proxy` uses the configured NaiveProxy upstream; `direct` connects to the target IP and port;
`reject` closes the flow without an outbound connection. Both proxy and direct sockets use the optional top-level
`outbound_mark`. Sniffing does not replace the target with a hostname and performs no additional DNS queries.
