# Project Overview

A local Linux proxy client with TPROXY, HTTP, and SOCKS5 inbounds, built with Rust and Rama 0.4.0.

```text
Local application -> TPROXY + sniff / HTTP / SOCKS5 -> routing
                                        |-> proxy: TLS/H2 CONNECT -> upstream -> destination
                                        |-> direct: destination
                                        `-> reject: protocol error or close
```

The NaiveProxy payload codec is independently implemented from the published protocol description. This project does not use the official NaiveProxy implementation, Chromium, or Cronet.

## Status

This is an initial working prototype, not a production release. It implements:

- IPv4/IPv6 transparent listeners and original TCP destination recovery.
- Bounded TLS SNI / HTTP/1 Host sniffing with byte-preserving replay.
- Ordered domain, domain suffix, destination CIDR, and port rules for proxy/direct/reject.
- Marked proxy and direct sockets, TLS certificate/hostname verification, SNI, and mandatory H2 ALPN.
- HTTP/2 CONNECT with Basic proxy authentication and padding negotiation.
- Independent transmit/receive padding, bounded per-flow buffers, backpressure, half-close, and idle deadlines.
- Rama HTTP/1 and cleartext HTTP/2 forward proxy and CONNECT inbounds, with per-request routing.
- Rama SOCKS5 no-auth CONNECT, including domain, IPv4, and IPv6 targets.
- Local UDP/TCP DNS service with upstream selection, global egress routing, bootstrap resolution, and an LRU cache.

Proxied TCP flows reuse upstream TLS/H2 sessions. A single internal pool policy limits live sessions to four, streams per session to 64, and pending CONNECT attempts to 128. The connection budget includes connections being established and draining sessions still held by active tunnels. A connection slot is released only after both the session owners and the underlying transport have been dropped. Inbound bridge tasks retain the tunnel's session and stream permit until the bridge finishes or is cancelled. Stream admission follows the peer's current H2 concurrency limit, including later increases and decreases; a zero limit pauses admission on that session. Requests waiting on upstream resolution, connection establishment, or a newly established session can use capacity released by another pooled session. If upstream resolution fails, the request checks for immediately available pooled stream capacity before returning the DNS error. Selecting an existing session cancels the pending establishment before sending CONNECT. Capacity changes and resource releases wake waiting requests without polling.

Tests use a custom Rama H2 peer with handwritten padding fixtures, a generated TLS certificate, and real Linux TPROXY in an isolated namespace. Interoperability with a deployed third-party NaiveProxy server has not yet been tested.
