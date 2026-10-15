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

Each proxied TCP flow currently opens a separate upstream TLS/H2 session. Session pooling, reconnect backoff, fingerprint tuning, HTTP/3, and UDP tunneling remain future work. There is no direct fallback when an intercepted connection fails. Wire compatibility does not imply Chromium fingerprint equivalence.

Tests use a custom Rama H2 peer with handwritten padding fixtures, a generated TLS certificate, and real Linux TPROXY in an isolated namespace. Interoperability with a deployed third-party NaiveProxy server has not yet been tested.
