# Protocol and Architecture

## Modules

Protocol inbounds, routing, DNS, and transport are separated into:

```text
src/
  main.rs
  lib.rs
  config.rs
  inbound.rs
  linux.rs
  outbound.rs
  routing.rs
  sniff.rs
  dns.rs
  dns/
    bootstrap.rs
    cache.rs
    packet.rs
  relay.rs
  naive/
    mod.rs
    padding.rs
    client.rs
```

`naive/client.rs` owns upstream sessions and CONNECT streams. `linux.rs` manages listeners, original destinations, and process shutdown. `inbound.rs` uses Rama services for HTTP and SOCKS5 with a shared egress adapter. `dns.rs` owns DNS listeners, rules, and upstream transport; `dns/bootstrap.rs` resolves named upstreams, `dns/packet.rs` validates wire packets, and `dns/cache.rs` manages TTL-based response caching.

## Protocol constraints

- TPROXY recovers the destination IP and port, not the original hostname. TLS SNI and HTTP `Host` are routing hints, not authenticated identities.
- NaiveProxy CONNECT carries TCP byte streams, not arbitrary UDP. Do not use Fake-IP or silently fall back to direct egress on proxy failure.
- Keep interception and outbound bypass marks distinct. Check protocol limits at the untrusted network boundary.
- The payload codec must remain independent of the official NaiveProxy implementation, Chromium, and Cronet. Wire compatibility does not imply a Chromium-equivalent fingerprint or censorship resistance.

## Rama integration

Rama provides TLS and HTTP/2 for the Naive outbound. Its automatic HTTP server handles HTTP/1 and cleartext HTTP/2 prior knowledge. Every request routes independently; ordinary HTTP streams through a Rama HTTP/1 client, while CONNECT uses upgrades. Rama's SOCKS5 acceptor handles no-auth CONNECT with custom connection and relay services. Padding remains independent of HTTP frame boundaries.

`PrefixedIo` replaces custom sniff replay. TLS record reassembly remains local because Rama 0.4.0's prefix parser does not reassemble multiple records.

## NaiveProxy implementation

The implementation uses the published informal padding specification as protocol evidence and maintains independent transmit and receive counters.

- Negotiate padding with the CONNECT request/response `padding` header.
- The first eight padding records in each direction contain a two-byte big-endian payload length, one padding-length byte, payload, and padding bytes; subsequent data is raw.
- Split payloads exceeding 65,535 bytes while padding is active.
- Parse incrementally across arbitrary transport reads and H2 DATA boundaries.
- Handle empty payload records, partial writes, backpressure, premature EOF, reset, and truncated records without corrupting stream state.
- Treat H2 frame padding and reset behavior separately from the payload codec.
- Disable Fast Open initially: wait for a successful CONNECT response and padding negotiation before sending tunnel payload.
- Implement HTTP/2 CONNECT authority semantics, proxy authentication, status/error mapping, and half-close behavior.

## References

- [NaiveProxy padding specification](https://github.com/klzgrad/naiveproxy#padding-protocol-an-informal-specification) (documentation only)
- [Rama overview](https://ramaproxy.org/)
- [Rama transparent proxy guide](https://ramaproxy.org/book/proxies/transparent.html)
- [Rama Linux TCP TPROXY example](https://github.com/plabayo/rama/blob/main/examples/src/linux_tproxy_tcp.rs)
- [Rama CONNECT proxy example](https://github.com/plabayo/rama/blob/main/examples/src/http_connect_proxy.rs)
- [Linux kernel TPROXY documentation](https://docs.kernel.org/networking/tproxy.html)
