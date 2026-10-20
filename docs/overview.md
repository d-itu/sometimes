# Project Overview

A local Linux proxy client with TPROXY, HTTP, and SOCKS5 inbounds.

```text
Local application -> TPROXY + sniff / HTTP / SOCKS5 -> routing
                                        |-> proxy: TLS/H2 CONNECT -> upstream -> destination
                                        |-> direct: destination
                                        `-> reject: protocol error or close
```

## Status

This is an initial working prototype, not a production release. It implements:

- IPv4/IPv6 transparent TCP listeners.
- TLS SNI / HTTP/1 Host sniffing for routing.
- Ordered domain, domain suffix, destination CIDR, and port rules for proxy/direct/reject.
- Outbound bypass marks, TLS certificate/hostname verification, SNI, and mandatory H2 ALPN.
- HTTP/2 CONNECT with Basic proxy authentication and padding negotiation.
- Half-close and idle deadlines for tunnels.
- HTTP/1 and cleartext HTTP/2 forward proxy and CONNECT inbounds, with per-request routing.
- SOCKS5 no-auth CONNECT, including domain, IPv4, and IPv6 targets.
- Local UDP/TCP DNS service with upstream selection, egress routing, bootstrap resolution, and response caching.

Interoperability with a deployed third-party NaiveProxy server has not yet been tested.

## Compatibility and limits

The client supports the published NaiveProxy protocol. Compatibility does not imply a Chromium-equivalent fingerprint
or censorship resistance.

TPROXY supplies the destination IP and port, but not the original hostname. TLS SNI and HTTP `Host` can inform routing;
they are not authenticated identities. Encrypted names and unsupported protocols cannot provide a routing hostname.

Transparent interception supports TCP. QUIC, arbitrary UDP forwarding, transparent HTTP/2 header sniffing,
TLS decryption, and Fake-IP are unsupported. Gateway interception, server-side NaiveProxy listeners,
transparent source-address egress, and HTTP/3 are also unsupported.

See [explicit proxy listeners](configuration.md#explicit-proxy-listeners) for supported HTTP and SOCKS request types
and [upstream configuration](configuration.md#upstream) for NaiveProxy server requirements.

## Quick start

On Linux, install Rust 1.96 or newer with Cargo. Run these commands from the repository root:

```sh
cargo build --release
cp examples/sometimes.toml sometimes.toml
chmod 600 sometimes.toml
```

Edit `sometimes.toml`: set `upstream.host`, `upstream.username`, and `upstream.password` for your NaiveProxy server.
For this standalone setup, remove the top-level `outbound_mark` and replace the example's entire `[[listeners]]` block
with these loopback listeners. Keep `[dns].enabled = false`.

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

This setup requires no TPROXY privileges or firewall changes. If interception rules already exist on the host,
follow [deployment](deployment.md) and keep the matching [outbound mark](configuration.md#outbound-mark).

Validate the configuration, then start the proxy:

```sh
./target/release/sometimes check --config sometimes.toml
./target/release/sometimes run --config sometimes.toml
```

The `check` command validates configuration and TLS client setup without opening network sockets.
A successful check does not verify upstream availability or credentials.

In another terminal, use either listener:

```sh
curl --proxy http://127.0.0.1:8080 https://example.com
curl --proxy socks5h://127.0.0.1:1080 https://example.com
```

Press Ctrl-C to stop. For transparent interception or persistent service operation, continue with
[deployment](deployment.md).

## References

- [NaiveProxy padding specification][padding-spec]
- [Linux kernel TPROXY documentation](https://docs.kernel.org/networking/tproxy.html)

[padding-spec]: https://github.com/klzgrad/naiveproxy#padding-protocol-an-informal-specification
