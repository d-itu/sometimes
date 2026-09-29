# Roadmap

The current prototype is described in [overview](overview.md). Remaining work and possible extensions:

- Pool authenticated H2 sessions with stream limits, bounded pending requests, GOAWAY draining, and reconnect backoff.
- Fuzz the codec and measure concurrency, memory use, throughput, and latency.
- Test wire interoperability against a pinned, independently implemented server with NaiveProxy padding support; verify its provenance and protocol capabilities first. Browser fingerprint similarity needs separate evaluation.
- Add TLS listener termination, HTTP/1 h2c Upgrade, extended CONNECT, WebSocket Upgrade, and optional SOCKS authentication/BIND/UDP ASSOCIATE.
- Extend DNS with DoT/DoH, response re-routing, DNSSEC, and encrypted DNS interception.
- Add UID/cgroup-based routing, HTTP/3, and UDP forwarding only with explicit designs for interception and transport.

See [protocol and architecture](protocol.md) for protocol constraints and [deployment](deployment.md) for the current interception scope.
