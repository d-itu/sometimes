# Deployment

This project does not install firewall, nftables, or policy-routing rules automatically. Review `examples/tproxy.nft` before applying it.

The main template intercepts public-destination TCP traffic from the host. When DNS is enabled, the separate `examples/dns-redirect.nft` template redirects local UDP/TCP port 53 to port 1053. Do not load that template while DNS is disabled. UDP, including QUIC, otherwise follows its existing route. Applications using QUIC are not transparently proxied by this prototype.

## Fixed values in the example

| Setting | Value |
| --- | --- |
| Listener port | 12345 |
| Outbound bypass mark | `0x534f` / 21327 |
| Interception mark | `0x5354` |
| Policy route table | 100 |
| Policy rule priority | 100 |
| nftables tables | `inet sometimes`; optional `inet sometimes_dns` |

Choose unused marks, table numbers, and priorities if these conflict with an existing setup. The top-level `outbound_mark` and nftables bypass mark must match. Both address-family listeners are required by the example rules.

## Privileges

With TPROXY, the process needs permission to set `IP_TRANSPARENT`, `IPV6_TRANSPARENT`, and `SO_MARK` (`CAP_NET_ADMIN`). A standalone HTTP/SOCKS proxy without `outbound_mark` does not require that capability. When interception rules exist, keep the mark enabled even if only explicit proxy listeners are configured. Run the TPROXY service under a dedicated unprivileged account with access to the credential-bearing configuration, rather than as root. For example, after creating the account and installing the binary and configuration in locations accessible to it, use a systemd service with:

```ini
[Service]
User=sometimes
Group=sometimes
ExecStart=/usr/local/bin/sometimes run --config /etc/sometimes/sometimes.toml
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=true
```

Keep the configuration readable only by this account; review any additional systemd sandbox settings against DNS resolution and networking needs.

## Install rules

Install policy routes before the nftables table:

```sh
sudo ip rule add priority 100 fwmark 0x5354 lookup 100
sudo ip route add local 0.0.0.0/0 dev lo table 100
sudo ip -6 rule add priority 100 fwmark 0x5354 lookup 100
sudo ip -6 route add local ::/0 dev lo table 100
sudo nft -f examples/tproxy.nft
# Only when [dns].enabled = true and the DNS service is running:
sudo nft -f examples/dns-redirect.nft
```

Existing firewall rules must also allow diverted traffic. Start with a controlled test environment; the supplied table assumes it owns these marks and is loaded once.

## Remove rules

Remove interception before stopping the process:

```sh
sudo nft delete table inet sometimes_dns # only if the optional DNS table was installed
sudo nft delete table inet sometimes
sudo ip rule del priority 100 fwmark 0x5354 lookup 100
sudo ip route del local 0.0.0.0/0 dev lo table 100
sudo ip -6 rule del priority 100 fwmark 0x5354 lookup 100
sudo ip -6 route del local ::/0 table 100
```

These commands remove only the entries introduced above. SIGINT/SIGTERM stops accepting new connections and allows active flows up to ten seconds to finish.

## Scope

The initial deployment targets traffic originating on the local Linux host. Gateway interception, server-side NaiveProxy listeners, transparent source-address egress, HTTP/3, and arbitrary UDP forwarding are outside the current architecture. Do not modify host networking during tests; use `scripts/test-netns.sh` instead.
