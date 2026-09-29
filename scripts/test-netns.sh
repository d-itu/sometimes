#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# Compile and fetch dependencies before removing external network access.
cargo test --lib --test tproxy --no-run
unshare --user --map-root-user --net bash -euo pipefail -c '
    ip link set lo up
    ip route add default dev lo src 127.0.0.1
    ip -6 route add default dev lo src ::1
    ip rule add priority 100 fwmark 0x5354 lookup 100
    ip route add local 0.0.0.0/0 dev lo table 100
    ip -6 rule add priority 100 fwmark 0x5354 lookup 100
    ip -6 route add local ::/0 dev lo table 100
    nft -f examples/tproxy.nft
    cargo test --offline --lib --test tproxy -- --ignored --test-threads=1
'
