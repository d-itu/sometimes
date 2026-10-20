# Development

For application setup and configuration validation, follow [quick start](overview.md#quick-start).
Run the commands below from the repository root.

## Build and check

Use Rust 1.96 or newer with Cargo, rustfmt, and Clippy. TOML checks require `tombi`.

```sh
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
tombi lint Cargo.toml examples/sometimes.toml
tombi format --check Cargo.toml examples/sometimes.toml
```

Ordinary tests cover padding, TLS/H2, routing, DNS, and explicit proxy inbounds.

## Network tests

The network tests additionally require user/network namespaces, `ip`, `nft`, and kernel TPROXY support:

```sh
bash scripts/test-netns.sh
```

The script runs the TPROXY tests in an isolated namespace without changing host networking.
Use this script instead of changing host networking for tests.
