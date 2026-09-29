# Development

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

The network tests additionally require user/network namespaces, `ip`, `nft`, and kernel TPROXY support:

```sh
bash scripts/test-netns.sh
```

The script compiles first and runs the ignored TPROXY tests in an isolated namespace without changing host networking. Ordinary tests cover padding, TLS/H2, routing, DNS, and explicit proxy inbounds.

## Configuration check

```sh
cargo run -- check --config examples/sometimes.toml
cargo build --release
```

The `check` command validates configuration and TLS client setup without opening network sockets. The example contains a placeholder hostname; a successful check does not imply that the upstream exists or that credentials are accepted.
