# AGENTS.md

## Cursor Cloud specific instructions

This is the **Matrix Rust SDK** -- a Rust workspace of libraries for building Matrix chat clients. It is a pure Rust project (no Node.js/Python required for core development).

### Key commands

- **Build** (default members only): `cargo build`
- **Lint**: `cargo clippy -- -D warnings` and `typos`
- **Test** (unit/integration without Synapse): `cargo nextest run --workspace --exclude matrix-sdk-integration-testing`
- **Full CI**: `cargo xtask ci` (requires `clippy`, `cargo-nextest`, `typos-cli`, `wasm-pack`)
- **Run examples**: `cargo run -p example-<name> -- <args>` (see `examples/README.md`)

### Caveats and non-obvious notes

- The workspace MSRV is `1.93`. Ensure `rustup default 1.93.0` (or newer) is active.
- `cargo-nextest` must be installed with `--locked` flag: `cargo install cargo-nextest --locked`.
- `libsqlite3-dev` (or equivalent) must be installed as a system dependency for linking. Alternatively, enable the `bundled` feature on `matrix-sdk-sqlite` to compile SQLite from source.
- Integration tests (`testing/matrix-sdk-integration-testing`) require a running Synapse instance. Start one via: `sudo docker compose -f testing/matrix-sdk-integration-testing/assets/docker-compose.yml up -d` (serves on port 8228). See `testing/matrix-sdk-integration-testing/README.md`.
- Docker in the Cloud Agent VM requires `sudo` and the fuse-overlayfs + iptables-legacy workarounds documented in the system prompt. The daemon must be started manually: `sudo dockerd &>/tmp/dockerd.log &`.
- The workspace uses `resolver = "3"` and edition 2024, so older Rust toolchains will not work.
- `matrix-sdk` has mutually exclusive TLS features (`native-tls` vs `rustls-tls`). The default is `rustls-tls`; do not enable both simultaneously.
- See `CONTRIBUTING.md` for test tooling, snapshot testing with `cargo-insta`, and CI details.
