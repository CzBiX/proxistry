# Proxistry

A pull-through Docker/OCI registry proxy. Single Rust crate, Axum + Tokio.

## Commands

```bash
# CI checks (what actually runs in GitHub Actions)
cargo fmt --check
cargo clippy --locked -- -D warnings
cargo test --locked

# Local lint (auto-fixes, differs from CI)
just lint          # runs clippy --fix + fmt

# Run
cargo run -- -c config.toml --log-level debug

# Version bump
just bump patch    # or minor/major; creates git commit + tag
```

`just lint` uses `--fix --allow-dirty` — always run the CI form before committing.

## Architecture

Single binary. Modules:

- `cache/` — filesystem blob/manifest cache with LRU eviction, inflight request dedup
- `proxy/` — upstream HTTP client, request handler, URL rewriting
- `registry/` — upstream auth (basic/token), path-based registry routing
- `middleware/` — request logging
- `server.rs` — Axum router assembly, background task spawning
- `config.rs` — TOML config deserialization

Entry point: `src/main.rs` → `server::build_router()` → Axum serve with graceful shutdown.

## Config

- `config.toml` is gitignored; copy from `config.example.toml`
- All fields optional with sensible defaults
- Listen default: `0.0.0.0:5000`
- Cache default dir: `./cache`, max 4GB, LRU eviction every 5 min

## Release Flow

Push a `v*` tag → CI builds linux-amd64, linux-arm64, darwin-arm64 binaries + multi-arch Docker image to GHCR. Use `just bump` to create the tag.

## Testing

No special fixtures or services required. Standard `cargo test`. Dev-dependency: `tempfile` for cache tests.
