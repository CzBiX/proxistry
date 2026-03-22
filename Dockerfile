FROM rust:1.94-bookworm AS builder

WORKDIR /app

# Cache dependencies by building a dummy project first
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && \
    cargo build --locked --release && rm -rf src target/release/deps/proxistry*

# Build the real project
COPY src ./src
RUN cargo build --locked --release

# Runtime stage
FROM gcr.io/distroless/cc-debian13

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash proxistry

COPY --from=builder /app/target/release/proxistry /usr/local/bin/proxistry

RUN mkdir -p /var/lib/proxistry/cache && chown -R proxistry:proxistry /var/lib/proxistry

USER proxistry

EXPOSE 8000

ENTRYPOINT ["proxistry"]
CMD ["--config", "/etc/proxistry/config.toml"]
