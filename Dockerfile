FROM rust:1.94-slim AS builder

WORKDIR /app

# Cache dependencies by building a dummy project first
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && \
    cargo build --locked --release && rm -rf src target/release/deps/proxistry*

# Build the real project
COPY src ./src
RUN cargo build --locked --release

# Runtime stage
FROM gcr.io/distroless/cc-debian13:nonroot

COPY --from=builder /app/target/release/proxistry /
EXPOSE 5000

ENTRYPOINT ["./proxistry"]
CMD ["--config", "/etc/proxistry/config.toml"]
