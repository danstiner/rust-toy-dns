# Leveraging the pre-built Docker images with 
# cargo-chef and the Rust toolchain
FROM lukemathwalker/cargo-chef:latest-rust-1.59.0 AS chef
WORKDIR /app


FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json


FROM chef AS builder 
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release --bin rust-dns


FROM debian:bullseye-slim AS runtime
WORKDIR /app
COPY --from=builder /app/target/release/rust-dns /usr/local/bin
EXPOSE 53/udp
CMD ["/usr/local/bin/rust-dns", "0.0.0.0:53"]
