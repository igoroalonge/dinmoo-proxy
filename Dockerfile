FROM rust:1.97.1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN useradd --system --home /var/lib/dinmoo-proxy --create-home --shell /usr/sbin/nologin dinmoo-proxy
COPY --from=build /src/target/release/dinmoo-proxy /usr/local/bin/dinmoo-proxy
USER dinmoo-proxy
EXPOSE 8443/tcp
ENTRYPOINT ["/usr/local/bin/dinmoo-proxy", "gateway", "0.0.0.0:8443"]
