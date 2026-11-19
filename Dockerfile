# Build flamejobd
FROM rust:1.97 AS build
WORKDIR /src
COPY . .
RUN cargo build --release --bin flamejobd

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/flamejobd /usr/local/bin/flamejobd
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/flamejobd"]
