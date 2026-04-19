FROM rust:latest AS builder

WORKDIR /app

COPY Cargo.toml ./
COPY src ./src

RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --uid 10001 appuser

COPY --from=builder /app/target/release/notes-service /usr/local/bin/notes-service

USER appuser
EXPOSE 3002
CMD ["notes-service"]
