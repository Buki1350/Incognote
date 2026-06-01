FROM rust:1.88-bookworm AS builder

WORKDIR /app

COPY . .

# build całego workspace (najbezpieczniej)
RUN cargo build --release


FROM nginx:1.27-bookworm

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# binarki Rust
COPY --from=builder /app/target/release/auth-service /usr/local/bin/auth-service
COPY --from=builder /app/target/release/notes-service /usr/local/bin/notes-service

# frontend
COPY frontend/ /usr/share/nginx/html/

# entrypoint
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 80

ENTRYPOINT ["docker-entrypoint.sh"]
