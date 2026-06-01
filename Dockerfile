FROM rust:1.88-bookworm AS builder

WORKDIR /app

COPY . .

RUN cargo build --release -p incognote-auth
RUN cargo build --release -p incognote-notes

FROM nginx:1.27-alpine

RUN apk add --no-cache ca-certificates

COPY --from=builder /app/target/release/incognote-auth /usr/local/bin/auth-service
COPY --from=builder /app/target/release/incognote-notes /usr/local/bin/notes-service

COPY frontend/ /usr/share/nginx/html/
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 80

ENTRYPOINT ["docker-entrypoint.sh"]
