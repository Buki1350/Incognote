FROM rust:1.88-bookworm AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY auth-service/Cargo.toml auth-service/
COPY notes-service/Cargo.toml notes-service/

RUN mkdir -p auth-service/src notes-service/src \
    && echo 'fn main() {}' > auth-service/src/main.rs \
    && echo 'fn main() {}' > notes-service/src/main.rs \
    && mkdir -p auth-service/src/routes auth-service/src/services notes-service/src/routes notes-service/src/services \
    && echo '' > auth-service/src/lib.rs \
    && echo '' > notes-service/src/lib.rs \
    && cargo build --release 2>/dev/null; true

COPY . .

RUN cargo build --release

FROM nginx:1.27-alpine

RUN apk add --no-cache ca-certificates

COPY --from=builder /app/target/release/auth-service /usr/local/bin/auth-service
COPY --from=builder /app/target/release/notes-service /usr/local/bin/notes-service

COPY frontend/ /usr/share/nginx/html/

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 80

ENTRYPOINT ["docker-entrypoint.sh"]
