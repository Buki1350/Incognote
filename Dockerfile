FROM rust:1.88-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY auth-service/Cargo.toml notes-service/Cargo.toml ./

# dummy main to cache dependencies separately from source changes
RUN mkdir -p auth-service/src notes-service/src \
    && echo "fn main() {}" > auth-service/src/main.rs \
    && echo "fn main() {}" > notes-service/src/main.rs \
    && cargo build --release -p incognote-auth -p incognote-notes 2>&1

COPY auth-service/src ./auth-service/src
COPY notes-service/src ./notes-service/src

RUN cargo build --release -p incognote-auth -p incognote-notes

FROM nginx:1.27-alpine

RUN apk add --no-cache ca-certificates

COPY --from=builder /app/target/release/auth-service /usr/local/bin/auth-service
COPY --from=builder /app/target/release/notes-service /usr/local/bin/notes-service

COPY frontend/ /usr/share/nginx/html/
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 80

ENTRYPOINT ["docker-entrypoint.sh"]
