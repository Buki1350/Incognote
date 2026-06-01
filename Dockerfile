FROM rust:1.88-bookworm AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY auth-service/Cargo.toml auth-service/Cargo.toml
COPY notes-service/Cargo.toml notes-service/Cargo.toml

# Create placeholder sources so dependencies compile
RUN mkdir -p auth-service/src/routes auth-service/src/services \
             notes-service/src/routes notes-service/src/services \
             database \
    && echo 'fn main() {}' > auth-service/src/main.rs \
    && echo 'pub mod routes; pub mod services;' > auth-service/src/lib.rs \
    && touch auth-service/src/app_state.rs \
    && touch auth-service/src/db.rs \
    && touch auth-service/src/models.rs \
    && touch auth-service/src/validation.rs \
    && touch auth-service/src/routes/mod.rs \
    && touch auth-service/src/services/mod.rs \
    && touch auth-service/src/services/geoip.rs \
    && touch auth-service/src/services/jwt.rs \
    && touch auth-service/src/services/password.rs \
    && touch auth-service/src/services/rate_limit.rs \
    && echo 'fn main() {}' > notes-service/src/main.rs \
    && echo 'pub mod routes; pub mod services;' > notes-service/src/lib.rs \
    && touch notes-service/src/app_state.rs \
    && touch notes-service/src/db.rs \
    && touch notes-service/src/models.rs \
    && touch notes-service/src/routes/mod.rs \
    && touch notes-service/src/services/mod.rs \
    && touch notes-service/src/services/auth_client.rs \
    && touch notes-service/src/services/encryption.rs

RUN cargo build --release 2>/dev/null; true

# Real source code
COPY auth-service/src auth-service/src
COPY notes-service/src notes-service/src
COPY database/schema.sql database/schema.sql

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
