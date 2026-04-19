//! Auth service executable.

use incognote_auth::{
    app_state::AppState,
    build_router,
    db::{init_db, Db},
    services::{
        validate_email, validate_password_strength, validate_username, GeoIpService, JwtService,
        PasswordService, RateLimiter,
    },
};
use std::io;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "auth-service=info,tower_http=info".to_string()),
        )
        .init();

    let db = Db::connect().await?;
    init_db(&db.pool).await?;

    seed_admin_if_configured(&db.pool).await?;

    let jwt = JwtService::from_env()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let geoip = GeoIpService::new();
    let limiter = RateLimiter::secure_defaults();

    let state = AppState::new(db, jwt, geoip, limiter);
    let app = build_router(state);

    let addr = "0.0.0.0:3001";
    tracing::info!(%addr, "auth service started");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn seed_admin_if_configured(
    pool: &sqlx::Pool<sqlx::Postgres>,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(admin_username_raw) = std::env::var("ADMIN_USERNAME").ok() else {
        return Ok(());
    };
    let Some(admin_password) = std::env::var("ADMIN_PASSWORD").ok() else {
        tracing::warn!("ADMIN_USERNAME set without ADMIN_PASSWORD; admin bootstrap skipped");
        return Ok(());
    };

    let admin_username = admin_username_raw.trim().to_lowercase();
    let admin_email = std::env::var("ADMIN_EMAIL")
        .ok()
        .map(|value| value.trim().to_lowercase())
        .unwrap_or_else(|| format!("{admin_username}@incognote.local"));
    validate_username(&admin_username)
        .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message.to_string()))?;
    validate_email(&admin_email)
        .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message.to_string()))?;
    validate_password_strength(&admin_password)
        .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))?;

    let password_hash = PasswordService::hash_password(&admin_password)
        .map_err(|message| io::Error::new(io::ErrorKind::Other, message))?;

    sqlx::query(
        r#"
        INSERT INTO users (username, email, password_hash, is_email_verified, email_verification_token, role)
        VALUES ($1, $2, $3, TRUE, NULL, 'admin')
        ON CONFLICT (username)
        DO UPDATE SET
            email = EXCLUDED.email,
            password_hash = EXCLUDED.password_hash,
            is_email_verified = TRUE,
            email_verification_token = NULL,
            role = 'admin'
        "#,
    )
    .bind(&admin_username)
    .bind(&admin_email)
    .bind(&password_hash)
    .execute(pool)
    .await?;

    tracing::info!(%admin_username, %admin_email, "admin account ensured from environment");

    Ok(())
}
