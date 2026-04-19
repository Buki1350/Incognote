mod app;
mod db;
mod models;
mod routes;
mod services;

use crate::{
    app::build_app_state,
    routes::{
        google_auth_callback, google_auth_start, health, register, resend_verification,
        verify_email,
    },
};
use axum::{
    Router,
    routing::{get, post},
};
use std::net::SocketAddr;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init();

    let app_state = build_app_state().await?;

    let app = Router::new()
        .route("/health", get(health))
        .route("/register", post(register))
        .route("/verify-email", get(verify_email))
        .route("/resend-verification", post(resend_verification))
        .route("/auth/google/start", get(google_auth_start))
        .route("/auth/google/callback", get(google_auth_callback))
        .with_state(app_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    info!("Server listening on http://{addr}");
    info!(
        "Try: GET /health, POST /register, GET /verify-email, POST /resend-verification, GET /auth/google/start"
    );

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

fn init() {
    // `tracing_subscriber` transports `tracing::` messages to output.
    tracing_subscriber::fmt() // fmt() -> subscriber builder
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "rust_backend_template=debug,tower_http=debug".into()),
        )
        .init();
}
