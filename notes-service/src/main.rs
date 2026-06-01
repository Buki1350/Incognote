use incognote_notes::{
    app_state::AppState,
    build_router,
    db::{init_db, Db},
    services::{AuthClient, EncryptionService},
};
use std::io;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "notes-service=info,tower_http=info".to_string()),
        )
        .init();

    let db = Db::connect().await?;
    init_db(&db.pool).await?;

    let auth_client = AuthClient::from_env();
    let encryption = EncryptionService::from_env()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;

    let state = AppState::new(db, auth_client, encryption);
    let app = build_router(state);

    let port = std::env::var("PORT").or_else(|_| std::env::var("NOTES_PORT")).unwrap_or_else(|_| "3002".to_string());
    let addr = format!("0.0.0.0:{port}");
    tracing::info!(%addr, "notes service started");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
