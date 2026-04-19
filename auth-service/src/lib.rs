//! Auth Service library for Incognote.
//! This crate keeps auth logic modular so handlers can stay compact.

pub mod app_state;
pub mod db;
pub mod models;
pub mod routes;
pub mod services;

use app_state::AppState;
use axum::{
    http::{header, Method},
    routing::{get, post, put},
    Router,
};
use tower_http::{cors::CorsLayer, trace::TraceLayer};

/// Build the HTTP router for the auth service.
pub fn build_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin([
            "http://localhost:8080".parse().expect("valid origin"),
            "http://127.0.0.1:8080".parse().expect("valid origin"),
        ])
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION]);

    Router::new()
        .route("/health", get(routes::health::health))
        .route("/register", post(routes::auth::register))
        .route("/login", post(routes::auth::login))
        .route("/verify-email", post(routes::auth::verify_email))
        .route(
            "/resend-verification",
            post(routes::auth::resend_verification),
        )
        .route("/validate-token", post(routes::auth::validate_token))
        .route("/roles/{user_id}", put(routes::auth::update_role))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}
