pub mod app_state;
pub mod db;
pub mod models;
pub mod routes;
pub mod services;
pub mod validation;

use app_state::AppState;
use axum::{
    http::{header, Method},
    routing::{get, post, put},
    Router,
};
use tower_http::{cors::CorsLayer, trace::TraceLayer};

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
        .route("/register", post(routes::register::register))
        .route("/login", post(routes::login::login))
        .route("/verify-email", post(routes::verify_email::verify_email))
        .route(
            "/resend-verification",
            post(routes::resend_verification::resend_verification),
        )
        .route("/validate-token", post(routes::validate_token::validate_token))
        .route("/roles/{user_id}", put(routes::update_role::update_role))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}
