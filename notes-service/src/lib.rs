pub mod app_state;
pub mod db;
pub mod models;
pub mod routes;
pub mod services;

use app_state::AppState;
use axum::{
    http::{header, Method},
    routing::{delete, get, post, put},
    Router,
};
use tower_http::{cors::CorsLayer, trace::TraceLayer};

pub fn build_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin([
            "http://localhost:8080".parse().expect("valid origin"),
            "http://127.0.0.1:8080".parse().expect("valid origin"),
        ])
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION]);

    Router::new()
        .route("/health", get(routes::health::health))
        .route("/notes", get(routes::notes::list_notes))
        .route("/notes", post(routes::notes::create_note))
        .route("/notes/{id}", get(routes::notes::get_note))
        .route("/notes/{id}", put(routes::notes::update_note))
        .route("/notes/{id}", delete(routes::notes::delete_note))
        .route("/notes/share", post(routes::notes::share_note))
        .route("/friends", get(routes::friends::list_friends))
        .route("/friends", post(routes::friends::add_friend))
        .route("/friends/invites", get(routes::friends::list_friend_invites))
        .route(
            "/friends/invites/{request_id}/accept",
            post(routes::friends::accept_friend_invite),
        )
        .route(
            "/friends/invites/{request_id}/reject",
            post(routes::friends::reject_friend_invite),
        )
        .route("/messages", get(routes::messages::list_messages))
        .route("/messages", post(routes::messages::send_message))
        .route("/messages/{id}", delete(routes::messages::delete_message))
        .route("/admin/users", get(routes::admin::list_all_users))
        .route("/admin/users/{user_id}", delete(routes::admin::delete_user))
        .route("/admin/users/{user_id}/notes", get(routes::admin::list_user_notes))
        .route("/admin/notes", get(routes::admin::list_all_notes))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}
