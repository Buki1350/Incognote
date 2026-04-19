use crate::app_state::AppState;
use axum::{extract::State, Json};

pub async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    let auth_available = state.auth_client.is_available().await;

    Json(serde_json::json!({
        "service": "notes-service",
        "status": if auth_available { "ok" } else { "degraded" },
        "auth_service_available": auth_available
    }))
}
