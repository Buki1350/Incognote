use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
};

use crate::{
    app::{AppError, AppState},
    models::{AuthResponse, GoogleAuthCallbackQuery},
};

pub async fn google_auth_callback(
    State(state): State<AppState>,
    Query(payload): Query<GoogleAuthCallbackQuery>,
) -> Result<(StatusCode, Json<AuthResponse>), AppError> {
    let response = state
        .services
        .user
        .complete_google_oauth(payload.code, payload.state)
        .await?;

    Ok((StatusCode::OK, Json(response)))
}
