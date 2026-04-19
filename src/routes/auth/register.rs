use axum::{Json, extract::State, http::StatusCode};

use crate::{
    app::{AppError, AppState},
    models::{RegisterRequest, RegisterResponse},
};

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), AppError> {
    let user = state.services.user.register(payload).await?;
    Ok((StatusCode::CREATED, Json(user)))
}
