use axum::{Json, extract::State, http::StatusCode};

use crate::{
    app::{AppError, AppState},
    models::{ResetPasswordRequest, MessageResponse},
};

pub async fn reset_password(
    State(state): State<AppState>,
    Json(payload): Json<ResetPasswordRequest>,
) -> Result<(StatusCode, Json<MessageResponse>), AppError> {
    state.services.user.reset_password(payload).await?;
    Ok((StatusCode::OK, Json(MessageResponse {
        message: "Password has been reset successfully".to_string(),
    })))
}