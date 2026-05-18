use axum::{Json, extract::State, http::StatusCode};

use crate::{
    app::{AppError, AppState},
    models::{ForgotPasswordRequest, MessageResponse},
};

pub async fn forgot_password(
    State(state): State<AppState>,
    Json(payload): Json<ForgotPasswordRequest>,
) -> Result<(StatusCode, Json<MessageResponse>), AppError> {
    state.services.user.forgot_password(payload).await?;
    Ok((StatusCode::OK, Json(MessageResponse {
        message: "If the email exists, a password reset link has been sent".to_string(),
    })))
}