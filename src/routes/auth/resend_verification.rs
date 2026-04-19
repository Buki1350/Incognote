use axum::{Json, extract::State, http::StatusCode};

use crate::{
    app::{AppError, AppState},
    models::{MessageResponse, ResendVerificationRequest},
};

pub async fn resend_verification(
    State(state): State<AppState>,
    Json(payload): Json<ResendVerificationRequest>,
) -> Result<(StatusCode, Json<MessageResponse>), AppError> {
    state
        .services
        .user
        .resend_verification_email(payload.email)
        .await?;

    Ok((
        StatusCode::OK,
        Json(MessageResponse {
            message:
                "If this e-mail exists and is not verified, a new verification message was sent."
                    .to_string(),
        }),
    ))
}
