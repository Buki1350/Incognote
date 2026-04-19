use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
};

use crate::{
    app::{AppError, AppState},
    models::{MessageResponse, VerifyEmailQuery},
};

pub async fn verify_email(
    State(state): State<AppState>,
    Query(payload): Query<VerifyEmailQuery>,
) -> Result<(StatusCode, Json<MessageResponse>), AppError> {
    let verified = state.services.user.verify_email(payload.token).await?;

    if !verified {
        return Err(AppError::Validation(
            "invalid or expired verification token".to_string(),
        ));
    }

    Ok((
        StatusCode::OK,
        Json(MessageResponse {
            message: "e-mail verified successfully".to_string(),
        }),
    ))
}
