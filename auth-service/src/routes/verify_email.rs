use crate::{app_state::AppState, validation::validate_email};
use axum::{extract::State, http::StatusCode, Json};
use super::json_error;

pub async fn verify_email(
    State(state): State<AppState>,
    Json(payload): Json<crate::models::VerifyEmailRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let email = payload.email.trim().to_lowercase();
    let token = payload.token.trim();

    if let Err(message) = validate_email(&email) {
        return json_error(StatusCode::BAD_REQUEST, message);
    }
    if token.is_empty() || token.len() > 128 {
        return json_error(StatusCode::BAD_REQUEST, "Invalid verification token");
    }

    let updated = sqlx::query(
        r#"
        UPDATE users
        SET is_email_verified = TRUE,
            email_verification_token = NULL
        WHERE email = $1
          AND email_verification_token = $2
        "#,
    )
    .bind(&email)
    .bind(token)
    .execute(&state.db.pool)
    .await;

    match updated {
        Ok(result) if result.rows_affected() == 0 => json_error(
            StatusCode::BAD_REQUEST,
            "Invalid email or verification token",
        ),
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({ "message": "Email verified successfully" })),
        ),
        Err(error) => {
            tracing::error!(?error, %email, "email verification failed");
            json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
        }
    }
}
