use crate::{
    app_state::AppState,
    validation::{validate_email, validate_trusted_email_provider},
};
use axum::{extract::State, http::StatusCode, Json};
use super::{generate_verification_token, json_error};

pub async fn resend_verification(
    State(state): State<AppState>,
    Json(payload): Json<crate::models::ResendVerificationRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let email = payload.email.trim().to_lowercase();
    if let Err(message) = validate_email(&email) {
        return json_error(StatusCode::BAD_REQUEST, message);
    }
    if let Err(message) = validate_trusted_email_provider(&email) {
        return json_error(StatusCode::BAD_REQUEST, &message);
    }

    let token = generate_verification_token();
    let updated = sqlx::query(
        r#"
        UPDATE users
        SET email_verification_token = $1
        WHERE email = $2
          AND is_email_verified = FALSE
        "#,
    )
    .bind(&token)
    .bind(&email)
    .execute(&state.db.pool)
    .await;

    match updated {
        Ok(result) if result.rows_affected() == 0 => json_error(
            StatusCode::NOT_FOUND,
            "Unverified user with this email not found",
        ),
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "message": "Verification token refreshed",
                "verification_token": token
            })),
        ),
        Err(error) => {
            tracing::error!(?error, %email, "resend verification failed");
            json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
        }
    }
}
