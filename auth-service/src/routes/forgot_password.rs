use crate::{
    app_state::AppState,
    validation::{validate_email, validate_trusted_email_provider},
};
use axum::{extract::State, http::StatusCode, Json};
use super::{generate_verification_token, json_error};
use chrono::{Duration, Utc};

pub async fn forgot_password(
    State(state): State<AppState>,
    Json(payload): Json<crate::models::ForgotPasswordRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let email = payload.email.trim().to_lowercase();

    if let Err(message) = validate_email(&email) {
        return json_error(StatusCode::BAD_REQUEST, message);
    }
    if let Err(message) = validate_trusted_email_provider(&email) {
        return json_error(StatusCode::BAD_REQUEST, &message);
    }

    let user = sqlx::query_as::<_, (i64, String, bool)>(
        r#"
        SELECT id, username, is_email_verified
        FROM users
        WHERE email = $1
        "#,
    )
    .bind(&email)
    .fetch_optional(&state.db.pool)
    .await;

    let user = match user {
        Ok(Some(u)) => u,
        Ok(None) => {
            return json_error(StatusCode::NOT_FOUND, "User with this email not found");
        }
        Err(e) => {
            tracing::error!(?e, %email, "forgot-password db lookup failed");
            return json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable");
        }
    };

    let token = generate_verification_token();
    let expires_at = Utc::now() + Duration::hours(1);

    let updated = sqlx::query(
        r#"
        UPDATE users
        SET password_reset_token = $1,
            password_reset_token_expires_at = $2
        WHERE id = $3
        "#,
    )
    .bind(&token)
    .bind(expires_at)
    .bind(user.0)
    .execute(&state.db.pool)
    .await;

    match updated {
        Ok(_) => {
            let email_sent = if state.email.is_enabled() {
                match state.email.send_password_reset_email(&email, &token).await {
                    Ok(_) => true,
                    Err(e) => {
                        tracing::error!(%email, error = %e, "failed to send password reset email; falling back to dev mode");
                        false
                    }
                }
            } else {
                false
            };

            if email_sent {
                (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "message": "If the email exists, a password reset link has been sent."
                    })),
                )
            } else {
                tracing::warn!(%email, token = %token, "returning reset token in response (dev mode)");
                (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "message": "Password reset token generated.",
                        "reset_token": token
                    })),
                )
            }
        }
        Err(e) => {
            tracing::error!(?e, %email, "forgot-password update failed");
            json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
        }
    }
}
