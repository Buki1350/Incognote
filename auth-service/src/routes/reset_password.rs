use crate::{
    app_state::AppState,
    services::PasswordService,
    validation::{validate_email, validate_password_strength},
};
use axum::{extract::State, http::StatusCode, Json};
use super::json_error;
use chrono::Utc;

pub async fn reset_password(
    State(state): State<AppState>,
    Json(payload): Json<crate::models::ResetPasswordRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let email = payload.email.trim().to_lowercase();
    let token = payload.token.trim();
    let new_password = &payload.new_password;

    if let Err(message) = validate_email(&email) {
        return json_error(StatusCode::BAD_REQUEST, message);
    }
    if token.is_empty() || token.len() > 128 {
        return json_error(StatusCode::BAD_REQUEST, "Invalid reset token");
    }
    if let Err(message) = validate_password_strength(new_password) {
        return json_error(StatusCode::BAD_REQUEST, &message);
    }

    let user = sqlx::query_as::<_, (i64, String, Option<String>, Option<chrono::DateTime<Utc>>)>(
        r#"
        SELECT id, username, password_reset_token, password_reset_token_expires_at
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
            tracing::error!(?e, %email, "reset-password db lookup failed");
            return json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable");
        }
    };

    let stored_token = match user.2 {
        Some(t) => t,
        None => {
            return json_error(StatusCode::BAD_REQUEST, "No password reset requested for this user");
        }
    };

    let expires_at = match user.3 {
        Some(t) => t,
        None => {
            return json_error(StatusCode::BAD_REQUEST, "Password reset token expired");
        }
    };

    if Utc::now() > expires_at {
        return json_error(StatusCode::BAD_REQUEST, "Password reset token has expired. Request a new one.");
    }

    if stored_token != token {
        return json_error(StatusCode::BAD_REQUEST, "Invalid reset token");
    }

    let new_hash = match PasswordService::hash_password(new_password) {
        Ok(hash) => hash,
        Err(_) => {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to hash password");
        }
    };

    let updated = sqlx::query(
        r#"
        UPDATE users
        SET password_hash = $1,
            password_reset_token = NULL,
            password_reset_token_expires_at = NULL
        WHERE id = $2
        "#,
    )
    .bind(&new_hash)
    .bind(user.0)
    .execute(&state.db.pool)
    .await;

    match updated {
        Ok(_) => {
            tracing::info!(%email, user_id = user.0, "password reset successfully");
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "message": "Password reset successfully. You can login now."
                })),
            )
        }
        Err(e) => {
            tracing::error!(?e, %email, "reset-password update failed");
            json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
        }
    }
}
