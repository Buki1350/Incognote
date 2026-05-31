use crate::{
    app_state::AppState,
    services::PasswordService,
    validation::{validate_email, validate_password_strength, validate_trusted_email_provider, validate_username},
};
use axum::{extract::State, http::StatusCode, Json};
use super::{generate_verification_token, json_error};

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<crate::models::RegisterRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let username = payload.username.trim().to_lowercase();
    let email = payload.email.trim().to_lowercase();

    if let Err(message) = validate_username(&username) {
        return json_error(StatusCode::BAD_REQUEST, message);
    }
    if let Err(message) = validate_email(&email) {
        return json_error(StatusCode::BAD_REQUEST, message);
    }
    if let Err(message) = validate_trusted_email_provider(&email) {
        return json_error(StatusCode::BAD_REQUEST, &message);
    }
    if let Err(message) = validate_password_strength(&payload.password) {
        return json_error(StatusCode::BAD_REQUEST, &message);
    }

    let password_hash = match PasswordService::hash_password(&payload.password) {
        Ok(hash) => hash,
        Err(_) => {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to hash password");
        }
    };

    let verification_token = generate_verification_token();

    let inserted = sqlx::query_as::<_, (i64,)>(
        r#"
        INSERT INTO users (username, email, password_hash, is_email_verified, email_verification_token, role)
        VALUES ($1, $2, $3, FALSE, $4, 'user')
        RETURNING id
        "#,
    )
    .bind(&username)
    .bind(&email)
    .bind(&password_hash)
    .bind(&verification_token)
    .fetch_one(&state.db.pool)
    .await;

    match inserted {
        Ok((user_id,)) => {
            tracing::info!(username = %username, %email, user_id, "user registered, email verification required");
            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "message": "User registered. Verify email before login.",
                    "user_id": user_id,
                    "verification_token": verification_token
                })),
            )
        }
        Err(error) if is_unique_violation(&error) => {
            json_error(StatusCode::CONFLICT, "Username or email already exists")
        }
        Err(error) => {
            tracing::error!(?error, "register failed");
            json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
        }
    }
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    match error {
        sqlx::Error::Database(db_error) => db_error.is_unique_violation(),
        _ => false,
    }
}
