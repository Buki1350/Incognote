use crate::{
    app_state::AppState,
    models::{AuthUser, ErrorResponse},
    services::AuthError,
};
use axum::{
    http::{HeaderMap, StatusCode},
    Json,
};

#[derive(Debug, sqlx::FromRow)]
pub struct UserLookupRow {
    pub user_id: i64,
}

pub async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthUser, (StatusCode, Json<serde_json::Value>)> {
    let token = extract_bearer_token(headers)
        .ok_or_else(|| json_error(StatusCode::UNAUTHORIZED, "Missing bearer token"))?;

    state
        .auth_client
        .validate_token(&token)
        .await
        .map_err(|error| match error {
            AuthError::InvalidToken => json_error(StatusCode::UNAUTHORIZED, "Invalid token"),
            AuthError::ServiceUnavailable => {
                tracing::warn!("auth service unavailable; denying request");
                json_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Authentication service unavailable",
                )
            }
        })
}

pub fn json_error(status: StatusCode, message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        status,
        Json(
            serde_json::to_value(ErrorResponse {
                message: message.to_string(),
            })
            .unwrap_or_else(|_| serde_json::json!({ "message": message })),
        ),
    )
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(ToOwned::to_owned)
}

pub fn ordered_pair(a: i64, b: i64) -> (i64, i64) {
    if a < b { (a, b) } else { (b, a) }
}

pub fn normalize_private_key(value: Option<&str>) -> Result<Option<&str>, &'static str> {
    let key = value.map(str::trim).filter(|value| !value.is_empty());
    if let Some(value) = key {
        if value.len() < 8 || value.len() > 256 {
            return Err("Private key must be 8-256 characters long");
        }
    }
    Ok(key)
}

pub fn validate_note_content(content: &str) -> Result<(), &'static str> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err("Note content cannot be empty");
    }
    if trimmed.len() > 5000 {
        return Err("Note content cannot exceed 5000 characters");
    }
    Ok(())
}

pub async fn lookup_user_by_identifier(
    state: &AppState,
    identifier: &str,
) -> Result<Option<UserLookupRow>, sqlx::Error> {
    sqlx::query_as::<_, UserLookupRow>(
        r#"
        SELECT id AS user_id
        FROM users
        WHERE username = $1 OR email = $1
        "#,
    )
    .bind(identifier)
    .fetch_optional(&state.db.pool)
    .await
}

pub async fn are_friends(
    state: &AppState,
    user_id: i64,
    other_user_id: i64,
) -> Result<bool, sqlx::Error> {
    let (user_one_id, user_two_id) = ordered_pair(user_id, other_user_id);

    sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM friends
            WHERE user_one_id = $1 AND user_two_id = $2
        )
        "#,
    )
    .bind(user_one_id)
    .bind(user_two_id)
    .fetch_one(&state.db.pool)
    .await
}
