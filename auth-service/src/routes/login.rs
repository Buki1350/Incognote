use crate::{
    app_state::AppState,
    models::AuthResponse,
    services::PasswordService,
    validation::{validate_email, validate_trusted_email_provider},
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use super::{extract_ip, json_error};

pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<crate::models::LoginRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let email = payload.email.trim().to_lowercase();
    let ip = extract_ip(&headers);

    if let Err(message) = validate_email(&email) {
        return json_error(StatusCode::BAD_REQUEST, message);
    }
    if let Err(message) = validate_trusted_email_provider(&email) {
        return json_error(StatusCode::BAD_REQUEST, &message);
    }

    if state.limiter.is_blocked(&email, &ip) {
        tracing::warn!(%email, %ip, "login blocked by rate limiter");
        return json_error(StatusCode::TOO_MANY_REQUESTS, "Too many login attempts");
    }

    let user = sqlx::query_as::<_, (i64, String, String, String, bool, String)>(
        r#"
        SELECT id, username, email, password_hash, is_email_verified, role
        FROM users
        WHERE email = $1
        "#,
    )
    .bind(&email)
    .fetch_optional(&state.db.pool)
    .await;

    let Some((user_id, db_username, db_email, password_hash, is_email_verified, role)) = (match user
    {
        Ok(record) => record,
        Err(error) => {
            tracing::error!(?error, "login db query failed");
            return json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable");
        }
    }) else {
        state.limiter.record_failure(&email, &ip);
        tracing::warn!(%email, %ip, "invalid login: unknown user");
        return json_error(StatusCode::UNAUTHORIZED, "Invalid credentials");
    };

    if !is_email_verified {
        tracing::warn!(%db_email, "login blocked: email not verified");
        return json_error(StatusCode::FORBIDDEN, "Email address is not verified");
    }

    let password_ok =
        PasswordService::verify_password(&payload.password, &password_hash).unwrap_or(false);
    if !password_ok {
        state.limiter.record_failure(&email, &ip);
        tracing::warn!(%email, %ip, "invalid login: bad password");
        return json_error(StatusCode::UNAUTHORIZED, "Invalid credentials");
    }

    state.limiter.record_success(&email, &ip);

    let normalized_role = if role == "admin" { "admin" } else { "user" };

    let token = match state
        .jwt
        .generate_token(user_id, &db_username, &db_email, normalized_role)
    {
        Ok(token) => token,
        Err(error) => {
            tracing::error!(?error, "token generation failed");
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create session",
            );
        }
    };

    let country = state
        .geoip
        .lookup_country(&ip)
        .await
        .unwrap_or_else(|| "unknown".to_string());
    tracing::info!(%db_username, %db_email, %ip, %country, role = normalized_role, "login success");

    (
        StatusCode::OK,
        Json(
            serde_json::to_value(AuthResponse {
                token,
                user_id,
                username: db_username,
                email: db_email,
                role: normalized_role.to_string(),
            })
            .unwrap_or_else(|_| serde_json::json!({ "message": "serialization error" })),
        ),
    )
}
