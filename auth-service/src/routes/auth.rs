//! Authentication endpoints.
//! Security-sensitive logic stays centralized here so behavior is easier to audit.

use crate::{
    app_state::AppState,
    models::{
        AuthResponse, Claims, ErrorResponse, LoginRequest, RegisterRequest,
        ResendVerificationRequest, UpdateRoleRequest, ValidateTokenRequest, ValidateTokenResponse,
        VerifyEmailRequest,
    },
    services::{
        validate_email, validate_password_strength, validate_trusted_email_provider,
        validate_username, PasswordService,
    },
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use rand::{distributions::Alphanumeric, thread_rng, Rng};

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
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

pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<LoginRequest>,
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

pub async fn verify_email(
    State(state): State<AppState>,
    Json(payload): Json<VerifyEmailRequest>,
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

pub async fn resend_verification(
    State(state): State<AppState>,
    Json(payload): Json<ResendVerificationRequest>,
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

/// Admin-only role update endpoint.
/// This keeps role management in the auth service.
pub async fn update_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<i64>,
    Json(payload): Json<UpdateRoleRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let Some(token) = extract_bearer_token(&headers) else {
        return json_error(StatusCode::UNAUTHORIZED, "Missing bearer token");
    };

    let claims = match state.jwt.validate_token(&token) {
        Ok(claims) => claims,
        Err(_) => return json_error(StatusCode::UNAUTHORIZED, "Invalid token"),
    };

    if claims.role != "admin" {
        return json_error(StatusCode::FORBIDDEN, "Admin role required");
    }

    if payload.role != "admin" && payload.role != "user" {
        return json_error(StatusCode::BAD_REQUEST, "Role must be admin or user");
    }

    let updated = sqlx::query(
        r#"
        UPDATE users
        SET role = $1
        WHERE id = $2
        "#,
    )
    .bind(&payload.role)
    .bind(user_id)
    .execute(&state.db.pool)
    .await;

    match updated {
        Ok(result) if result.rows_affected() == 0 => {
            json_error(StatusCode::NOT_FOUND, "User not found")
        }
        Ok(_) => {
            tracing::info!(admin_id = claims.sub, target_user_id = user_id, role = %payload.role, "role updated");
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "message": "Role updated",
                    "user_id": user_id,
                    "role": payload.role
                })),
            )
        }
        Err(error) => {
            tracing::error!(?error, target_user_id = user_id, "role update failed");
            json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
        }
    }
}

pub async fn validate_token(
    State(state): State<AppState>,
    Json(payload): Json<ValidateTokenRequest>,
) -> Json<ValidateTokenResponse> {
    let result = state.jwt.validate_token(&payload.token);

    match result {
        Ok(Claims {
            sub,
            username,
            email,
            role,
            ..
        }) => Json(ValidateTokenResponse {
            valid: true,
            user_id: Some(sub),
            username: Some(username),
            email: Some(email),
            role: Some(role),
        }),
        Err(_) => Json(ValidateTokenResponse {
            valid: false,
            user_id: None,
            username: None,
            email: None,
            role: None,
        }),
    }
}

fn json_error(status: StatusCode, message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        status,
        Json(
            serde_json::to_value(ErrorResponse {
                message: message.to_string(),
            })
            .unwrap_or_else(|_| serde_json::json!({"message": message})),
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

fn extract_ip(headers: &HeaderMap) -> String {
    if let Some(forwarded) = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
    {
        return forwarded
            .split(',')
            .next()
            .unwrap_or("unknown")
            .trim()
            .to_string();
    }

    headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| "unknown".to_string())
}

fn generate_verification_token() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(48)
        .map(char::from)
        .collect()
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    match error {
        sqlx::Error::Database(db_error) => db_error.is_unique_violation(),
        _ => false,
    }
}
