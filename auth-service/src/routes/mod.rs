pub mod forgot_password;
pub mod health;
pub mod login;
pub mod register;
pub mod reset_password;
pub mod update_role;
pub mod validate_token;

use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use crate::models::ErrorResponse;
use rand::{distributions::Alphanumeric, thread_rng, Rng};

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
