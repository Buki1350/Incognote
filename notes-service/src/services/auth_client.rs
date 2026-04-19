//! Client used by notes service to validate JWTs through auth service.
//! Any auth-service communication failure is treated as deny (fail-safe).

use crate::models::AuthUser;
use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    InvalidToken,
    ServiceUnavailable,
}

#[derive(Debug, Deserialize)]
struct ValidateTokenResponse {
    valid: bool,
    user_id: Option<i64>,
    username: Option<String>,
    role: Option<String>,
}

#[derive(Clone)]
pub struct AuthClient {
    client: Client,
    base_url: String,
}

impl AuthClient {
    pub fn from_env() -> Self {
        let base_url = std::env::var("AUTH_SERVICE_URL")
            .unwrap_or_else(|_| "http://localhost:3001".to_string());
        Self::new(base_url, Duration::from_secs(3))
    }

    pub fn new(base_url: String, timeout: Duration) -> Self {
        Self {
            client: Client::builder()
                .timeout(timeout)
                .build()
                .expect("failed to create auth client"),
            base_url,
        }
    }

    pub async fn validate_token(&self, token: &str) -> Result<AuthUser, AuthError> {
        let response = self
            .client
            .post(format!(
                "{}/validate-token",
                self.base_url.trim_end_matches('/')
            ))
            .json(&serde_json::json!({ "token": token }))
            .send()
            .await
            .map_err(|_| AuthError::ServiceUnavailable)?;

        if !response.status().is_success() {
            return Err(AuthError::ServiceUnavailable);
        }

        let payload = response
            .json::<ValidateTokenResponse>()
            .await
            .map_err(|_| AuthError::ServiceUnavailable)?;

        if !payload.valid {
            return Err(AuthError::InvalidToken);
        }

        let user_id = payload.user_id.ok_or(AuthError::InvalidToken)?;
        let username = payload.username.ok_or(AuthError::InvalidToken)?;
        let role = payload.role.ok_or(AuthError::InvalidToken)?;

        Ok(AuthUser {
            user_id,
            username,
            role,
        })
    }

    pub async fn is_available(&self) -> bool {
        self.client
            .get(format!("{}/health", self.base_url.trim_end_matches('/')))
            .send()
            .await
            .map(|response| response.status().is_success())
            .unwrap_or(false)
    }
}
