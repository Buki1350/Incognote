//! JWT Validator - Validates tokens with Auth Service
//!
//! SECURITY: This is the bridge between services
//! - Notes Service trusts Auth Service to validate tokens
//! - Uses HTTP to call Auth Service /validate-token
//! - Fails securely if Auth Service is unavailable
//!
//! FAILURE BEHAVIOR:
//! - If Auth Service is down: reject ALL requests (fail-safe)
//! - Never allow access when we can't verify the token

use crate::models::JwtClaims;
use reqwest::Client;
use std::time::Duration;

const AUTH_SERVICE_URL: &str = "http://localhost:3001";

pub struct JwtValidator {
    client: Client,
}

impl JwtValidator {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    /// Validate JWT by calling Auth Service
    ///
    /// SECURITY: Fail-safe behavior
    /// - If Auth Service is unreachable: return error (deny access)
    /// - If token is invalid: return error (deny access)
    /// - Only allow access on explicit "valid: true"
    pub async fn validate_token(&self, token: &str) -> Result<JwtClaims, String> {
        let response = self
            .client
            .post(format!("{}/validate-token", AUTH_SERVICE_URL))
            .json(&serde_json::json!({ "token": token }))
            .send()
            .await
            .map_err(|e| format!("Auth service unavailable: {}", e))?;

        if !response.status().is_success() {
            return Err("Auth service error".to_string());
        }

        let result: serde_json::Value = response
            .json()
            .await
            .map_err(|e| format!("Invalid auth response: {}", e))?;

        if result.get("valid").and_then(|v| v.as_bool()).unwrap_or(false) {
            Ok(JwtClaims {
                sub: result["user_id"].to_string(),
                username: result["username"].as_str().unwrap_or("").to_string(),
                role: result["role"].as_str().unwrap_or("").to_string(),
                exp: 0,
                iat: 0,
            })
        } else {
            Err("Invalid token".to_string())
        }
    }

    /// Check if Auth Service is healthy
    /// Used for health checks
    pub async fn is_auth_available(&self) -> bool {
        self.client
            .get(format!("{}/health", AUTH_SERVICE_URL))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }
}

impl Default for JwtValidator {
    fn default() -> Self {
        Self::new()
    }
}