//! JWT helper for issuing and validating auth tokens.

use crate::models::Claims;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};

#[derive(Clone)]
pub struct JwtService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    ttl_seconds: i64,
}

impl JwtService {
    pub fn from_env() -> Result<Self, String> {
        let secret = std::env::var("JWT_SECRET")
            .map_err(|_| "JWT_SECRET is required and must be at least 32 characters".to_string())?;

        let ttl_seconds = std::env::var("JWT_TTL_SECONDS")
            .ok()
            .and_then(|value| value.parse::<i64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(3600);

        Self::from_secret(&secret, ttl_seconds)
    }

    pub fn from_secret(secret: &str, ttl_seconds: i64) -> Result<Self, String> {
        if secret.len() < 32 {
            return Err("JWT secret must be at least 32 characters".to_string());
        }
        if ttl_seconds <= 0 {
            return Err("JWT TTL must be positive".to_string());
        }

        Ok(Self {
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
            ttl_seconds,
        })
    }

    pub fn generate_token(
        &self,
        user_id: i64,
        username: &str,
        email: &str,
        role: &str,
    ) -> Result<String, String> {
        let now = Utc::now();
        let exp = now + Duration::seconds(self.ttl_seconds);

        let claims = Claims {
            sub: user_id,
            username: username.to_string(),
            email: email.to_string(),
            role: role.to_string(),
            exp: exp.timestamp() as usize,
            iat: now.timestamp() as usize,
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|error| format!("token generation failed: {error}"))
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims, String> {
        let validation = Validation::new(Algorithm::HS256);

        decode::<Claims>(token, &self.decoding_key, &validation)
            .map(|decoded| decoded.claims)
            .map_err(|error| format!("token validation failed: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::JwtService;

    #[test]
    fn token_round_trip_works() {
        let jwt = JwtService::from_secret("12345678901234567890123456789012", 3600).unwrap();
        let token = jwt
            .generate_token(10, "alice", "alice@example.com", "user")
            .unwrap();
        let claims = jwt.validate_token(&token).unwrap();

        assert_eq!(claims.sub, 10);
        assert_eq!(claims.username, "alice");
        assert_eq!(claims.email, "alice@example.com");
        assert_eq!(claims.role, "user");
    }
}
