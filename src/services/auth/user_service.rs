use crate::{
    app::AppError,
    db::{UserRecord, UserRepository},
    models::{AuthResponse, AuthUserResponse, RegisterRequest, RegisterResponse},
    services::MailService,
};
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use urlencoding::encode;

const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_USERINFO_URL: &str = "https://openidconnect.googleapis.com/v1/userinfo";
const DEFAULT_SESSION_TTL_SECONDS: i64 = 3600;
const MIN_USERNAME_LEN: usize = 5;
const MIN_PASSWORD_LEN: usize = 8;

#[derive(Debug, Deserialize)]
struct GoogleTokenResponse {
    access_token: String,
}

#[derive(Debug, Deserialize)]
struct GoogleTokenErrorResponse {
    error: String,
    error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GoogleUserInfoResponse {
    sub: String,
    email: Option<String>,
    email_verified: Option<bool>,
    name: Option<String>,
}

struct GoogleOAuthConfig {
    client_id: String,
    client_secret: String,
    redirect_url: String,
}

impl GoogleOAuthConfig {
    fn from_env() -> Result<Self, AppError> {
        let client_id = std::env::var("GOOGLE_CLIENT_ID").ok();
        let client_secret = std::env::var("GOOGLE_CLIENT_SECRET").ok();
        let redirect_url = std::env::var("GOOGLE_REDIRECT_URL").ok();

        match (client_id, client_secret, redirect_url) {
            (Some(client_id), Some(client_secret), Some(redirect_url))
                if !client_id.trim().is_empty()
                    && !client_secret.trim().is_empty()
                    && !redirect_url.trim().is_empty() =>
            {
                Ok(Self {
                    client_id,
                    client_secret,
                    redirect_url,
                })
            }
            _ => Err(AppError::Internal(
                "Google OAuth is not configured. Set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET and GOOGLE_REDIRECT_URL."
                    .to_string(),
            )),
        }
    }
}

#[derive(Clone)]
pub struct UserService {
    pub(crate) user_repo: Arc<UserRepository>,
    pub(crate) mail_service: Arc<MailService>,
}

impl UserService {
    pub async fn register(&self, payload: RegisterRequest) -> Result<RegisterResponse, AppError> {
        if payload.username.trim().len() < MIN_USERNAME_LEN {
            return Err(AppError::Validation(format!(
                "username must have at least {} characters",
                MIN_USERNAME_LEN,
            )));
        }

        if payload.password.len() < MIN_PASSWORD_LEN {
            return Err(AppError::Validation(format!(
                "password must have at least {} characters",
                MIN_PASSWORD_LEN,
            )));
        }

        if !payload.email.contains('@') {
            return Err(AppError::Validation(
                format!("incorrect email ({})", payload.email).to_string(),
            ));
        }

        let password_hash = Self::hash_password(payload.password.as_bytes())?;

        let verification_token = Self::generate_random_token(32);
        let verification_token_hash = Self::hash_token(&verification_token);

        let user = self
            .user_repo
            .create_user_with_verification_token(
                payload.email,
                payload.username,
                password_hash,
                verification_token_hash,
            )
            .await?;

        self.mail_service
            .send_verification_email(&user.email, &verification_token)
            .await?;

        Ok(user)
    }

    pub async fn verify_email(&self, token: String) -> Result<bool, AppError> {
        if token.trim().is_empty() {
            return Err(AppError::Validation(
                "verification token cannot be empty".to_string(),
            ));
        }

        let token_hash = Self::hash_token(&token);
        self.user_repo.verify_email_token(&token_hash).await
    }

    pub async fn resend_verification_email(&self, email: String) -> Result<(), AppError> {
        if !email.contains('@') {
            return Err(AppError::Validation(
                format!("incorrect email ({})", email).to_string(),
            ));
        }

        let verification_token = Self::generate_random_token(32);
        let verification_token_hash = Self::hash_token(&verification_token);

        let should_send = self
            .user_repo
            .create_resend_verification_token(&email, &verification_token_hash)
            .await?;

        if should_send {
            self.mail_service
                .send_verification_email(&email, &verification_token)
                .await?;
        }

        Ok(())
    }

    pub async fn start_google_oauth(&self) -> Result<String, AppError> {
        let config = GoogleOAuthConfig::from_env()?;
        let state = Self::generate_random_token(32);
        let state_hash = Self::hash_token(&state);

        self.user_repo.store_google_oauth_state(&state_hash).await?;

        let auth_url = format!(
            "{base}?response_type=code&client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}&state={state}&access_type=online&prompt=select_account",
            base = GOOGLE_AUTH_URL,
            client_id = encode(&config.client_id),
            redirect_uri = encode(&config.redirect_url),
            scope = encode("openid email profile"),
            state = encode(&state),
        );

        Ok(auth_url)
    }

    pub async fn complete_google_oauth(
        &self,
        authorization_code: String,
        state: String,
    ) -> Result<AuthResponse, AppError> {
        if authorization_code.trim().is_empty() {
            return Err(AppError::Validation(
                "authorization code cannot be empty".to_string(),
            ));
        }

        if state.trim().is_empty() {
            return Err(AppError::Validation("state cannot be empty".to_string()));
        }

        let state_hash = Self::hash_token(&state);
        let state_consumed = self
            .user_repo
            .consume_google_oauth_state(&state_hash)
            .await?;
        if !state_consumed {
            return Err(AppError::Validation(
                "invalid or expired oauth state".to_string(),
            ));
        }

        let config = GoogleOAuthConfig::from_env()?;
        let access_token =
            Self::exchange_google_code_for_access_token(&config, &authorization_code).await?;
        let google_user = Self::fetch_google_user_info(&access_token).await?;

        let email = google_user
            .email
            .ok_or_else(|| AppError::Validation("google account has no e-mail".to_string()))?;

        if !google_user.email_verified.unwrap_or(false) {
            return Err(AppError::Validation(
                "google e-mail must be verified".to_string(),
            ));
        }

        let user = self
            .resolve_google_user(&google_user.sub, &email, google_user.name.as_deref())
            .await?;

        let session_token = Self::generate_random_token(32);
        let session_token_hash = Self::hash_token(&session_token);
        let session_ttl_seconds = Self::session_ttl_seconds();

        self.user_repo
            .create_user_session(user.id, &session_token_hash, session_ttl_seconds)
            .await?;

        Ok(AuthResponse {
            access_token: session_token,
            token_type: "Bearer".to_string(),
            expires_in: session_ttl_seconds,
            user: user_record_to_auth_user_response(user),
        })
    }

    async fn resolve_google_user(
        &self,
        google_sub: &str,
        email: &str,
        full_name: Option<&str>,
    ) -> Result<UserRecord, AppError> {
        if let Some(user) = self.user_repo.find_user_by_google_sub(google_sub).await? {
            return Ok(user);
        }

        let mut user = if let Some(existing_user) = self.user_repo.find_user_by_email(email).await?
        {
            existing_user
        } else {
            self.create_google_user_with_retry(email, full_name).await?
        };

        if !user.is_verified {
            self.user_repo.set_user_verified(user.id).await?;
            user.is_verified = true;
        }

        self.user_repo
            .link_google_identity(user.id, google_sub)
            .await?;

        if let Some(linked_user) = self.user_repo.find_user_by_google_sub(google_sub).await? {
            return Ok(linked_user);
        }

        Ok(user)
    }

    async fn create_google_user_with_retry(
        &self,
        email: &str,
        full_name: Option<&str>,
    ) -> Result<UserRecord, AppError> {
        let google_password_hash = Self::hash_password(Self::generate_random_token(32).as_bytes())?;

        for _ in 0..8 {
            let username = Self::generate_google_username(email, full_name);
            match self
                .user_repo
                .create_google_user(email, &username, &google_password_hash)
                .await
            {
                Ok(user) => return Ok(user),
                Err(AppError::Conflict(_)) => {
                    if let Some(existing_user) = self.user_repo.find_user_by_email(email).await? {
                        return Ok(existing_user);
                    }
                }
                Err(error) => return Err(error),
            }
        }

        Err(AppError::Internal(
            "failed to create unique username for google login".to_string(),
        ))
    }

    async fn exchange_google_code_for_access_token(
        config: &GoogleOAuthConfig,
        authorization_code: &str,
    ) -> Result<String, AppError> {
        let client = reqwest::Client::new();
        let response = client
            .post(GOOGLE_TOKEN_URL)
            .form(&[
                ("code", authorization_code),
                ("client_id", config.client_id.as_str()),
                ("client_secret", config.client_secret.as_str()),
                ("redirect_uri", config.redirect_url.as_str()),
                ("grant_type", "authorization_code"),
            ])
            .send()
            .await
            .map_err(|_| AppError::Internal("failed to call google token endpoint".to_string()))?;

        if !response.status().is_success() {
            let error_message = response
                .json::<GoogleTokenErrorResponse>()
                .await
                .map(|error| {
                    let description = error.error_description.unwrap_or_default();
                    if description.is_empty() {
                        error.error
                    } else {
                        format!("{} ({})", error.error, description)
                    }
                })
                .unwrap_or_else(|_| "unknown token exchange error".to_string());

            return Err(AppError::Validation(format!(
                "google token exchange failed: {}",
                error_message
            )));
        }

        let token_response = response
            .json::<GoogleTokenResponse>()
            .await
            .map_err(|_| AppError::Internal("invalid google token response".to_string()))?;

        Ok(token_response.access_token)
    }

    async fn fetch_google_user_info(
        access_token: &str,
    ) -> Result<GoogleUserInfoResponse, AppError> {
        let client = reqwest::Client::new();
        let response = client
            .get(GOOGLE_USERINFO_URL)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|_| {
                AppError::Internal("failed to call google userinfo endpoint".to_string())
            })?;

        if !response.status().is_success() {
            return Err(AppError::Validation(
                "google userinfo request failed".to_string(),
            ));
        }

        response
            .json::<GoogleUserInfoResponse>()
            .await
            .map_err(|_| AppError::Internal("invalid google userinfo response".to_string()))
    }

    fn generate_random_token(byte_len: usize) -> String {
        let mut token_bytes = vec![0u8; byte_len];
        OsRng.fill_bytes(&mut token_bytes);
        URL_SAFE_NO_PAD.encode(token_bytes)
    }

    fn hash_token(token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let hash = hasher.finalize();
        format!("{:x}", hash)
    }

    fn hash_password(raw_password: &[u8]) -> Result<String, AppError> {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(raw_password, &salt)
            .map_err(|_| AppError::Internal("password hashing failed".to_string()))
            .map(|password_hash| password_hash.to_string())
    }

    fn session_ttl_seconds() -> i64 {
        std::env::var("SESSION_TOKEN_TTL_SECONDS")
            .ok()
            .and_then(|value| value.parse::<i64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_SESSION_TTL_SECONDS)
    }

    fn generate_google_username(email: &str, full_name: Option<&str>) -> String {
        let seed = full_name.unwrap_or(email);
        let mut base: String = seed
            .chars()
            .filter_map(|ch| {
                if ch.is_ascii_alphanumeric() {
                    Some(ch.to_ascii_lowercase())
                } else if ch == ' ' || ch == '_' || ch == '-' || ch == '.' {
                    Some('_')
                } else {
                    None
                }
            })
            .collect();

        if base.len() < MIN_USERNAME_LEN {
            let email_prefix = email.split('@').next().unwrap_or_default();
            base = email_prefix
                .chars()
                .filter_map(|ch| {
                    if ch.is_ascii_alphanumeric() {
                        Some(ch.to_ascii_lowercase())
                    } else if ch == '_' || ch == '-' || ch == '.' {
                        Some('_')
                    } else {
                        None
                    }
                })
                .collect();
        }

        if base.len() < MIN_USERNAME_LEN {
            base = "google_user".to_string();
        }

        if base.len() > 20 {
            base.truncate(20);
        }

        let mut suffix_bytes = [0u8; 4];
        OsRng.fill_bytes(&mut suffix_bytes);
        let suffix = suffix_bytes
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<String>();

        format!("{}_{}", base, suffix)
    }
}

fn user_record_to_auth_user_response(user: UserRecord) -> AuthUserResponse {
    AuthUserResponse {
        id: user.id,
        email: user.email,
        username: user.username,
        is_verified: user.is_verified,
    }
}
