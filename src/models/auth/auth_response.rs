use serde::Serialize;

use crate::models::AuthUserResponse;

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub(crate) access_token: String,
    pub(crate) token_type: String,
    pub(crate) expires_in: i64,
    pub(crate) user: AuthUserResponse,
}
