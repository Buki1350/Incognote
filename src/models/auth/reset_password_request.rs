use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ResetPasswordRequest {
    pub(crate) email: String,
    pub(crate) token: String,
    pub(crate) new_password: String,
    pub(crate) confirm_password: String,
}
