use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ForgotPasswordRequest {
    pub(crate) email: String,
}
