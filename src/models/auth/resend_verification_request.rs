use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ResendVerificationRequest {
    pub(crate) email: String,
}
