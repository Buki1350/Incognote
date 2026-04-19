use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct VerifyEmailQuery {
    pub(crate) token: String,
}
