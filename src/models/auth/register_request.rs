use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub(crate) email: String,
    pub(crate) username: String,
    pub(crate) password: String,
}
