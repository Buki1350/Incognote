use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub(crate) id: i64,
    pub(crate) email: String,
    pub(crate) username: String,
    pub(crate) is_verified: bool,
}
