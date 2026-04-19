use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct GoogleAuthCallbackQuery {
    pub(crate) code: String,
    pub(crate) state: String,
}
