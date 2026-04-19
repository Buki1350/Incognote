use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    error: String,
}
