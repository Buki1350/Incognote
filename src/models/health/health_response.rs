use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub(crate) status: &'static str,
}
