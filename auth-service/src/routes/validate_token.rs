use crate::{app_state::AppState, models::{Claims, ValidateTokenRequest, ValidateTokenResponse}};
use axum::{extract::State, Json};

pub async fn validate_token(
    State(state): State<AppState>,
    Json(payload): Json<ValidateTokenRequest>,
) -> Json<ValidateTokenResponse> {
    let result = state.jwt.validate_token(&payload.token);

    match result {
        Ok(Claims {
            sub,
            username,
            email,
            role,
            ..
        }) => Json(ValidateTokenResponse {
            valid: true,
            user_id: Some(sub),
            username: Some(username),
            email: Some(email),
            role: Some(role),
        }),
        Err(_) => Json(ValidateTokenResponse {
            valid: false,
            user_id: None,
            username: None,
            email: None,
            role: None,
        }),
    }
}
