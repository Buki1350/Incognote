use axum::{extract::State, response::Redirect};

use crate::app::{AppError, AppState};

pub async fn google_auth_start(State(state): State<AppState>) -> Result<Redirect, AppError> {
    let auth_url = state.services.user.start_google_oauth().await?;
    Ok(Redirect::to(&auth_url))
}
