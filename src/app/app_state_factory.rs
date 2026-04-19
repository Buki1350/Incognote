use crate::{
    db::{UserRepository, build_postgres_pool, initialize_db},
    services::{MailService, UserService},
};
use std::sync::Arc;

use super::{AppState, Services};

pub async fn build_app_state() -> Result<AppState, Box<dyn std::error::Error>> {
    let pool = build_postgres_pool().await?;
    initialize_db(&pool).await?;

    let user_repo = Arc::new(UserRepository { pool });
    let mail_service = Arc::new(MailService::from_env()?);
    let user_service = Arc::new(UserService {
        user_repo,
        mail_service,
    });

    let services = Services { user: user_service };

    Ok(AppState::new(services))
}
