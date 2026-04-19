//! Shared state for notes handlers.

use crate::{
    db::Db,
    services::{AuthClient, EncryptionService},
};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Db>,
    pub auth_client: Arc<AuthClient>,
    pub encryption: Arc<EncryptionService>,
}

impl AppState {
    pub fn new(db: Db, auth_client: AuthClient, encryption: EncryptionService) -> Self {
        Self {
            db: Arc::new(db),
            auth_client: Arc::new(auth_client),
            encryption: Arc::new(encryption),
        }
    }
}
