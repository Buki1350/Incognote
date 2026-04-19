use crate::services::UserService;
use std::sync::Arc;

#[derive(Clone)]
pub struct Services {
    pub(crate) user: Arc<UserService>,
}

#[derive(Clone)]
pub struct AppState {
    pub(crate) services: Services,
}

impl AppState {
    pub fn new(services: Services) -> Self {
        Self { services }
    }
}
