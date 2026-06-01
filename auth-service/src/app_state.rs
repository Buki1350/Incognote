//! Shared state for all auth handlers.

use crate::{
    db::Db,
    services::{EmailService, GeoIpService, JwtService, RateLimiter},
};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Db>,
    pub jwt: Arc<JwtService>,
    pub geoip: Arc<GeoIpService>,
    pub limiter: Arc<RateLimiter>,
    pub email: Arc<EmailService>,
}

impl AppState {
    pub fn new(db: Db, jwt: JwtService, geoip: GeoIpService, limiter: RateLimiter, email: EmailService) -> Self {
        Self {
            db: Arc::new(db),
            jwt: Arc::new(jwt),
            geoip: Arc::new(geoip),
            limiter: Arc::new(limiter),
            email: Arc::new(email),
        }
    }
}
