//! Shared state for all auth handlers.

use crate::{
    db::Db,
    services::{GeoIpService, JwtService, RateLimiter},
};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Db>,
    pub jwt: Arc<JwtService>,
    pub geoip: Arc<GeoIpService>,
    pub limiter: Arc<RateLimiter>,
}

impl AppState {
    pub fn new(db: Db, jwt: JwtService, geoip: GeoIpService, limiter: RateLimiter) -> Self {
        Self {
            db: Arc::new(db),
            jwt: Arc::new(jwt),
            geoip: Arc::new(geoip),
            limiter: Arc::new(limiter),
        }
    }
}
