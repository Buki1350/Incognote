//! External API client used to enrich login audit logs with country information.
//! Failures are tolerated because geolocation is optional telemetry.

use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Deserialize)]
struct GeoIpResponse {
    country_name: Option<String>,
}

#[derive(Clone)]
pub struct GeoIpService {
    client: Client,
    base_url: String,
}

impl GeoIpService {
    pub fn new() -> Self {
        let base_url =
            std::env::var("GEOIP_API_BASE_URL").unwrap_or_else(|_| "https://ipapi.co".to_string());

        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(3))
                .build()
                .expect("failed to create geoip client"),
            base_url,
        }
    }

    pub async fn lookup_country(&self, ip: &str) -> Option<String> {
        if ip.trim().is_empty() || ip == "unknown" {
            return None;
        }

        if is_local_ip(ip) {
            return Some("local".to_string());
        }

        let url = format!("{}/{}/json/", self.base_url.trim_end_matches('/'), ip);

        let response = self.client.get(url).send().await.ok()?;
        if !response.status().is_success() {
            return None;
        }

        response.json::<GeoIpResponse>().await.ok()?.country_name
    }
}

fn is_local_ip(ip: &str) -> bool {
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            let octets = v4.octets();
            octets[0] == 10
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 168)
                || v4.is_loopback()
        }
        Ok(std::net::IpAddr::V6(v6)) => v6.is_loopback(),
        Err(_) => false,
    }
}
