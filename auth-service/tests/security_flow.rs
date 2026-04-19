use incognote_auth::services::{JwtService, PasswordService, RateLimiter};
use std::time::Duration;

#[test]
fn auth_security_primitives_work_together() {
    let jwt = JwtService::from_secret("12345678901234567890123456789012", 3600).unwrap();

    let password_hash = PasswordService::hash_password("secure123").unwrap();
    assert!(PasswordService::verify_password("secure123", &password_hash).unwrap());

    let token = jwt
        .generate_token(42, "alice", "alice@example.com", "user")
        .unwrap();
    let claims = jwt.validate_token(&token).unwrap();
    assert_eq!(claims.sub, 42);
    assert_eq!(claims.username, "alice");
    assert_eq!(claims.email, "alice@example.com");

    let limiter = RateLimiter::new(2, Duration::from_secs(60), Duration::from_secs(1));
    limiter.record_failure("alice", "1.1.1.1");
    assert!(!limiter.is_blocked("alice", "1.1.1.1"));
    limiter.record_failure("alice", "1.1.1.1");
    assert!(limiter.is_blocked("alice", "1.1.1.1"));
}
