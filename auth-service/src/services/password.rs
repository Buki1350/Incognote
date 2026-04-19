//! Password hashing and input validation helpers.

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand::rngs::OsRng;

pub struct PasswordService;

impl PasswordService {
    pub fn hash_password(password: &str) -> Result<String, String> {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|error| format!("password hashing failed: {error}"))
    }

    pub fn verify_password(password: &str, hash: &str) -> Result<bool, String> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|error| format!("invalid password hash format: {error}"))?;

        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }
}

pub fn validate_username(username: &str) -> Result<(), &'static str> {
    if username.len() < 3 || username.len() > 32 {
        return Err("Username must be 3-32 characters long");
    }

    if !username
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return Err("Username can contain only letters, digits, and underscore");
    }

    Ok(())
}

pub fn validate_email(email: &str) -> Result<(), &'static str> {
    if email.len() < 6 || email.len() > 254 {
        return Err("Email must be 6-254 characters long");
    }

    let Some((local, domain)) = email.split_once('@') else {
        return Err("Email must contain @");
    };

    if local.is_empty() || local.len() > 64 {
        return Err("Email local part is invalid");
    }

    if domain.len() < 3 || !domain.contains('.') {
        return Err("Email domain is invalid");
    }

    if !email
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '+' | '@'))
    {
        return Err("Email contains unsupported characters");
    }

    Ok(())
}

pub fn validate_trusted_email_provider(email: &str) -> Result<(), String> {
    let Some((_, domain)) = email.rsplit_once('@') else {
        return Err("Email provider could not be determined".to_string());
    };
    let domain = domain.trim().to_lowercase();

    let trusted_domains = std::env::var("TRUSTED_EMAIL_DOMAINS")
        .ok()
        .map(|raw| {
            raw.split(',')
                .map(|item| item.trim().to_lowercase())
                .filter(|item| !item.is_empty())
                .collect::<Vec<_>>()
        })
        .filter(|domains| !domains.is_empty())
        .unwrap_or_else(|| {
            vec![
                "gmail.com".to_string(),
                "googlemail.com".to_string(),
                "outlook.com".to_string(),
                "hotmail.com".to_string(),
                "live.com".to_string(),
                "yahoo.com".to_string(),
                "icloud.com".to_string(),
                "proton.me".to_string(),
                "protonmail.com".to_string(),
                "incognote.local".to_string(),
            ]
        });

    if trusted_domains.iter().any(|item| item == &domain) {
        Ok(())
    } else {
        Err(format!(
            "Email provider '{domain}' is not trusted. Allowed: {}",
            trusted_domains.join(", ")
        ))
    }
}

pub fn validate_password_strength(password: &str) -> Result<(), String> {
    if password.len() < 8 || password.len() > 128 {
        return Err("Password must be 8-128 characters long".to_string());
    }

    let has_letter = password.chars().any(|ch| ch.is_ascii_alphabetic());
    let has_digit = password.chars().any(|ch| ch.is_ascii_digit());

    if !has_letter || !has_digit {
        return Err("Password must contain at least one letter and one digit".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        validate_email, validate_password_strength, validate_trusted_email_provider,
        validate_username, PasswordService,
    };

    #[test]
    fn username_validation_enforces_expected_pattern() {
        assert!(validate_username("ab").is_err());
        assert!(validate_username("alice_test").is_ok());
        assert!(validate_username("alice-test").is_err());
    }

    #[test]
    fn password_validation_requires_letter_and_digit() {
        assert!(validate_password_strength("12345678").is_err());
        assert!(validate_password_strength("password").is_err());
        assert!(validate_password_strength("pass1234").is_ok());
    }

    #[test]
    fn email_validation_requires_basic_shape() {
        assert!(validate_email("a@b").is_err());
        assert!(validate_email("alice@example.com").is_ok());
        assert!(validate_email("alice example.com").is_err());
    }

    #[test]
    fn trusted_provider_validation_uses_defaults() {
        assert!(validate_trusted_email_provider("alice@gmail.com").is_ok());
        assert!(validate_trusted_email_provider("alice@unknown-provider.test").is_err());
    }

    #[test]
    fn hash_and_verify_password() {
        let hash = PasswordService::hash_password("pass1234").unwrap();
        assert!(PasswordService::verify_password("pass1234", &hash).unwrap());
        assert!(!PasswordService::verify_password("wrong", &hash).unwrap());
    }
}
