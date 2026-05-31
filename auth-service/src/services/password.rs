//! Password hashing helpers.

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

#[cfg(test)]
mod tests {
    use super::PasswordService;

    #[test]
    fn hash_and_verify_password() {
        let hash = PasswordService::hash_password("pass1234").unwrap();
        assert!(PasswordService::verify_password("pass1234", &hash).unwrap());
        assert!(!PasswordService::verify_password("wrong", &hash).unwrap());
    }
}
