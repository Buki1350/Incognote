//! Database layer for the auth service.
//! User accounts and email-verification metadata are managed here.

use sqlx::{postgres::PgPoolOptions, Pool, Postgres};
use std::env;

#[derive(Clone)]
pub struct Db {
    pub pool: Pool<Postgres>,
}

impl Db {
    pub async fn connect() -> Result<Self, sqlx::Error> {
        let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://postgres:postgres@localhost:5432/incognote".to_string()
        });

        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(&database_url)
            .await?;

        Ok(Self { pool })
    }
}

/// Create the `users` table expected by the assignment.
pub async fn init_db(pool: &Pool<Postgres>) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id BIGSERIAL PRIMARY KEY,
            username VARCHAR(32) NOT NULL UNIQUE,
            email VARCHAR(254) NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            is_email_verified BOOLEAN NOT NULL DEFAULT FALSE,
            email_verification_token VARCHAR(128),
            role VARCHAR(10) NOT NULL CHECK (role IN ('admin', 'user'))
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(254)")
        .execute(pool)
        .await?;
    sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_email_verified BOOLEAN")
        .execute(pool)
        .await?;
    sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verification_token VARCHAR(128)")
        .execute(pool)
        .await?;

    sqlx::query(
        r#"
        UPDATE users
        SET email = CONCAT(username, '@incognote.local')
        WHERE email IS NULL OR BTRIM(email) = ''
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("ALTER TABLE users ALTER COLUMN email SET NOT NULL")
        .execute(pool)
        .await?;
    sqlx::query("UPDATE users SET is_email_verified = TRUE WHERE is_email_verified IS NULL")
        .execute(pool)
        .await?;
    sqlx::query("ALTER TABLE users ALTER COLUMN is_email_verified SET DEFAULT FALSE")
        .execute(pool)
        .await?;
    sqlx::query("ALTER TABLE users ALTER COLUMN is_email_verified SET NOT NULL")
        .execute(pool)
        .await?;

    sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique ON users (email)")
        .execute(pool)
        .await?;
    sqlx::query(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_verification_token_unique ON users (email_verification_token) WHERE email_verification_token IS NOT NULL",
    )
    .execute(pool)
    .await?;

    Ok(())
}
