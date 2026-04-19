use sqlx::{Pool, Postgres, postgres::PgPoolOptions};

use crate::{app::AppError, models::RegisterResponse};

#[derive(Clone)]
pub struct UserRepository {
    pub(crate) pool: Pool<Postgres>,
}

#[derive(Debug, Clone)]
pub struct UserRecord {
    pub id: i64,
    pub email: String,
    pub username: String,
    pub is_verified: bool,
}

impl UserRepository {
    pub async fn create_user_with_verification_token(
        &self,
        email: String,
        username: String,
        password_hash: String,
        verification_token_hash: String,
    ) -> Result<RegisterResponse, AppError> {
        let mut tx = self.pool.begin().await.map_err(AppError::Database)?;

        let inserted_user = sqlx::query_as::<_, (i64, String, String, bool)>(
            r#"
            INSERT INTO users (email, username, password_hash, is_verified)
            VALUES ($1, $2, $3, FALSE)
            RETURNING id, email, username, is_verified
            "#,
        )
        .bind(&email)
        .bind(&username)
        .bind(&password_hash)
        .fetch_one(&mut *tx)
        .await;

        match inserted_user {
            Ok((id, email, username, is_verified)) => {
                sqlx::query(
                    r#"
                    INSERT INTO email_verification_tokens (user_id, token_hash, expires_at)
                    VALUES ($1, $2, NOW() + INTERVAL '24 hours')
                    "#,
                )
                .bind(id)
                .bind(&verification_token_hash)
                .execute(&mut *tx)
                .await
                .map_err(AppError::Database)?;

                tx.commit().await.map_err(AppError::Database)?;

                Ok(RegisterResponse {
                    id,
                    email,
                    username,
                    is_verified,
                })
            }
            Err(error) => {
                if is_unique_constraint(&error) {
                    return Err(AppError::Conflict(
                        "user with this email or username already exists".to_string(),
                    ));
                }

                Err(AppError::Database(error))
            }
        }
    }

    pub async fn verify_email_token(&self, token_hash: &str) -> Result<bool, AppError> {
        let mut tx = self.pool.begin().await.map_err(AppError::Database)?;

        let matched_user = sqlx::query_as::<_, (i64,)>(
            r#"
            UPDATE email_verification_tokens
            SET used_at = NOW()
            WHERE token_hash = $1
              AND used_at IS NULL
              AND expires_at > NOW()
            RETURNING user_id
            "#,
        )
        .bind(token_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::Database)?;

        let Some((user_id,)) = matched_user else {
            tx.commit().await.map_err(AppError::Database)?;
            return Ok(false);
        };

        sqlx::query(
            r#"
            UPDATE users
            SET is_verified = TRUE
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::Database)?;

        sqlx::query(
            r#"
            DELETE FROM email_verification_tokens
            WHERE user_id = $1
              AND used_at IS NULL
            "#,
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::Database)?;

        tx.commit().await.map_err(AppError::Database)?;
        Ok(true)
    }

    pub async fn create_resend_verification_token(
        &self,
        email: &str,
        token_hash: &str,
    ) -> Result<bool, AppError> {
        let mut tx = self.pool.begin().await.map_err(AppError::Database)?;

        let maybe_user = sqlx::query_as::<_, (i64, bool)>(
            r#"
            SELECT id, is_verified
            FROM users
            WHERE email = $1
            FOR UPDATE
            "#,
        )
        .bind(email)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::Database)?;

        let Some((user_id, is_verified)) = maybe_user else {
            tx.commit().await.map_err(AppError::Database)?;
            return Ok(false);
        };

        if is_verified {
            tx.commit().await.map_err(AppError::Database)?;
            return Ok(false);
        }

        sqlx::query(
            r#"
            DELETE FROM email_verification_tokens
            WHERE user_id = $1
              AND used_at IS NULL
            "#,
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::Database)?;

        sqlx::query(
            r#"
            INSERT INTO email_verification_tokens (user_id, token_hash, expires_at)
            VALUES ($1, $2, NOW() + INTERVAL '24 hours')
            "#,
        )
        .bind(user_id)
        .bind(token_hash)
        .execute(&mut *tx)
        .await
        .map_err(AppError::Database)?;

        tx.commit().await.map_err(AppError::Database)?;
        Ok(true)
    }

    pub async fn store_google_oauth_state(&self, state_hash: &str) -> Result<(), AppError> {
        sqlx::query(
            r#"
            DELETE FROM oauth_login_states
            WHERE expires_at <= NOW()
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(AppError::Database)?;

        sqlx::query(
            r#"
            INSERT INTO oauth_login_states (state_hash, expires_at)
            VALUES ($1, NOW() + INTERVAL '10 minutes')
            ON CONFLICT (state_hash)
            DO UPDATE SET expires_at = EXCLUDED.expires_at
            "#,
        )
        .bind(state_hash)
        .execute(&self.pool)
        .await
        .map_err(AppError::Database)?;

        Ok(())
    }

    pub async fn consume_google_oauth_state(&self, state_hash: &str) -> Result<bool, AppError> {
        let consumed = sqlx::query_scalar::<_, String>(
            r#"
            DELETE FROM oauth_login_states
            WHERE state_hash = $1
              AND expires_at > NOW()
            RETURNING state_hash
            "#,
        )
        .bind(state_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(AppError::Database)?;

        Ok(consumed.is_some())
    }

    pub async fn find_user_by_google_sub(
        &self,
        provider_sub: &str,
    ) -> Result<Option<UserRecord>, AppError> {
        let row = sqlx::query_as::<_, (i64, String, String, bool)>(
            r#"
            SELECT u.id, u.email, u.username, u.is_verified
            FROM users u
            JOIN oauth_identities oi ON oi.user_id = u.id
            WHERE oi.provider = 'google'
              AND oi.provider_sub = $1
            "#,
        )
        .bind(provider_sub)
        .fetch_optional(&self.pool)
        .await
        .map_err(AppError::Database)?;

        Ok(row.map(tuple_to_user_record))
    }

    pub async fn find_user_by_email(&self, email: &str) -> Result<Option<UserRecord>, AppError> {
        let row = sqlx::query_as::<_, (i64, String, String, bool)>(
            r#"
            SELECT id, email, username, is_verified
            FROM users
            WHERE email = $1
            "#,
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(AppError::Database)?;

        Ok(row.map(tuple_to_user_record))
    }

    pub async fn create_google_user(
        &self,
        email: &str,
        username: &str,
        password_hash: &str,
    ) -> Result<UserRecord, AppError> {
        let row = sqlx::query_as::<_, (i64, String, String, bool)>(
            r#"
            INSERT INTO users (email, username, password_hash, is_verified)
            VALUES ($1, $2, $3, TRUE)
            RETURNING id, email, username, is_verified
            "#,
        )
        .bind(email)
        .bind(username)
        .bind(password_hash)
        .fetch_one(&self.pool)
        .await;

        match row {
            Ok(tuple) => Ok(tuple_to_user_record(tuple)),
            Err(error) => {
                if is_unique_constraint(&error) {
                    return Err(AppError::Conflict(
                        "user with this email or username already exists".to_string(),
                    ));
                }

                Err(AppError::Database(error))
            }
        }
    }

    pub async fn set_user_verified(&self, user_id: i64) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE users
            SET is_verified = TRUE
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(AppError::Database)?;

        Ok(())
    }

    pub async fn link_google_identity(
        &self,
        user_id: i64,
        provider_sub: &str,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            INSERT INTO oauth_identities (user_id, provider, provider_sub)
            VALUES ($1, 'google', $2)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(user_id)
        .bind(provider_sub)
        .execute(&self.pool)
        .await
        .map_err(AppError::Database)?;

        Ok(())
    }

    pub async fn create_user_session(
        &self,
        user_id: i64,
        token_hash: &str,
        expires_in_seconds: i64,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            DELETE FROM user_sessions
            WHERE expires_at <= NOW()
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(AppError::Database)?;

        sqlx::query(
            r#"
            INSERT INTO user_sessions (user_id, token_hash, expires_at)
            VALUES ($1, $2, NOW() + ($3 * INTERVAL '1 second'))
            "#,
        )
        .bind(user_id)
        .bind(token_hash)
        .bind(expires_in_seconds)
        .execute(&self.pool)
        .await
        .map_err(AppError::Database)?;

        Ok(())
    }
}

pub async fn build_postgres_pool() -> Result<Pool<Postgres>, Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/db".to_string());

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    Ok(pool)
}

pub async fn initialize_db(pool: &Pool<Postgres>) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id BIGSERIAL PRIMARY KEY,
            email VARCHAR(255) NOT NULL UNIQUE,
            username VARCHAR(255) NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            is_verified BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS is_verified BOOLEAN NOT NULL DEFAULT FALSE
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS email_verification_tokens (
            id BIGSERIAL PRIMARY KEY,
            user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token_hash CHAR(64) NOT NULL UNIQUE,
            expires_at TIMESTAMPTZ NOT NULL,
            used_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_user_id
        ON email_verification_tokens (user_id)
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS oauth_login_states (
            state_hash CHAR(64) PRIMARY KEY,
            expires_at TIMESTAMPTZ NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_oauth_login_states_expires_at
        ON oauth_login_states (expires_at)
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS oauth_identities (
            id BIGSERIAL PRIMARY KEY,
            user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            provider VARCHAR(64) NOT NULL,
            provider_sub VARCHAR(255) NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (provider, provider_sub),
            UNIQUE (user_id, provider)
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_oauth_identities_user_id
        ON oauth_identities (user_id)
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS user_sessions (
            id BIGSERIAL PRIMARY KEY,
            user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token_hash CHAR(64) NOT NULL UNIQUE,
            expires_at TIMESTAMPTZ NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id
        ON user_sessions (user_id)
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_user_sessions_expires_at
        ON user_sessions (expires_at)
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}

fn tuple_to_user_record(tuple: (i64, String, String, bool)) -> UserRecord {
    let (id, email, username, is_verified) = tuple;
    UserRecord {
        id,
        email,
        username,
        is_verified,
    }
}

fn is_unique_constraint(error: &sqlx::Error) -> bool {
    match error {
        sqlx::Error::Database(db_error) => db_error.is_unique_violation(),
        _ => false,
    }
}
