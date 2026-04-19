//! Database utilities for notes service.
//! Note, friendship, invite, and direct-message tables are initialized here.

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

pub async fn init_db(pool: &Pool<Postgres>) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS notes (
            id BIGSERIAL PRIMARY KEY,
            owner_id BIGINT NOT NULL,
            content TEXT NOT NULL,
            is_encrypted BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS note_permissions (
            id BIGSERIAL PRIMARY KEY,
            note_id BIGINT NOT NULL REFERENCES notes(id) ON DELETE CASCADE,
            user_id BIGINT NOT NULL,
            permission VARCHAR(10) NOT NULL CHECK (permission IN ('read', 'write')),
            UNIQUE(note_id, user_id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_notes_owner_id ON notes(owner_id)")
        .execute(pool)
        .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_note_permissions_user_id ON note_permissions(user_id)",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS friends (
            id BIGSERIAL PRIMARY KEY,
            user_one_id BIGINT NOT NULL,
            user_two_id BIGINT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CONSTRAINT chk_friends_pair CHECK (user_one_id < user_two_id),
            UNIQUE(user_one_id, user_two_id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS direct_messages (
            id BIGSERIAL PRIMARY KEY,
            sender_id BIGINT NOT NULL,
            recipient_id BIGINT NOT NULL,
            content TEXT NOT NULL,
            is_private_encrypted BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS friend_requests (
            id BIGSERIAL PRIMARY KEY,
            requester_id BIGINT NOT NULL,
            recipient_id BIGINT NOT NULL,
            status VARCHAR(10) NOT NULL CHECK (status IN ('pending', 'accepted', 'rejected')),
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE(requester_id, recipient_id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_friends_user_one ON friends(user_one_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_friends_user_two ON friends(user_two_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_messages_sender ON direct_messages(sender_id)")
        .execute(pool)
        .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_messages_recipient ON direct_messages(recipient_id)",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_friend_requests_requester ON friend_requests(requester_id)",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_friend_requests_recipient ON friend_requests(recipient_id)",
    )
    .execute(pool)
    .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_friend_requests_status ON friend_requests(status)")
        .execute(pool)
        .await?;

    Ok(())
}
