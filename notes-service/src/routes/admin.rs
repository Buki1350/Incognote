use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use serde::Serialize;

use crate::{
    app_state::AppState,
    routes::helpers::{authenticate, json_error},
};
use axum::http::StatusCode;

#[derive(Debug, Serialize)]
struct AdminUser {
    id: i64,
    username: String,
    email: String,
    is_verified: bool,
}

#[derive(Debug, Serialize)]
struct AdminNote {
    id: i64,
    owner_id: i64,
    owner_username: String,
    content: String,
    is_encrypted: bool,
    created_at: String,
}

pub async fn list_all_users(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> (StatusCode, Json<serde_json::Value>) {
    let user = match authenticate(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    if !user.is_admin() {
        return json_error(StatusCode::FORBIDDEN, "Admin access required");
    }

    let rows = match sqlx::query_as::<_, (i64, String, String, bool)>(
        r#"
        SELECT id, username, email, is_email_verified
        FROM users
        ORDER BY id
        "#,
    )
    .fetch_all(&state.db.pool)
    .await
    {
        Ok(rows) => rows,
        Err(error) => {
            tracing::error!(?error, "failed to fetch users");
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    };

    let users: Vec<AdminUser> = rows
        .into_iter()
        .map(|(id, username, email, is_verified)| AdminUser {
            id,
            username,
            email,
            is_verified,
        })
        .collect();

    (StatusCode::OK, Json(serde_json::json!({ "users": users })))
}

pub async fn list_all_notes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> (StatusCode, Json<serde_json::Value>) {
    let user = match authenticate(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    if !user.is_admin() {
        return json_error(StatusCode::FORBIDDEN, "Admin access required");
    }

    let rows = match sqlx::query_as::<_, (i64, i64, String, String, bool, chrono::DateTime<chrono::Utc>)>(
        r#"
        SELECT n.id, n.owner_id, u.username, n.content, n.is_encrypted, n.created_at
        FROM notes n
        JOIN users u ON u.id = n.owner_id
        ORDER BY n.id
        "#,
    )
    .fetch_all(&state.db.pool)
    .await
    {
        Ok(rows) => rows,
        Err(error) => {
            tracing::error!(?error, "failed to fetch notes");
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    };

    let notes: Vec<AdminNote> = rows
        .into_iter()
        .map(|(id, owner_id, owner_username, content, is_encrypted, created_at)| AdminNote {
            id,
            owner_id,
            owner_username,
            content,
            is_encrypted,
            created_at: created_at.to_rfc3339(),
        })
        .collect();

    (StatusCode::OK, Json(serde_json::json!({ "notes": notes })))
}

pub async fn list_user_notes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<i64>,
) -> (StatusCode, Json<serde_json::Value>) {
    let user = match authenticate(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    if !user.is_admin() {
        return json_error(StatusCode::FORBIDDEN, "Admin access required");
    }

    let rows = match sqlx::query_as::<_, (i64, i64, String, String, bool, chrono::DateTime<chrono::Utc>)>(
        r#"
        SELECT n.id, n.owner_id, u.username, n.content, n.is_encrypted, n.created_at
        FROM notes n
        JOIN users u ON u.id = n.owner_id
        WHERE n.owner_id = $1
        ORDER BY n.id
        "#,
    )
    .bind(user_id)
    .fetch_all(&state.db.pool)
    .await
    {
        Ok(rows) => rows,
        Err(error) => {
            tracing::error!(?error, "failed to fetch notes for user {user_id}");
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    };

    let notes: Vec<AdminNote> = rows
        .into_iter()
        .map(|(id, owner_id, owner_username, content, is_encrypted, created_at)| AdminNote {
            id,
            owner_id,
            owner_username,
            content,
            is_encrypted,
            created_at: created_at.to_rfc3339(),
        })
        .collect();

    (StatusCode::OK, Json(serde_json::json!({ "notes": notes })))
}

pub async fn delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<i64>,
) -> (StatusCode, Json<serde_json::Value>) {
    let user = match authenticate(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    if !user.is_admin() {
        return json_error(StatusCode::FORBIDDEN, "Admin access required");
    }

    if user.user_id == user_id {
        return json_error(StatusCode::BAD_REQUEST, "Cannot delete yourself");
    }

    let mut tx = match state.db.pool.begin().await {
        Ok(tx) => tx,
        Err(error) => {
            tracing::error!(?error, "failed to begin transaction");
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    };

    if let Err(error) = sqlx::query("DELETE FROM note_permissions WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await
    {
        tracing::error!(?error, "failed to delete note permissions");
        let _ = tx.rollback().await;
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error");
    }

    if let Err(error) = sqlx::query("DELETE FROM direct_messages WHERE sender_id = $1 OR recipient_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await
    {
        tracing::error!(?error, "failed to delete messages");
        let _ = tx.rollback().await;
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error");
    }

    if let Err(error) = sqlx::query("DELETE FROM friend_requests WHERE requester_id = $1 OR recipient_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await
    {
        tracing::error!(?error, "failed to delete friend requests");
        let _ = tx.rollback().await;
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error");
    }

    if let Err(error) = sqlx::query(
        "DELETE FROM friends WHERE user_one_id = $1 OR user_two_id = $1",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await
    {
        tracing::error!(?error, "failed to delete friends");
        let _ = tx.rollback().await;
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error");
    }

    if let Err(error) = sqlx::query("DELETE FROM notes WHERE owner_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await
    {
        tracing::error!(?error, "failed to delete notes");
        let _ = tx.rollback().await;
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error");
    }

    if let Err(error) = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await
    {
        tracing::error!(?error, "failed to delete user");
        let _ = tx.rollback().await;
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error");
    }

    if let Err(error) = tx.commit().await {
        tracing::error!(?error, "failed to commit transaction");
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Database error");
    }

    tracing::info!(admin_id = user.user_id, deleted_user_id = user_id, "user deleted");
    (StatusCode::OK, Json(serde_json::json!({ "message": "User deleted" })))
}
