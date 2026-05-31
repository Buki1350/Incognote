use crate::{
    app_state::AppState,
    models::{ListMessagesQuery, MessageResponse, SendMessageRequest},
    services::{sanitize_note_content, EncryptionService},
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use super::helpers::{are_friends, authenticate, json_error, lookup_user_by_identifier, normalize_private_key};

#[derive(Debug, sqlx::FromRow)]
struct MessageRow {
    id: i64,
    sender_id: i64,
    sender_username: String,
    recipient_id: i64,
    recipient_username: String,
    content: String,
    is_private_encrypted: bool,
    created_at: chrono::DateTime<chrono::Utc>,
}

pub async fn send_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<SendMessageRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let user = match authenticate(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let recipient = payload.recipient.trim().to_lowercase();
    if recipient.is_empty() || recipient.len() > 254 {
        return json_error(StatusCode::BAD_REQUEST, "Invalid recipient identifier");
    }
    if let Err(message) = validate_message_content(&payload.content) {
        return json_error(StatusCode::BAD_REQUEST, message);
    }

    let target = match lookup_user_by_identifier(&state, &recipient).await {
        Ok(Some(target)) => target,
        Ok(None) => return json_error(StatusCode::NOT_FOUND, "Recipient not found"),
        Err(error) => {
            tracing::error!(?error, actor_user_id = user.user_id, "failed to lookup message recipient");
            return json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable");
        }
    };

    if target.user_id == user.user_id {
        return json_error(StatusCode::BAD_REQUEST, "Cannot send message to yourself");
    }

    let friendship = match are_friends(&state, user.user_id, target.user_id).await {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(?error, actor_user_id = user.user_id, target_user_id = target.user_id, "friendship check failed");
            return json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable");
        }
    };
    if !friendship {
        return json_error(StatusCode::FORBIDDEN, "Recipient must be in your friends list");
    }

    let private_key = match normalize_private_key(payload.private_key.as_deref()) {
        Ok(value) => value,
        Err(message) => return json_error(StatusCode::BAD_REQUEST, message),
    };

    let sanitized = sanitize_note_content(payload.content.trim());
    let (stored_content, is_private_encrypted) = if let Some(key) = private_key {
        match EncryptionService::encrypt_with_passphrase(key, &sanitized) {
            Ok(encrypted) => (encrypted, true),
            Err(error) => {
                tracing::error!(?error, actor_user_id = user.user_id, "failed to encrypt message");
                return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to encrypt message");
            }
        }
    } else {
        (sanitized, false)
    };

    let inserted = sqlx::query_as::<_, (i64,)>(
        r#"
        INSERT INTO direct_messages (sender_id, recipient_id, content, is_private_encrypted)
        VALUES ($1, $2, $3, $4)
        RETURNING id
        "#,
    )
    .bind(user.user_id)
    .bind(target.user_id)
    .bind(stored_content)
    .bind(is_private_encrypted)
    .fetch_one(&state.db.pool)
    .await;

    match inserted {
        Ok((message_id,)) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "message": "Message sent",
                "id": message_id
            })),
        ),
        Err(error) => {
            tracing::error!(?error, actor_user_id = user.user_id, target_user_id = target.user_id, "failed to send message");
            json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
        }
    }
}

pub async fn list_messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListMessagesQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    let user = match authenticate(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let private_key = match normalize_private_key(query.private_key.as_deref()) {
        Ok(value) => value,
        Err(message) => return json_error(StatusCode::BAD_REQUEST, message),
    };

    let rows = sqlx::query_as::<_, MessageRow>(
        r#"
        SELECT
            m.id,
            m.sender_id,
            sender.username AS sender_username,
            m.recipient_id,
            recipient.username AS recipient_username,
            m.content,
            m.is_private_encrypted,
            m.created_at
        FROM direct_messages m
        JOIN users sender ON sender.id = m.sender_id
        JOIN users recipient ON recipient.id = m.recipient_id
        WHERE m.sender_id = $1 OR m.recipient_id = $1
        ORDER BY m.created_at DESC
        LIMIT 200
        "#,
    )
    .bind(user.user_id)
    .fetch_all(&state.db.pool)
    .await;

    match rows {
        Ok(rows) => {
            let messages = rows
                .into_iter()
                .map(|row| {
                    let decrypted_content = if row.is_private_encrypted {
                        match private_key {
                            Some(key) => {
                                EncryptionService::decrypt_with_passphrase(key, &row.content)
                                    .unwrap_or_else(|_| "[encrypted message: invalid private key]".to_string())
                            }
                            None => "[encrypted message: provide private key]".to_string(),
                        }
                    } else {
                        row.content
                    };

                    MessageResponse {
                        id: row.id,
                        sender_id: row.sender_id,
                        sender_username: row.sender_username,
                        recipient_id: row.recipient_id,
                        recipient_username: row.recipient_username,
                        direction: if row.sender_id == user.user_id {
                            "sent".to_string()
                        } else {
                            "received".to_string()
                        },
                        content: decrypted_content,
                        encrypted_with_private_key: row.is_private_encrypted,
                        created_at: row.created_at,
                    }
                })
                .collect::<Vec<_>>();

            (StatusCode::OK, Json(serde_json::json!({ "messages": messages })))
        }
        Err(error) => {
            tracing::error!(?error, user_id = user.user_id, "failed to list messages");
            json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
        }
    }
}

pub async fn delete_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(message_id): Path<i64>,
) -> (StatusCode, Json<serde_json::Value>) {
    let user = match authenticate(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let row = sqlx::query_as::<_, (i64, i64)>(
        r#"
        SELECT sender_id, recipient_id
        FROM direct_messages
        WHERE id = $1
        "#,
    )
    .bind(message_id)
    .fetch_optional(&state.db.pool)
    .await;

    let Some((sender_id, recipient_id)) = (match row {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(?error, user_id = user.user_id, message_id, "message lookup failed");
            return json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable");
        }
    }) else {
        return json_error(StatusCode::NOT_FOUND, "Message not found");
    };

    if user.user_id != sender_id && user.user_id != recipient_id {
        return json_error(StatusCode::FORBIDDEN, "Not a participant of this message");
    }

    if let Err(error) = sqlx::query("DELETE FROM direct_messages WHERE id = $1")
        .bind(message_id)
        .execute(&state.db.pool)
        .await
    {
        tracing::error!(?error, user_id = user.user_id, message_id, "failed to delete message");
        return json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable");
    }

    tracing::info!(user_id = user.user_id, message_id, "message deleted");
    (StatusCode::OK, Json(serde_json::json!({ "message": "Message deleted" })))
}

fn validate_message_content(content: &str) -> Result<(), &'static str> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err("Message content cannot be empty");
    }
    if trimmed.len() > 5000 {
        return Err("Message content cannot exceed 5000 characters");
    }
    Ok(())
}
