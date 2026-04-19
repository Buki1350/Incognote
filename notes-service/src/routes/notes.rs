//! Note CRUD/share endpoints with permission checks and fail-safe auth validation.

use crate::{
    app_state::AppState,
    models::{
        AddFriendRequest, AuthUser, CreateNoteRequest, ErrorResponse, FriendInviteResponse,
        FriendResponse, ListMessagesQuery, MessageResponse, NoteResponse, NotesQuery,
        SendMessageRequest, ShareNoteRequest, UpdateNoteRequest,
    },
    services::{sanitize_note_content, AuthError, EncryptionService},
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::{DateTime, Utc};

#[derive(Debug, sqlx::FromRow)]
struct NoteRow {
    id: i64,
    owner_id: i64,
    content: String,
    is_encrypted: bool,
    created_at: DateTime<Utc>,
    permission: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct FriendRow {
    user_id: i64,
    username: String,
}

#[derive(Debug, sqlx::FromRow)]
struct UserLookupRow {
    user_id: i64,
}

#[derive(Debug, sqlx::FromRow)]
struct FriendInviteRow {
    request_id: i64,
    requester_username: String,
    recipient_id: i64,
    recipient_username: String,
    status: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
struct MessageRow {
    id: i64,
    sender_id: i64,
    sender_username: String,
    recipient_id: i64,
    recipient_username: String,
    content: String,
    is_private_encrypted: bool,
    created_at: DateTime<Utc>,
}

pub async fn list_notes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<NotesQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    let user = match authenticate(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let private_key = match normalize_private_key(query.private_key.as_deref()) {
        Ok(value) => value,
        Err(message) => return json_error(StatusCode::BAD_REQUEST, message),
    };

    let query_result = if user.is_admin() {
        sqlx::query_as::<_, NoteRow>(
            r#"
            SELECT id, owner_id, content, is_encrypted, created_at, NULL::TEXT as permission
            FROM notes
            ORDER BY created_at DESC
            "#,
        )
        .fetch_all(&state.db.pool)
        .await
    } else {
        sqlx::query_as::<_, NoteRow>(
            r#"
            SELECT n.id, n.owner_id, n.content, n.is_encrypted, n.created_at, np.permission
            FROM notes n
            LEFT JOIN note_permissions np
              ON np.note_id = n.id
             AND np.user_id = $1
            WHERE n.owner_id = $1 OR np.user_id = $1
            ORDER BY n.created_at DESC
            "#,
        )
        .bind(user.user_id)
        .fetch_all(&state.db.pool)
        .await
    };

    let rows = match query_result {
        Ok(rows) => rows,
        Err(error) => {
            tracing::error!(?error, user_id = user.user_id, "failed to list notes");
            return json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable");
        }
    };

    let notes = rows
        .into_iter()
        .map(|row| build_note_response(&state, &user, row, private_key))
        .collect::<Vec<_>>();

    tracing::info!(user_id = user.user_id, total = notes.len(), "notes listed");
    (StatusCode::OK, Json(serde_json::json!({ "notes": notes })))
}

pub async fn create_note(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateNoteRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let user = match authenticate(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    if let Err(message) = validate_note_content(&payload.content) {
        return json_error(StatusCode::BAD_REQUEST, message);
    }

    let private_key = match normalize_private_key(payload.private_key.as_deref()) {
        Ok(value) => value,
        Err(message) => return json_error(StatusCode::BAD_REQUEST, message),
    };

    let sanitized = sanitize_note_content(payload.content.trim());
    let (stored_content, is_encrypted) = if let Some(key) = private_key {
        match EncryptionService::encrypt_with_passphrase(key, &sanitized) {
            Ok(value) => (value, true),
            Err(error) => {
                tracing::error!(?error, user_id = user.user_id, "failed to encrypt note");
                return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to encrypt note");
            }
        }
    } else if payload.is_encrypted {
        // Backward-compatible fallback for old clients still using checkbox encryption.
        match state.encryption.encrypt(&sanitized) {
            Ok(value) => (value, true),
            Err(error) => {
                tracing::error!(?error, user_id = user.user_id, "failed to encrypt note");
                return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to encrypt note");
            }
        }
    } else {
        (sanitized, false)
    };

    let created = sqlx::query_as::<_, (i64,)>(
        r#"
        INSERT INTO notes (owner_id, content, is_encrypted)
        VALUES ($1, $2, $3)
        RETURNING id
        "#,
    )
    .bind(user.user_id)
    .bind(stored_content)
    .bind(is_encrypted)
    .fetch_one(&state.db.pool)
    .await;

    match created {
        Ok((id,)) => {
            tracing::info!(
                user_id = user.user_id,
                note_id = id,
                is_encrypted,
                "note created"
            );
            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "message": "Note created",
                    "id": id
                })),
            )
        }
        Err(error) => {
            tracing::error!(?error, user_id = user.user_id, "failed to create note");
            json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
        }
    }
}

pub async fn get_note(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(note_id): Path<i64>,
    Query(query): Query<NotesQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    let user = match authenticate(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let private_key = match normalize_private_key(query.private_key.as_deref()) {
        Ok(value) => value,
        Err(message) => return json_error(StatusCode::BAD_REQUEST, message),
    };

    let row = match load_note_for_user(&state, note_id, &user).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            tracing::warn!(
                user_id = user.user_id,
                note_id,
                "note access denied or not found"
            );
            return json_error(StatusCode::NOT_FOUND, "Note not found");
        }
        Err(error) => {
            tracing::error!(
                ?error,
                user_id = user.user_id,
                note_id,
                "failed to get note"
            );
            return json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable");
        }
    };

    tracing::info!(user_id = user.user_id, note_id, "note read");
    (
        StatusCode::OK,
        Json(
            serde_json::to_value(build_note_response(&state, &user, row, private_key))
                .unwrap_or_else(|_| serde_json::json!({ "message": "serialization error" })),
        ),
    )
}

pub async fn update_note(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(note_id): Path<i64>,
    Json(payload): Json<UpdateNoteRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let user = match authenticate(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    if let Err(message) = validate_note_content(&payload.content) {
        return json_error(StatusCode::BAD_REQUEST, message);
    }

    let private_key = match normalize_private_key(payload.private_key.as_deref()) {
        Ok(value) => value,
        Err(message) => return json_error(StatusCode::BAD_REQUEST, message),
    };

    let row = match load_note_for_user(&state, note_id, &user).await {
        Ok(Some(row)) => row,
        Ok(None) => return json_error(StatusCode::NOT_FOUND, "Note not found"),
        Err(error) => {
            tracing::error!(
                ?error,
                user_id = user.user_id,
                note_id,
                "failed to fetch note for update"
            );
            return json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable");
        }
    };

    if !can_edit(&user, row.owner_id, row.permission.as_deref()) {
        tracing::warn!(user_id = user.user_id, note_id, "update denied");
        return json_error(StatusCode::FORBIDDEN, "Write permission required");
    }

    let sanitized = sanitize_note_content(payload.content.trim());
    let (stored_content, is_encrypted) = if let Some(key) = private_key {
        match EncryptionService::encrypt_with_passphrase(key, &sanitized) {
            Ok(value) => (value, true),
            Err(error) => {
                tracing::error!(
                    ?error,
                    user_id = user.user_id,
                    note_id,
                    "failed to encrypt note on update"
                );
                return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to encrypt note");
            }
        }
    } else if payload.is_encrypted {
        match state.encryption.encrypt(&sanitized) {
            Ok(value) => (value, true),
            Err(error) => {
                tracing::error!(
                    ?error,
                    user_id = user.user_id,
                    note_id,
                    "failed to encrypt note on update"
                );
                return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to encrypt note");
            }
        }
    } else {
        (sanitized, false)
    };

    let updated = sqlx::query(
        r#"
        UPDATE notes
        SET content = $1, is_encrypted = $2
        WHERE id = $3
        "#,
    )
    .bind(stored_content)
    .bind(is_encrypted)
    .bind(note_id)
    .execute(&state.db.pool)
    .await;

    match updated {
        Ok(_) => {
            tracing::info!(
                user_id = user.user_id,
                note_id,
                is_encrypted,
                "note updated"
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({ "message": "Note updated" })),
            )
        }
        Err(error) => {
            tracing::error!(
                ?error,
                user_id = user.user_id,
                note_id,
                "note update failed"
            );
            json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
        }
    }
}

pub async fn delete_note(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(note_id): Path<i64>,
) -> (StatusCode, Json<serde_json::Value>) {
    let user = match authenticate(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    if !user.is_admin() {
        let owner = sqlx::query_as::<_, (i64,)>("SELECT owner_id FROM notes WHERE id = $1")
            .bind(note_id)
            .fetch_optional(&state.db.pool)
            .await;

        let Some((owner_id,)) = (match owner {
            Ok(value) => value,
            Err(error) => {
                tracing::error!(
                    ?error,
                    user_id = user.user_id,
                    note_id,
                    "owner check failed"
                );
                return json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable");
            }
        }) else {
            return json_error(StatusCode::NOT_FOUND, "Note not found");
        };

        if owner_id != user.user_id {
            tracing::warn!(user_id = user.user_id, note_id, "delete denied");
            return json_error(
                StatusCode::FORBIDDEN,
                "Only owner or admin can delete a note",
            );
        }
    }

    let deleted = sqlx::query("DELETE FROM notes WHERE id = $1")
        .bind(note_id)
        .execute(&state.db.pool)
        .await;

    match deleted {
        Ok(result) if result.rows_affected() == 0 => {
            json_error(StatusCode::NOT_FOUND, "Note not found")
        }
        Ok(_) => {
            tracing::info!(user_id = user.user_id, note_id, "note deleted");
            (
                StatusCode::OK,
                Json(serde_json::json!({ "message": "Note deleted" })),
            )
        }
        Err(error) => {
            tracing::error!(
                ?error,
                user_id = user.user_id,
                note_id,
                "note delete failed"
            );
            json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
        }
    }
}

pub async fn share_note(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ShareNoteRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let user = match authenticate(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let recipient_identifier = payload.recipient.trim().to_lowercase();
    if recipient_identifier.is_empty() || recipient_identifier.len() > 254 {
        return json_error(StatusCode::BAD_REQUEST, "Invalid recipient identifier");
    }

    if payload.permission != "read" && payload.permission != "write" {
        return json_error(StatusCode::BAD_REQUEST, "Permission must be read or write");
    }

    let owner = sqlx::query_as::<_, (i64,)>("SELECT owner_id FROM notes WHERE id = $1")
        .bind(payload.note_id)
        .fetch_optional(&state.db.pool)
        .await;

    let Some((owner_id,)) = (match owner {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(
                ?error,
                user_id = user.user_id,
                note_id = payload.note_id,
                "share owner lookup failed"
            );
            return json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable");
        }
    }) else {
        return json_error(StatusCode::NOT_FOUND, "Note not found");
    };

    if !user.is_admin() && owner_id != user.user_id {
        return json_error(StatusCode::FORBIDDEN, "Only owner or admin can share note");
    }

    let target_user =
        sqlx::query_as::<_, (i64,)>("SELECT id FROM users WHERE username = $1 OR email = $1")
            .bind(&recipient_identifier)
            .fetch_optional(&state.db.pool)
            .await;

    let Some((target_user_id,)) = (match target_user {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(
                ?error,
                user_id = user.user_id,
                recipient = %recipient_identifier,
                "share target lookup failed"
            );
            return json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable");
        }
    }) else {
        return json_error(StatusCode::NOT_FOUND, "Target user not found");
    };

    let saved = sqlx::query(
        r#"
        INSERT INTO note_permissions (note_id, user_id, permission)
        VALUES ($1, $2, $3)
        ON CONFLICT (note_id, user_id)
        DO UPDATE SET permission = EXCLUDED.permission
        "#,
    )
    .bind(payload.note_id)
    .bind(target_user_id)
    .bind(&payload.permission)
    .execute(&state.db.pool)
    .await;

    match saved {
        Ok(_) => {
            tracing::info!(
                actor_user_id = user.user_id,
                note_id = payload.note_id,
                target_user_id,
                permission = %payload.permission,
                "note shared"
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({ "message": "Note shared" })),
            )
        }
        Err(error) => {
            tracing::error!(
                ?error,
                actor_user_id = user.user_id,
                note_id = payload.note_id,
                "failed to share note"
            );
            json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
        }
    }
}

pub async fn add_friend(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<AddFriendRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let user = match authenticate(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let identifier = payload.identifier.trim().to_lowercase();
    if identifier.is_empty() || identifier.len() > 254 {
        return json_error(StatusCode::BAD_REQUEST, "Invalid friend identifier");
    }

    let target = match lookup_user_by_identifier(&state, &identifier).await {
        Ok(Some(target)) => target,
        Ok(None) => return json_error(StatusCode::NOT_FOUND, "User not found"),
        Err(error) => {
            tracing::error!(
                ?error,
                actor_user_id = user.user_id,
                "failed to lookup invite target"
            );
            return json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable");
        }
    };

    if target.user_id == user.user_id {
        return json_error(StatusCode::BAD_REQUEST, "Cannot invite yourself");
    }

    let already_friends = match are_friends(&state, user.user_id, target.user_id).await {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(
                ?error,
                actor_user_id = user.user_id,
                target_user_id = target.user_id,
                "friendship check failed"
            );
            return json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable");
        }
    };
    if already_friends {
        return json_error(StatusCode::CONFLICT, "User is already your friend");
    }

    let reverse_pending = sqlx::query_as::<_, (i64,)>(
        r#"
        SELECT id
        FROM friend_requests
        WHERE requester_id = $1
          AND recipient_id = $2
          AND status = 'pending'
        "#,
    )
    .bind(target.user_id)
    .bind(user.user_id)
    .fetch_optional(&state.db.pool)
    .await;

    match reverse_pending {
        Ok(Some(_)) => {
            return json_error(
                StatusCode::CONFLICT,
                "You already have an incoming invite from this user",
            );
        }
        Ok(None) => {}
        Err(error) => {
            tracing::error!(
                ?error,
                actor_user_id = user.user_id,
                target_user_id = target.user_id,
                "reverse invite check failed"
            );
            return json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable");
        }
    }

    let existing = sqlx::query_as::<_, (i64, String)>(
        r#"
        SELECT id, status
        FROM friend_requests
        WHERE requester_id = $1
          AND recipient_id = $2
        "#,
    )
    .bind(user.user_id)
    .bind(target.user_id)
    .fetch_optional(&state.db.pool)
    .await;

    let invite_id = match existing {
        Ok(Some((invite_id, status))) if status == "pending" => invite_id,
        Ok(Some((invite_id, status))) if status == "rejected" => {
            let updated = sqlx::query(
                r#"
                UPDATE friend_requests
                SET status = 'pending', updated_at = NOW()
                WHERE id = $1
                "#,
            )
            .bind(invite_id)
            .execute(&state.db.pool)
            .await;

            if let Err(error) = updated {
                tracing::error!(
                    ?error,
                    actor_user_id = user.user_id,
                    target_user_id = target.user_id,
                    "failed to re-open rejected invite"
                );
                return json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable");
            }

            invite_id
        }
        Ok(Some((_invite_id, _status))) => {
            return json_error(StatusCode::CONFLICT, "Invite already processed");
        }
        Ok(None) => {
            let inserted = sqlx::query_as::<_, (i64,)>(
                r#"
                INSERT INTO friend_requests (requester_id, recipient_id, status)
                VALUES ($1, $2, 'pending')
                RETURNING id
                "#,
            )
            .bind(user.user_id)
            .bind(target.user_id)
            .fetch_one(&state.db.pool)
            .await;

            match inserted {
                Ok((id,)) => id,
                Err(error) => {
                    tracing::error!(
                        ?error,
                        actor_user_id = user.user_id,
                        target_user_id = target.user_id,
                        "failed to create invite"
                    );
                    return json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable");
                }
            }
        }
        Err(error) => {
            tracing::error!(
                ?error,
                actor_user_id = user.user_id,
                target_user_id = target.user_id,
                "existing invite lookup failed"
            );
            return json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable");
        }
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "message": "Friend invite sent",
            "invite_id": invite_id
        })),
    )
}

pub async fn list_friends(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> (StatusCode, Json<serde_json::Value>) {
    let user = match authenticate(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let rows = sqlx::query_as::<_, FriendRow>(
        r#"
        SELECT
            u.id AS user_id,
            u.username
        FROM friends f
        JOIN users u
          ON u.id = CASE
              WHEN f.user_one_id = $1 THEN f.user_two_id
              ELSE f.user_one_id
          END
        WHERE f.user_one_id = $1 OR f.user_two_id = $1
        ORDER BY u.username ASC
        "#,
    )
    .bind(user.user_id)
    .fetch_all(&state.db.pool)
    .await;

    match rows {
        Ok(rows) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "friends": rows
                    .into_iter()
                    .map(|row| FriendResponse {
                        user_id: row.user_id,
                        username: row.username
                    })
                    .collect::<Vec<_>>()
            })),
        ),
        Err(error) => {
            tracing::error!(?error, user_id = user.user_id, "failed to list friends");
            json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
        }
    }
}

pub async fn list_friend_invites(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> (StatusCode, Json<serde_json::Value>) {
    let user = match authenticate(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let rows = sqlx::query_as::<_, FriendInviteRow>(
        r#"
        SELECT
            fr.id AS request_id,
            requester.username AS requester_username,
            fr.recipient_id,
            recipient.username AS recipient_username,
            fr.status,
            fr.created_at
        FROM friend_requests fr
        JOIN users requester ON requester.id = fr.requester_id
        JOIN users recipient ON recipient.id = fr.recipient_id
        WHERE (fr.requester_id = $1 OR fr.recipient_id = $1)
          AND fr.status = 'pending'
        ORDER BY fr.created_at DESC
        "#,
    )
    .bind(user.user_id)
    .fetch_all(&state.db.pool)
    .await;

    match rows {
        Ok(rows) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "invites": rows
                    .into_iter()
                    .map(|row| FriendInviteResponse {
                        request_id: row.request_id,
                        direction: if row.recipient_id == user.user_id {
                            "incoming".to_string()
                        } else {
                            "outgoing".to_string()
                        },
                        status: row.status,
                        requester_username: row.requester_username,
                        recipient_username: row.recipient_username,
                        created_at: row.created_at
                    })
                    .collect::<Vec<_>>()
            })),
        ),
        Err(error) => {
            tracing::error!(
                ?error,
                user_id = user.user_id,
                "failed to list friend invites"
            );
            json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
        }
    }
}

pub async fn accept_friend_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(request_id): Path<i64>,
) -> (StatusCode, Json<serde_json::Value>) {
    handle_friend_invite_action(state, headers, request_id, "accepted").await
}

pub async fn reject_friend_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(request_id): Path<i64>,
) -> (StatusCode, Json<serde_json::Value>) {
    handle_friend_invite_action(state, headers, request_id, "rejected").await
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
            tracing::error!(
                ?error,
                actor_user_id = user.user_id,
                "failed to lookup message recipient"
            );
            return json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable");
        }
    };

    if target.user_id == user.user_id {
        return json_error(StatusCode::BAD_REQUEST, "Cannot send message to yourself");
    }

    let friendship = match are_friends(&state, user.user_id, target.user_id).await {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(
                ?error,
                actor_user_id = user.user_id,
                target_user_id = target.user_id,
                "friendship check failed"
            );
            return json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable");
        }
    };
    if !friendship {
        return json_error(
            StatusCode::FORBIDDEN,
            "Recipient must be in your friends list",
        );
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
                tracing::error!(
                    ?error,
                    actor_user_id = user.user_id,
                    "failed to encrypt message"
                );
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to encrypt message",
                );
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
            tracing::error!(
                ?error,
                actor_user_id = user.user_id,
                target_user_id = target.user_id,
                "failed to send message"
            );
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
                                    .unwrap_or_else(|_| {
                                        "[encrypted message: invalid private key]".to_string()
                                    })
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

            (
                StatusCode::OK,
                Json(serde_json::json!({ "messages": messages })),
            )
        }
        Err(error) => {
            tracing::error!(?error, user_id = user.user_id, "failed to list messages");
            json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
        }
    }
}

async fn handle_friend_invite_action(
    state: AppState,
    headers: HeaderMap,
    request_id: i64,
    action: &str,
) -> (StatusCode, Json<serde_json::Value>) {
    let user = match authenticate(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let request = sqlx::query_as::<_, (i64, i64, String)>(
        r#"
        SELECT requester_id, recipient_id, status
        FROM friend_requests
        WHERE id = $1
        "#,
    )
    .bind(request_id)
    .fetch_optional(&state.db.pool)
    .await;

    let Some((requester_id, recipient_id, status)) = (match request {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(
                ?error,
                user_id = user.user_id,
                request_id,
                "invite lookup failed"
            );
            return json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable");
        }
    }) else {
        return json_error(StatusCode::NOT_FOUND, "Invite not found");
    };

    if recipient_id != user.user_id {
        return json_error(StatusCode::FORBIDDEN, "Only invite recipient can respond");
    }
    if status != "pending" {
        return json_error(StatusCode::BAD_REQUEST, "Invite is not pending");
    }

    let updated = sqlx::query(
        r#"
        UPDATE friend_requests
        SET status = $1, updated_at = NOW()
        WHERE id = $2
        "#,
    )
    .bind(action)
    .bind(request_id)
    .execute(&state.db.pool)
    .await;

    if let Err(error) = updated {
        tracing::error!(
            ?error,
            user_id = user.user_id,
            request_id,
            "invite update failed"
        );
        return json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable");
    }

    if action == "accepted" {
        let (user_one_id, user_two_id) = ordered_pair(requester_id, recipient_id);
        let inserted = sqlx::query(
            r#"
            INSERT INTO friends (user_one_id, user_two_id)
            VALUES ($1, $2)
            ON CONFLICT (user_one_id, user_two_id) DO NOTHING
            "#,
        )
        .bind(user_one_id)
        .bind(user_two_id)
        .execute(&state.db.pool)
        .await;

        if let Err(error) = inserted {
            tracing::error!(
                ?error,
                user_id = user.user_id,
                request_id,
                "friend create failed"
            );
            return json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable");
        }
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "message": if action == "accepted" {
                "Invite accepted"
            } else {
                "Invite rejected"
            }
        })),
    )
}

async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthUser, (StatusCode, Json<serde_json::Value>)> {
    let token = extract_bearer_token(headers)
        .ok_or_else(|| json_error(StatusCode::UNAUTHORIZED, "Missing bearer token"))?;

    state
        .auth_client
        .validate_token(&token)
        .await
        .map_err(|error| match error {
            AuthError::InvalidToken => json_error(StatusCode::UNAUTHORIZED, "Invalid token"),
            AuthError::ServiceUnavailable => {
                tracing::warn!("auth service unavailable; denying request");
                json_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Authentication service unavailable",
                )
            }
        })
}

async fn load_note_for_user(
    state: &AppState,
    note_id: i64,
    user: &AuthUser,
) -> Result<Option<NoteRow>, sqlx::Error> {
    if user.is_admin() {
        return sqlx::query_as::<_, NoteRow>(
            r#"
            SELECT id, owner_id, content, is_encrypted, created_at, NULL::TEXT as permission
            FROM notes
            WHERE id = $1
            "#,
        )
        .bind(note_id)
        .fetch_optional(&state.db.pool)
        .await;
    }

    sqlx::query_as::<_, NoteRow>(
        r#"
        SELECT n.id, n.owner_id, n.content, n.is_encrypted, n.created_at, np.permission
        FROM notes n
        LEFT JOIN note_permissions np
          ON np.note_id = n.id
         AND np.user_id = $2
        WHERE n.id = $1
          AND (n.owner_id = $2 OR np.user_id = $2)
        "#,
    )
    .bind(note_id)
    .bind(user.user_id)
    .fetch_optional(&state.db.pool)
    .await
}

fn build_note_response(
    state: &AppState,
    user: &AuthUser,
    row: NoteRow,
    private_key: Option<&str>,
) -> NoteResponse {
    let content = if row.is_encrypted {
        decrypt_note_content(state, &row.content, private_key)
    } else {
        row.content
    };

    let permission = permission_label(user, row.owner_id, row.permission.as_deref()).to_string();
    let can_edit = can_edit(user, row.owner_id, row.permission.as_deref());

    NoteResponse {
        id: row.id,
        owner_id: row.owner_id,
        content,
        is_encrypted: row.is_encrypted,
        created_at: row.created_at,
        permission,
        can_edit,
    }
}

fn decrypt_note_content(state: &AppState, encrypted: &str, private_key: Option<&str>) -> String {
    if let Some(key) = private_key {
        if let Ok(content) = EncryptionService::decrypt_with_passphrase(key, encrypted) {
            return content;
        }
    }

    state
        .encryption
        .decrypt(encrypted)
        .unwrap_or_else(|_| "[encrypted content unavailable]".to_string())
}

fn can_edit(user: &AuthUser, owner_id: i64, permission: Option<&str>) -> bool {
    user.is_admin() || owner_id == user.user_id || permission == Some("write")
}

fn permission_label<'a>(user: &'a AuthUser, owner_id: i64, permission: Option<&'a str>) -> &'a str {
    if user.is_admin() {
        "admin"
    } else if owner_id == user.user_id {
        "owner"
    } else {
        permission.unwrap_or("read")
    }
}

fn validate_note_content(content: &str) -> Result<(), &'static str> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err("Note content cannot be empty");
    }
    if trimmed.len() > 5000 {
        return Err("Note content cannot exceed 5000 characters");
    }
    Ok(())
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

fn ordered_pair(a: i64, b: i64) -> (i64, i64) {
    if a < b {
        (a, b)
    } else {
        (b, a)
    }
}

fn normalize_private_key<'a>(value: Option<&'a str>) -> Result<Option<&'a str>, &'static str> {
    let key = value.map(str::trim).filter(|value| !value.is_empty());
    if let Some(value) = key {
        if value.len() < 8 || value.len() > 256 {
            return Err("Private key must be 8-256 characters long");
        }
    }
    Ok(key)
}

async fn lookup_user_by_identifier(
    state: &AppState,
    identifier: &str,
) -> Result<Option<UserLookupRow>, sqlx::Error> {
    sqlx::query_as::<_, UserLookupRow>(
        r#"
        SELECT id AS user_id
        FROM users
        WHERE username = $1 OR email = $1
        "#,
    )
    .bind(identifier)
    .fetch_optional(&state.db.pool)
    .await
}

async fn are_friends(
    state: &AppState,
    user_id: i64,
    other_user_id: i64,
) -> Result<bool, sqlx::Error> {
    let (user_one_id, user_two_id) = ordered_pair(user_id, other_user_id);

    sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM friends
            WHERE user_one_id = $1 AND user_two_id = $2
        )
        "#,
    )
    .bind(user_one_id)
    .bind(user_two_id)
    .fetch_one(&state.db.pool)
    .await
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(ToOwned::to_owned)
}

fn json_error(status: StatusCode, message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        status,
        Json(
            serde_json::to_value(ErrorResponse {
                message: message.to_string(),
            })
            .unwrap_or_else(|_| serde_json::json!({ "message": message })),
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::{can_edit, normalize_private_key, validate_note_content};
    use crate::models::AuthUser;

    #[test]
    fn admin_can_edit_everything() {
        let admin = AuthUser {
            user_id: 1,
            username: "root".to_string(),
            role: "admin".to_string(),
        };
        assert!(can_edit(&admin, 999, None));
    }

    #[test]
    fn write_permission_can_edit() {
        let user = AuthUser {
            user_id: 10,
            username: "alice".to_string(),
            role: "user".to_string(),
        };
        assert!(can_edit(&user, 20, Some("write")));
        assert!(!can_edit(&user, 20, Some("read")));
    }

    #[test]
    fn content_validation_enforces_limits() {
        assert!(validate_note_content("  ").is_err());
        assert!(validate_note_content("ok").is_ok());
        assert!(validate_note_content(&"x".repeat(5001)).is_err());
    }

    #[test]
    fn private_key_validation_works() {
        assert!(normalize_private_key(Some("short")).is_err());
        assert!(normalize_private_key(Some("validkey123")).is_ok());
        assert!(normalize_private_key(Some("   ")).is_ok());
    }
}
