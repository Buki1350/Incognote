use crate::{
    app_state::AppState,
    models::{AuthUser, CreateNoteRequest, NoteResponse, NotesQuery, ShareNoteRequest, UpdateNoteRequest},
    services::{sanitize_note_content, EncryptionService},
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::{DateTime, Utc};
use super::helpers::{are_friends, authenticate, json_error, lookup_user_by_identifier, normalize_private_key, validate_note_content};

#[derive(Debug, sqlx::FromRow)]
struct NoteRow {
    id: i64,
    owner_id: i64,
    content: String,
    is_encrypted: bool,
    created_at: DateTime<Utc>,
    permission: Option<String>,
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
            tracing::info!(user_id = user.user_id, note_id = id, is_encrypted, "note created");
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
            tracing::warn!(user_id = user.user_id, note_id, "note access denied or not found");
            return json_error(StatusCode::NOT_FOUND, "Note not found");
        }
        Err(error) => {
            tracing::error!(?error, user_id = user.user_id, note_id, "failed to get note");
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
            tracing::error!(?error, user_id = user.user_id, note_id, "failed to fetch note for update");
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
                tracing::error!(?error, user_id = user.user_id, note_id, "failed to encrypt note on update");
                return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to encrypt note");
            }
        }
    } else if payload.is_encrypted {
        match state.encryption.encrypt(&sanitized) {
            Ok(value) => (value, true),
            Err(error) => {
                tracing::error!(?error, user_id = user.user_id, note_id, "failed to encrypt note on update");
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
            tracing::info!(user_id = user.user_id, note_id, is_encrypted, "note updated");
            (
                StatusCode::OK,
                Json(serde_json::json!({ "message": "Note updated" })),
            )
        }
        Err(error) => {
            tracing::error!(?error, user_id = user.user_id, note_id, "note update failed");
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
                tracing::error!(?error, user_id = user.user_id, note_id, "owner check failed");
                return json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable");
            }
        }) else {
            return json_error(StatusCode::NOT_FOUND, "Note not found");
        };

        if owner_id != user.user_id {
            tracing::warn!(user_id = user.user_id, note_id, "delete denied");
            return json_error(StatusCode::FORBIDDEN, "Only owner or admin can delete a note");
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
            (StatusCode::OK, Json(serde_json::json!({ "message": "Note deleted" })))
        }
        Err(error) => {
            tracing::error!(?error, user_id = user.user_id, note_id, "note delete failed");
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
            tracing::error!(?error, user_id = user.user_id, note_id = payload.note_id, "share owner lookup failed");
            return json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable");
        }
    }) else {
        return json_error(StatusCode::NOT_FOUND, "Note not found");
    };

    if !user.is_admin() && owner_id != user.user_id {
        return json_error(StatusCode::FORBIDDEN, "Only owner or admin can share note");
    }

    let target_user = match lookup_user_by_identifier(&state, &recipient_identifier).await {
        Ok(Some(target)) => target,
        Ok(None) => return json_error(StatusCode::NOT_FOUND, "Target user not found"),
        Err(error) => {
            tracing::error!(?error, user_id = user.user_id, recipient = %recipient_identifier, "share target lookup failed");
            return json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable");
        }
    };

    let friendship = match are_friends(&state, user.user_id, target_user.user_id).await {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(?error, user_id = user.user_id, target_user_id = target_user.user_id, "friendship check failed");
            return json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable");
        }
    };

    if !friendship {
        return json_error(StatusCode::FORBIDDEN, "Recipient must be in your friends list");
    }

    let saved = sqlx::query(
        r#"
        INSERT INTO note_permissions (note_id, user_id, permission)
        VALUES ($1, $2, $3)
        ON CONFLICT (note_id, user_id)
        DO UPDATE SET permission = EXCLUDED.permission
        "#,
    )
    .bind(payload.note_id)
    .bind(target_user.user_id)
    .bind(&payload.permission)
    .execute(&state.db.pool)
    .await;

    match saved {
        Ok(_) => {
            tracing::info!(actor_user_id = user.user_id, note_id = payload.note_id, target_user_id = target_user.user_id, permission = %payload.permission, "note shared");
            (StatusCode::OK, Json(serde_json::json!({ "message": "Note shared" })))
        }
        Err(error) => {
            tracing::error!(?error, actor_user_id = user.user_id, note_id = payload.note_id, "failed to share note");
            json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
        }
    }
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

#[cfg(test)]
mod tests {
    use super::can_edit;
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
        assert!(super::validate_note_content("  ").is_err());
        assert!(super::validate_note_content("ok").is_ok());
        assert!(super::validate_note_content(&"x".repeat(5001)).is_err());
    }

    #[test]
    fn private_key_validation_works() {
        assert!(super::normalize_private_key(Some("short")).is_err());
        assert!(super::normalize_private_key(Some("validkey123")).is_ok());
        assert!(super::normalize_private_key(Some("   ")).is_ok());
    }
}
