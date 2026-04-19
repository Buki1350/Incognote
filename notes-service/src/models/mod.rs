//! Models for notes service requests/responses.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct CreateNoteRequest {
    pub content: String,
    #[serde(default)]
    pub is_encrypted: bool,
    pub private_key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateNoteRequest {
    pub content: String,
    #[serde(default)]
    pub is_encrypted: bool,
    pub private_key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ShareNoteRequest {
    pub note_id: i64,
    pub recipient: String,
    pub permission: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthUser {
    pub user_id: i64,
    pub username: String,
    pub role: String,
}

impl AuthUser {
    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }
}

#[derive(Debug, Serialize)]
pub struct NoteResponse {
    pub id: i64,
    pub owner_id: i64,
    pub content: String,
    pub is_encrypted: bool,
    pub created_at: DateTime<Utc>,
    pub permission: String,
    pub can_edit: bool,
}

#[derive(Debug, Deserialize)]
pub struct NotesQuery {
    pub private_key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AddFriendRequest {
    pub identifier: String,
}

#[derive(Debug, Serialize)]
pub struct FriendResponse {
    pub user_id: i64,
    pub username: String,
}

#[derive(Debug, Serialize)]
pub struct FriendInviteResponse {
    pub request_id: i64,
    pub direction: String,
    pub status: String,
    pub requester_username: String,
    pub recipient_username: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct SendMessageRequest {
    pub recipient: String,
    pub content: String,
    pub private_key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListMessagesQuery {
    pub private_key: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub id: i64,
    pub sender_id: i64,
    pub sender_username: String,
    pub recipient_id: i64,
    pub recipient_username: String,
    pub direction: String,
    pub content: String,
    pub encrypted_with_private_key: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub message: String,
}
