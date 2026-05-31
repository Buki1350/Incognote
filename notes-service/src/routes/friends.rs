use crate::{
    app_state::AppState,
    models::{AddFriendRequest, FriendInviteResponse, FriendResponse},
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::{DateTime, Utc};
use super::helpers::{are_friends, authenticate, json_error, lookup_user_by_identifier, ordered_pair};

#[derive(Debug, sqlx::FromRow)]
struct FriendRow {
    user_id: i64,
    username: String,
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
            tracing::error!(?error, actor_user_id = user.user_id, "failed to lookup invite target");
            return json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable");
        }
    };

    if target.user_id == user.user_id {
        return json_error(StatusCode::BAD_REQUEST, "Cannot invite yourself");
    }

    let already_friends = match are_friends(&state, user.user_id, target.user_id).await {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(?error, actor_user_id = user.user_id, target_user_id = target.user_id, "friendship check failed");
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
            return json_error(StatusCode::CONFLICT, "You already have an incoming invite from this user");
        }
        Ok(None) => {}
        Err(error) => {
            tracing::error!(?error, actor_user_id = user.user_id, target_user_id = target.user_id, "reverse invite check failed");
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
                tracing::error!(?error, actor_user_id = user.user_id, target_user_id = target.user_id, "failed to re-open rejected invite");
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
                    tracing::error!(?error, actor_user_id = user.user_id, target_user_id = target.user_id, "failed to create invite");
                    return json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable");
                }
            }
        }
        Err(error) => {
            tracing::error!(?error, actor_user_id = user.user_id, target_user_id = target.user_id, "existing invite lookup failed");
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
            tracing::error!(?error, user_id = user.user_id, "failed to list friend invites");
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
            tracing::error!(?error, user_id = user.user_id, request_id, "invite lookup failed");
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
        tracing::error!(?error, user_id = user.user_id, request_id, "invite update failed");
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
            tracing::error!(?error, user_id = user.user_id, request_id, "friend create failed");
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
