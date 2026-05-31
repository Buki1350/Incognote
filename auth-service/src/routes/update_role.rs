use crate::app_state::AppState;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use super::{extract_bearer_token, json_error};

pub async fn update_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<i64>,
    Json(payload): Json<crate::models::UpdateRoleRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let Some(token) = extract_bearer_token(&headers) else {
        return json_error(StatusCode::UNAUTHORIZED, "Missing bearer token");
    };

    let claims = match state.jwt.validate_token(&token) {
        Ok(claims) => claims,
        Err(_) => return json_error(StatusCode::UNAUTHORIZED, "Invalid token"),
    };

    if claims.role != "admin" {
        return json_error(StatusCode::FORBIDDEN, "Admin role required");
    }

    if payload.role != "admin" && payload.role != "user" {
        return json_error(StatusCode::BAD_REQUEST, "Role must be admin or user");
    }

    let updated = sqlx::query(
        r#"
        UPDATE users
        SET role = $1
        WHERE id = $2
        "#,
    )
    .bind(&payload.role)
    .bind(user_id)
    .execute(&state.db.pool)
    .await;

    match updated {
        Ok(result) if result.rows_affected() == 0 => {
            json_error(StatusCode::NOT_FOUND, "User not found")
        }
        Ok(_) => {
            tracing::info!(admin_id = claims.sub, target_user_id = user_id, role = %payload.role, "role updated");
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "message": "Role updated",
                    "user_id": user_id,
                    "role": payload.role
                })),
            )
        }
        Err(error) => {
            tracing::error!(?error, target_user_id = user_id, "role update failed");
            json_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
        }
    }
}
