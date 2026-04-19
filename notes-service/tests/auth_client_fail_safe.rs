use axum::{routing::post, Json, Router};
use incognote_notes::services::{AuthClient, AuthError};
use std::time::Duration;

#[tokio::test]
async fn auth_client_returns_invalid_on_invalid_token_payload() {
    async fn validate() -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "valid": false,
            "user_id": null,
            "username": null,
            "role": null
        }))
    }

    let app = Router::new().route("/validate-token", post(validate));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = AuthClient::new(format!("http://{}", addr), Duration::from_secs(2));
    let result = client.validate_token("fake").await;

    handle.abort();

    assert_eq!(result.unwrap_err(), AuthError::InvalidToken);
}

#[tokio::test]
async fn auth_client_fails_safe_when_auth_service_is_down() {
    let client = AuthClient::new("http://127.0.0.1:9".to_string(), Duration::from_millis(200));
    let result = client.validate_token("fake").await;

    assert_eq!(result.unwrap_err(), AuthError::ServiceUnavailable);
}
