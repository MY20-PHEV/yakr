//! Relay abuse-limit tests mirroring Python `test_phase9_relay_abuse.py`.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;
use yakr_relay::{create_app, BlobStore};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn store_payload(tag: &[u8], expires_at: Option<u64>, ciphertext: &[u8]) -> serde_json::Value {
    json!({
        "mailbox_tag": yakr_relay::store::b64encode(tag),
        "expires_at": expires_at.unwrap_or(now_ms() + 60_000),
        "ciphertext": yakr_relay::store::b64encode(ciphertext),
    })
}

#[tokio::test]
async fn relay_rejects_short_mailbox_tag() {
    let dir = tempfile::tempdir().unwrap();
    let store = BlobStore::new(dir.path(), 64 * 1024, 3);
    let app = create_app(store, "test");
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/blobs")
                .header("content-type", "application/json")
                .body(Body::from(store_payload(b"short", None, b"x").to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn relay_rejects_expired_blob() {
    let dir = tempfile::tempdir().unwrap();
    let store = BlobStore::new(dir.path(), 64 * 1024, 3);
    let app = create_app(store, "test");
    let tag = [1u8; 32];
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/blobs")
                .header("content-type", "application/json")
                .body(Body::from(
                    store_payload(&tag, Some(now_ms().saturating_sub(1)), b"x").to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn relay_enforces_per_tag_blob_cap() {
    let dir = tempfile::tempdir().unwrap();
    let store = BlobStore::new(dir.path(), 64 * 1024, 3);
    let app = create_app(store, "test");
    let tag = [3u8; 32];
    for _ in 0..3 {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/blobs")
                    .header("content-type", "application/json")
                    .body(Body::from(store_payload(&tag, None, b"x").to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
    }
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/blobs")
                .header("content-type", "application/json")
                .body(Body::from(store_payload(&tag, None, b"x").to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
}
