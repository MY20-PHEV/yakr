use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::store::{b64decode, b64encode, BlobStore};

#[derive(Clone)]
pub struct RelayState {
    pub store: Arc<BlobStore>,
    pub name: String,
}

#[derive(Deserialize)]
pub struct BlobStoreRequest {
    pub mailbox_tag: String,
    pub expires_at: u64,
    pub ciphertext: String,
}

#[derive(Serialize)]
pub struct BlobResponse {
    pub mailbox_tag: String,
    pub expires_at: u64,
    pub ciphertext: String,
    pub stored_at: u64,
}

pub fn create_app(store: BlobStore, name: impl Into<String>) -> Router {
    let state = RelayState {
        store: Arc::new(store),
        name: name.into(),
    };
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/blobs", post(store_blob))
        .route("/v1/blobs/{mailbox_tag}", get(fetch_blobs))
        .with_state(state)
}

async fn healthz(State(state): State<RelayState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "role": "mailbox",
        "name": state.name,
    }))
}

async fn store_blob(
    State(state): State<RelayState>,
    Json(request): Json<BlobStoreRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, String)> {
    let tag = b64decode(&request.mailbox_tag).map_err(|_| {
        (StatusCode::BAD_REQUEST, "invalid mailbox_tag".to_string())
    })?;
    let ciphertext = b64decode(&request.ciphertext).map_err(|_| {
        (StatusCode::BAD_REQUEST, "invalid ciphertext".to_string())
    })?;
    match state.store.store(&tag, request.expires_at, &ciphertext) {
        Ok(()) => Ok((
            StatusCode::CREATED,
            Json(serde_json::json!({ "status": "stored" })),
        )),
        Err(err) if err.contains("limit exceeded") => {
            Err((StatusCode::TOO_MANY_REQUESTS, err))
        }
        Err(err) => Err((StatusCode::BAD_REQUEST, err)),
    }
}

async fn fetch_blobs(
    State(state): State<RelayState>,
    Path(mailbox_tag): Path<String>,
) -> Result<Json<Vec<BlobResponse>>, (StatusCode, String)> {
    let tag = b64decode(&mailbox_tag)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid mailbox_tag".to_string()))?;
    let blobs = state
        .store
        .fetch(&tag)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok(Json(
        blobs
            .into_iter()
            .map(|blob| BlobResponse {
                mailbox_tag: b64encode(&blob.mailbox_tag),
                expires_at: blob.expires_at,
                ciphertext: b64encode(&blob.ciphertext),
                stored_at: blob.stored_at,
            })
            .collect(),
    ))
}
