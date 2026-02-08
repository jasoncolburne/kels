//! HTTP server for ready status endpoint.
//!
//! Exposes a `/ready` endpoint that other gossip nodes can query to determine
//! if this node is ready to sync KELs from.

use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};

/// Shared ready state
pub type SharedReadyState = Arc<RwLock<bool>>;

/// Response from the /ready endpoint
#[derive(Serialize)]
pub struct ReadyResponse {
    pub ready: bool,
}

/// GET /ready handler
async fn ready_handler(
    State(ready_state): State<SharedReadyState>,
) -> (StatusCode, Json<ReadyResponse>) {
    let ready = *ready_state.read().await;
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(ReadyResponse { ready }))
}

/// Create the HTTP router for the ready endpoint
pub fn create_router(ready_state: SharedReadyState) -> Router {
    Router::new()
        .route("/ready", get(ready_handler))
        .with_state(ready_state)
}

/// Run the HTTP server for ready status
pub async fn run_http_server(addr: std::net::SocketAddr, ready_state: SharedReadyState) {
    let app = create_router(ready_state);

    info!("Starting HTTP server on {}", addr);

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind HTTP server: {}", e);
            return;
        }
    };

    if let Err(e) = axum::serve(listener, app).await {
        error!("HTTP server error: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_ready_endpoint_not_ready() {
        let ready_state = Arc::new(RwLock::new(false));
        let app = create_router(ready_state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_ready_endpoint_ready() {
        let ready_state = Arc::new(RwLock::new(true));
        let app = create_router(ready_state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
