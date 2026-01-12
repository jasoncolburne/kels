#![allow(clippy::unwrap_used, clippy::expect_used, dead_code, unused_imports)]
//! Integration tests for KELS handlers
//!
//! Uses testcontainers to spin up a PostgreSQL instance for testing.
//!
//! NOTE: All tests are ignored because they require Redis testcontainer for ServerKelCache.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use cesr::Matter;
use http_body_util::BodyExt;
use kels_service::{KelsRepository, handlers::AppState};
use verifiable_storage::RepositoryConnection;

/// Re-create the router for tests (same as server::create_router)
fn create_router(state: std::sync::Arc<AppState>) -> Router {
    use axum::routing::{get, post};
    use kels_service::handlers;

    Router::new()
        .route("/health", get(handlers::health))
        .route("/api/kels/events", post(handlers::submit_events))
        .route("/api/kels/events/:said", get(handlers::get_event))
        .route("/api/kels/kel/:prefix", get(handlers::get_kel))
        .route(
            "/api/kels/kel/:prefix/since/:since_version",
            get(handlers::get_kel_since),
        )
        .with_state(state)
}
use kels::{BatchSubmitResponse, KeyEvent, KeyEventBuilder, KeyProvider, SignedKeyEvent};
use std::sync::Arc;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;
use tower::ServiceExt;

async fn setup_test_db() -> (
    testcontainers::ContainerAsync<Postgres>,
    Arc<KelsRepository>,
) {
    let container = Postgres::default()
        .start()
        .await
        .expect("Failed to start PostgreSQL container");

    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("Failed to get port");

    // Wait for PostgreSQL to be ready
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Connect to database
    let url = format!("postgres://postgres:postgres@localhost:{}/postgres", port);

    let repo = KelsRepository::connect(&url)
        .await
        .expect("Failed to connect to test database");

    repo.initialize()
        .await
        .expect("Failed to initialize tables");

    (container, Arc::new(repo))
}

fn create_test_app(_repo: Arc<KelsRepository>) -> Router {
    // These tests don't use Redis, so we can't use the stream cache
    // The handler tests focus on the PostgreSQL-based repository logic
    // For now, we skip tests that require the stream cache
    unimplemented!("Handler tests need refactoring to work with ServerKelCache")
}

// ==================== Health Check Tests ====================
// NOTE: These tests are currently ignored because they require Redis for ServerKelCache.
// TODO: Add Redis testcontainer support to enable these tests.

#[tokio::test]
#[ignore = "Requires Redis testcontainer for ServerKelCache"]
async fn test_health_endpoint() {
    let (_container, repo) = setup_test_db().await;
    let app = create_test_app(repo);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

// ==================== Submit Event Tests ====================

#[tokio::test]
#[ignore = "Requires Redis testcontainer for ServerKelCache"]
async fn test_submit_inception_event() {
    let (_container, repo) = setup_test_db().await;
    let app = create_test_app(repo);

    // Create a valid inception event
    let provider = KeyProvider::software();
    let mut builder = KeyEventBuilder::new(provider, None);
    let (event, signature) = builder.incept().await.unwrap();

    let public_key = event.public_key.clone().unwrap();
    let request = vec![SignedKeyEvent::new(
        event.clone(),
        public_key,
        signature.qb64(),
    )];

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/kels/events")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let batch_response: BatchSubmitResponse = serde_json::from_slice(&body).unwrap();

    assert!(batch_response.accepted);
    assert!(batch_response.diverged_at.is_none());
}

#[tokio::test]
#[ignore = "Requires Redis testcontainer for ServerKelCache"]
async fn test_submit_duplicate_inception_idempotent() {
    let (_container, repo) = setup_test_db().await;
    let app = create_test_app(repo.clone());

    // Create and submit first inception
    let provider = KeyProvider::software();
    let mut builder = KeyEventBuilder::new(provider, None);
    let (event, signature) = builder.incept().await.unwrap();

    let public_key = event.public_key.clone().unwrap();
    let request = vec![SignedKeyEvent::new(
        event.clone(),
        public_key,
        signature.qb64(),
    )];

    // First submission should succeed
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/kels/events")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Second submission with same event should be idempotent (accepted, skipped)
    let app2 = create_test_app(repo);
    let response = app2
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/kels/events")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // With the new batch API, resubmitting same event is idempotent
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
#[ignore = "Requires Redis testcontainer for ServerKelCache"]
async fn test_submit_interaction_event() {
    let (_container, repo) = setup_test_db().await;
    let app = create_test_app(repo.clone());

    // Create and submit inception first
    let provider = KeyProvider::software();
    let mut builder = KeyEventBuilder::new(provider, None);
    let (icp_event, icp_signature) = builder.incept().await.unwrap();

    let icp_public_key = icp_event.public_key.clone().unwrap();
    let icp_request = vec![SignedKeyEvent::new(
        icp_event.clone(),
        icp_public_key.clone(),
        icp_signature.qb64(),
    )];

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/kels/events")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&icp_request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Now create and submit an interaction event
    let (ixn_event, ixn_signature) = builder.interact("test_anchor_said").await.unwrap();

    let ixn_request = vec![SignedKeyEvent::new(
        ixn_event.clone(),
        icp_public_key, // ixn signed with same key as icp
        ixn_signature.qb64(),
    )];

    let app2 = create_test_app(repo);
    let response = app2
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/kels/events")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&ixn_request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let batch_response: BatchSubmitResponse = serde_json::from_slice(&body).unwrap();

    assert!(batch_response.accepted);
    assert!(batch_response.diverged_at.is_none());
}

#[tokio::test]
#[ignore = "Requires Redis testcontainer for ServerKelCache"]
async fn test_submit_rotation_event() {
    let (_container, repo) = setup_test_db().await;
    let app = create_test_app(repo.clone());

    // Create and submit inception first
    let provider = KeyProvider::software();
    let mut builder = KeyEventBuilder::new(provider, None);
    let (icp_event, icp_signature) = builder.incept().await.unwrap();

    let icp_public_key = icp_event.public_key.clone().unwrap();
    let icp_request = vec![SignedKeyEvent::new(
        icp_event.clone(),
        icp_public_key,
        icp_signature.qb64(),
    )];

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/kels/events")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&icp_request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Now create and submit a rotation event
    let (rot_event, rot_signature) = builder.rotate().await.unwrap();

    let rot_public_key = rot_event.public_key.clone().unwrap();
    let rot_request = vec![SignedKeyEvent::new(
        rot_event.clone(),
        rot_public_key,
        rot_signature.qb64(),
    )];

    let app2 = create_test_app(repo);
    let response = app2
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/kels/events")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&rot_request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let batch_response: BatchSubmitResponse = serde_json::from_slice(&body).unwrap();

    assert!(batch_response.accepted);
    assert!(batch_response.diverged_at.is_none());
}

#[tokio::test]
#[ignore = "Requires Redis testcontainer for ServerKelCache"]
async fn test_submit_event_after_decommission_rejected() {
    let (_container, repo) = setup_test_db().await;
    let app = create_test_app(repo.clone());

    // Create and submit inception
    let provider = KeyProvider::software();
    let mut builder = KeyEventBuilder::new(provider, None);
    let (icp_event, icp_signature) = builder.incept().await.unwrap();

    let icp_public_key = icp_event.public_key.clone().unwrap();
    let icp_request = vec![SignedKeyEvent::new(
        icp_event.clone(),
        icp_public_key,
        icp_signature.qb64(),
    )];

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/kels/events")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&icp_request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Submit decommission event (ror with both hashes None, dual signature)
    let _ = builder.decommission().await.unwrap();

    // Get the signed event from the builder (it has dual signatures)
    let decom_signed = builder.events().last().unwrap().clone();
    let decom_request = vec![decom_signed.clone()];

    let app2 = create_test_app(repo.clone());
    let response = app2
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/kels/events")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&decom_request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Now try to submit another event - should be rejected
    // Create a new provider and incept to get a valid signature capability
    let another_provider = KeyProvider::software();
    let mut another_builder = KeyEventBuilder::new(another_provider, None);
    let _ = another_builder.incept().await.unwrap(); // need to incept to have a valid key

    // Create a fake event that would be the next event after decommission
    let fake_event =
        KeyEvent::create_interaction(&decom_signed.event, "test_anchor".to_string()).unwrap();

    // Sign with the other provider's key
    let fake_signature = another_builder
        .sign(fake_event.said.as_bytes())
        .await
        .unwrap();

    // Use the other builder's public key to get a valid signature format
    let other_icp = another_builder.events().first().unwrap().event.clone();
    let fake_public_key = other_icp.public_key.clone().unwrap();
    let fake_request = vec![SignedKeyEvent::new(
        fake_event,
        fake_public_key,
        fake_signature.qb64(),
    )];

    let app3 = create_test_app(repo);
    let response = app3
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/kels/events")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&fake_request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be rejected because KEL is decommissioned (merge() will handle this)
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[ignore = "Requires Redis testcontainer for ServerKelCache"]
async fn test_submit_event_invalid_signature_format() {
    let (_container, repo) = setup_test_db().await;
    let app = create_test_app(repo);

    // Create a valid inception event but with invalid signature format
    let provider = KeyProvider::software();
    let mut builder = KeyEventBuilder::new(provider, None);
    let (event, _signature) = builder.incept().await.unwrap();

    let public_key = event.public_key.clone().unwrap();
    let request = vec![SignedKeyEvent::new(
        event,
        public_key,
        "not_a_valid_qb64_signature".to_string(),
    )];

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/kels/events")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[ignore = "Requires Redis testcontainer for ServerKelCache"]
async fn test_submit_event_wrong_signature() {
    let (_container, repo) = setup_test_db().await;
    let app = create_test_app(repo);

    // Create an inception event
    let provider1 = KeyProvider::software();
    let mut builder1 = KeyEventBuilder::new(provider1, None);
    let (event, _) = builder1.incept().await.unwrap();

    // Create a second builder and incept to get a valid key for signing
    let provider2 = KeyProvider::software();
    let mut builder2 = KeyEventBuilder::new(provider2, None);
    let _ = builder2.incept().await.unwrap(); // need to incept to have a valid key

    // Sign the first event with the second key (wrong key)
    let wrong_signature = builder2.sign(event.said.as_bytes()).await.unwrap();

    // Use the event's public_key (which won't match the wrong_signature's key)
    let public_key = event.public_key.clone().unwrap();
    let request = vec![SignedKeyEvent::new(
        event,
        public_key,
        wrong_signature.qb64(),
    )];

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/kels/events")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should fail KEL verification (signature doesn't match the public key in the event)
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ==================== Get KEL Tests ====================

#[tokio::test]
#[ignore = "Requires Redis testcontainer for ServerKelCache"]
async fn test_get_kel() {
    let (_container, repo) = setup_test_db().await;
    let app = create_test_app(repo.clone());

    // Create and submit some events
    let provider = KeyProvider::software();
    let mut builder = KeyEventBuilder::new(provider, None);
    let (icp_event, icp_signature) = builder.incept().await.unwrap();
    let (ixn_event, ixn_signature) = builder.interact("anchor1").await.unwrap();

    // Submit inception
    let icp_public_key = icp_event.public_key.clone().unwrap();
    let icp_request = vec![SignedKeyEvent::new(
        icp_event.clone(),
        icp_public_key.clone(),
        icp_signature.qb64(),
    )];
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/kels/events")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&icp_request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Submit interaction
    let ixn_request = vec![SignedKeyEvent::new(
        ixn_event.clone(),
        icp_public_key, // ixn signed with same key as icp
        ixn_signature.qb64(),
    )];
    let app2 = create_test_app(repo.clone());
    app2.oneshot(
        Request::builder()
            .method("POST")
            .uri("/api/kels/events")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&ixn_request).unwrap()))
            .unwrap(),
    )
    .await
    .unwrap();

    // Get the KEL
    let app3 = create_test_app(repo);
    let response = app3
        .oneshot(
            Request::builder()
                .uri(format!("/api/kels/kel/{}", icp_event.prefix))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let kel: Vec<SignedKeyEvent> = serde_json::from_slice(&body).unwrap();

    assert_eq!(kel.len(), 2);
    assert_eq!(kel[0].event.said, icp_event.said);
    assert_eq!(kel[1].event.said, ixn_event.said);
}

#[tokio::test]
#[ignore = "Requires Redis testcontainer for ServerKelCache"]
async fn test_get_kel_not_found() {
    let (_container, repo) = setup_test_db().await;
    let app = create_test_app(repo);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/kels/kel/nonexistent_prefix")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ==================== Get Event Tests ====================

#[tokio::test]
#[ignore = "Requires Redis testcontainer for ServerKelCache"]
async fn test_get_event_by_said() {
    let (_container, repo) = setup_test_db().await;
    let app = create_test_app(repo.clone());

    // Create and submit an event
    let provider = KeyProvider::software();
    let mut builder = KeyEventBuilder::new(provider, None);
    let (event, signature) = builder.incept().await.unwrap();

    let public_key = event.public_key.clone().unwrap();
    let request = vec![SignedKeyEvent::new(
        event.clone(),
        public_key.clone(),
        signature.qb64(),
    )];

    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/kels/events")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Get the event by SAID
    let app2 = create_test_app(repo);
    let response = app2
        .oneshot(
            Request::builder()
                .uri(format!("/api/kels/events/{}", event.said))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let signed_event: SignedKeyEvent = serde_json::from_slice(&body).unwrap();

    assert_eq!(signed_event.event.said, event.said);
    let sig = signed_event.signature(&public_key).unwrap();
    assert_eq!(sig.signature, signature.qb64());
}

#[tokio::test]
#[ignore = "Requires Redis testcontainer for ServerKelCache"]
async fn test_get_event_not_found() {
    let (_container, repo) = setup_test_db().await;
    let app = create_test_app(repo);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/kels/events/nonexistent_said")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ==================== Delegated KEL Tests ====================

#[tokio::test]
#[ignore = "Requires Redis testcontainer for ServerKelCache"]
async fn test_submit_delegated_inception() {
    let (_container, repo) = setup_test_db().await;
    let app = create_test_app(repo);

    // Create a delegated inception event
    let provider = KeyProvider::software();
    let mut builder = KeyEventBuilder::new(provider, None);
    let (event, signature) = builder
        .incept_delegated("Efake_delegating_prefix")
        .await
        .unwrap();

    let public_key = event.public_key.clone().unwrap();
    let request = vec![SignedKeyEvent::new(
        event.clone(),
        public_key,
        signature.qb64(),
    )];

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/kels/events")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let batch_response: BatchSubmitResponse = serde_json::from_slice(&body).unwrap();

    assert!(batch_response.accepted);
}

// ==================== Chain Linkage Tests ====================

#[tokio::test]
#[ignore = "Requires Redis testcontainer for ServerKelCache"]
async fn test_event_with_wrong_previous_rejected() {
    let (_container, repo) = setup_test_db().await;
    let app = create_test_app(repo.clone());

    // Create and submit inception
    let provider = KeyProvider::software();
    let mut builder = KeyEventBuilder::new(provider, None);
    let (icp_event, icp_signature) = builder.incept().await.unwrap();

    let icp_public_key = icp_event.public_key.clone().unwrap();
    let icp_request = vec![SignedKeyEvent::new(
        icp_event.clone(),
        icp_public_key.clone(),
        icp_signature.qb64(),
    )];

    app.oneshot(
        Request::builder()
            .method("POST")
            .uri("/api/kels/events")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&icp_request).unwrap()))
            .unwrap(),
    )
    .await
    .unwrap();

    // Create an interaction event with wrong previous reference
    let mut bad_event = KeyEvent::create_interaction(&icp_event, "anchor".to_string()).unwrap();
    bad_event.previous = Some("wrong_said".to_string());

    // We need to re-derive the SAID since we changed the content
    use verifiable_storage::Versioned;
    bad_event.increment().unwrap(); // This will recompute the SAID

    let bad_signature = builder.sign(bad_event.said.as_bytes()).await.unwrap();

    let bad_request = vec![SignedKeyEvent::new(
        bad_event,
        icp_public_key, // same key as icp
        bad_signature.qb64(),
    )];

    let app2 = create_test_app(repo);
    let response = app2
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/kels/events")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&bad_request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should fail due to wrong previous reference (merge() will handle this)
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
