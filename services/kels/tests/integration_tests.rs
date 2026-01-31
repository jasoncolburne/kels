//! Integration tests for the KELS service.
//!
//! These tests spin up real Postgres and Redis containers, start the server,
//! and hit it via HTTP to test the full request/response flow.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use cesr::{Digest, Matter};
use kels::{
    BatchKelsRequest, BatchSubmitResponse, KeyEventBuilder, SignedKeyEvent, SoftwareKeyProvider,
};
use reqwest::Client;
use std::net::TcpListener;
use std::sync::Arc;
use testcontainers::{ContainerAsync, runners::AsyncRunner};
use testcontainers_modules::{postgres::Postgres, redis::Redis};
use tokio::sync::OnceCell;

/// Test harness that manages containers and server lifecycle.
struct TestHarness {
    base_url: String,
    // Keep containers alive for the duration of tests
    _postgres: ContainerAsync<Postgres>,
    _redis: ContainerAsync<Redis>,
}

impl TestHarness {
    /// Create a new HTTP client for this test.
    /// Each test must create its own client since they run in separate tokio runtimes.
    fn client(&self) -> Client {
        Client::new()
    }
}

impl TestHarness {
    async fn new() -> Self {
        // Start Postgres container
        let postgres = Postgres::default()
            .start()
            .await
            .expect("Failed to start Postgres container");

        let pg_host = postgres
            .get_host()
            .await
            .expect("Failed to get Postgres host");
        let pg_port = postgres
            .get_host_port_ipv4(5432)
            .await
            .expect("Failed to get Postgres port");

        let database_url = format!(
            "postgres://postgres:postgres@{}:{}/postgres",
            pg_host, pg_port
        );

        // Start Redis container
        let redis = Redis::default()
            .start()
            .await
            .expect("Failed to start Redis container");

        let redis_host = redis.get_host().await.expect("Failed to get Redis host");
        let redis_port = redis
            .get_host_port_ipv4(6379)
            .await
            .expect("Failed to get Redis port");

        let redis_url = format!("redis://{}:{}", redis_host, redis_port);

        // Find an available port for the server
        let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind to random port");
        let port = listener.local_addr().unwrap().port();
        drop(listener); // Release the port so the server can use it

        let base_url = format!("http://127.0.0.1:{}", port);

        // Set environment variables for the server
        // SAFETY: We're in a test environment and the harness is initialized once via OnceCell,
        // so there's no concurrent access to environment variables during setup.
        unsafe {
            std::env::set_var("DATABASE_URL", &database_url);
            std::env::set_var("REDIS_URL", &redis_url);
        }

        // Start the server in a dedicated thread with its own runtime.
        // This ensures the server survives across test boundaries since each
        // #[tokio::test] creates its own runtime that shuts down after the test.
        let server_port = port;
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create server runtime");
            rt.block_on(async move {
                if let Err(e) = kels_service::run(server_port).await {
                    eprintln!("Server error: {}", e);
                }
            });
        });

        // Wait for server to be ready
        let health_url = format!("{}/health", base_url);

        for _ in 0..50 {
            // Create a temporary client just for health checks during setup
            let client = Client::new();
            if let Ok(resp) = client.get(&health_url).send().await
                && resp.status().is_success()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        Self {
            base_url,
            _postgres: postgres,
            _redis: redis,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

/// Global test harness - initialized once and reused across tests.
/// This avoids spinning up containers for each test.
static HARNESS: OnceCell<Arc<TestHarness>> = OnceCell::const_new();

async fn get_harness() -> Arc<TestHarness> {
    HARNESS
        .get_or_init(|| async { Arc::new(TestHarness::new().await) })
        .await
        .clone()
}

/// Helper to create a signed inception event.
async fn create_inception() -> (SignedKeyEvent, KeyEventBuilder<SoftwareKeyProvider>) {
    let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
    let (event, signature) = builder.incept().await.unwrap();
    let public_key = event.public_key.clone().unwrap();
    let signed = SignedKeyEvent::new(event, public_key, signature.qb64());
    (signed, builder)
}

/// Generate a valid CESR Blake3 digest to use as an anchor.
fn make_anchor(data: &str) -> String {
    Digest::blake3_256(data.as_bytes()).qb64()
}

/// Helper to create a signed interaction event.
async fn create_interaction(
    builder: &mut KeyEventBuilder<SoftwareKeyProvider>,
    anchor: &str,
) -> SignedKeyEvent {
    let (event, signature) = builder.interact(anchor).await.unwrap();
    let public_key = builder.current_public_key().await.unwrap();
    SignedKeyEvent::new(event, public_key.qb64(), signature.qb64())
}

// ==================== Tests ====================

#[tokio::test]
async fn test_health_check() {
    let harness = get_harness().await;

    let response = harness
        .client()
        .get(harness.url("/health"))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn test_submit_and_get_kel() {
    let harness = get_harness().await;

    // Create an inception event
    let (inception, _builder) = create_inception().await;
    let prefix = inception.event.prefix.clone();

    // Submit the event
    let response = harness
        .client()
        .post(harness.url("/api/kels/events"))
        .json(&vec![inception.clone()])
        .send()
        .await
        .expect("Failed to submit events");

    assert_eq!(response.status(), 200);
    let result: BatchSubmitResponse = response.json().await.unwrap();
    assert!(result.accepted);
    assert!(result.diverged_at.is_none());

    // Retrieve the KEL
    let response = harness
        .client()
        .get(harness.url(&format!("/api/kels/kel/{}", prefix)))
        .send()
        .await
        .expect("Failed to get KEL");

    assert_eq!(response.status(), 200);
    let events: Vec<SignedKeyEvent> = response.json().await.unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event.said, inception.event.said);
}

#[tokio::test]
async fn test_submit_multiple_events() {
    let harness = get_harness().await;

    // Create inception + interactions
    let (inception, mut builder) = create_inception().await;
    let prefix = inception.event.prefix.clone();
    let ixn1 = create_interaction(&mut builder, &make_anchor("credential1")).await;
    let ixn2 = create_interaction(&mut builder, &make_anchor("credential2")).await;

    // Submit all events at once
    let events = vec![inception.clone(), ixn1.clone(), ixn2.clone()];
    let response = harness
        .client()
        .post(harness.url("/api/kels/events"))
        .json(&events)
        .send()
        .await
        .expect("Failed to submit events");

    assert_eq!(response.status(), 200);
    let result: BatchSubmitResponse = response.json().await.unwrap();
    assert!(result.accepted);

    // Retrieve and verify
    let response = harness
        .client()
        .get(harness.url(&format!("/api/kels/kel/{}", prefix)))
        .send()
        .await
        .expect("Failed to get KEL");

    let stored_events: Vec<SignedKeyEvent> = response.json().await.unwrap();
    assert_eq!(stored_events.len(), 3);
}

#[tokio::test]
async fn test_get_nonexistent_kel() {
    let harness = get_harness().await;

    let response = harness
        .client()
        .get(harness.url("/api/kels/kel/Enonexistent_prefix_that_does_not_exist"))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 404);
}

#[tokio::test]
async fn test_batch_get_kels() {
    let harness = get_harness().await;

    // Create two separate KELs
    let (inception1, _) = create_inception().await;
    let (inception2, _) = create_inception().await;
    let prefix1 = inception1.event.prefix.clone();
    let prefix2 = inception2.event.prefix.clone();

    // Submit both
    harness
        .client()
        .post(harness.url("/api/kels/events"))
        .json(&vec![inception1])
        .send()
        .await
        .unwrap();

    harness
        .client()
        .post(harness.url("/api/kels/events"))
        .json(&vec![inception2])
        .send()
        .await
        .unwrap();

    // Batch fetch
    let request = BatchKelsRequest {
        prefixes: vec![prefix1.clone(), prefix2.clone()],
    };

    let response = harness
        .client()
        .post(harness.url("/api/kels/kels"))
        .json(&request)
        .send()
        .await
        .expect("Failed to batch fetch");

    assert_eq!(response.status(), 200);

    let result: std::collections::HashMap<String, Vec<SignedKeyEvent>> =
        response.json().await.unwrap();
    assert_eq!(result.len(), 2);
    assert!(result.contains_key(&prefix1));
    assert!(result.contains_key(&prefix2));
}

#[tokio::test]
async fn test_list_prefixes() {
    let harness = get_harness().await;

    // Create a KEL so there's at least one prefix
    let (inception, _) = create_inception().await;
    harness
        .client()
        .post(harness.url("/api/kels/events"))
        .json(&vec![inception])
        .send()
        .await
        .unwrap();

    // List prefixes
    let response = harness
        .client()
        .get(harness.url("/api/kels/prefixes"))
        .send()
        .await
        .expect("Failed to list prefixes");

    assert_eq!(response.status(), 200);

    let result: kels::PrefixListResponse = response.json().await.unwrap();
    assert!(!result.prefixes.is_empty());
}

#[tokio::test]
async fn test_idempotent_submit() {
    let harness = get_harness().await;

    let (inception, _) = create_inception().await;
    let prefix = inception.event.prefix.clone();

    // Submit the same event twice
    for _ in 0..2 {
        let response = harness
            .client()
            .post(harness.url("/api/kels/events"))
            .json(&vec![inception.clone()])
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        let result: BatchSubmitResponse = response.json().await.unwrap();
        assert!(result.accepted);
    }

    // Should still only have one event
    let response = harness
        .client()
        .get(harness.url(&format!("/api/kels/kel/{}", prefix)))
        .send()
        .await
        .unwrap();

    let events: Vec<SignedKeyEvent> = response.json().await.unwrap();
    assert_eq!(events.len(), 1);
}

#[tokio::test]
async fn test_submit_empty_events() {
    let harness = get_harness().await;

    let response = harness
        .client()
        .post(harness.url("/api/kels/events"))
        .json(&Vec::<SignedKeyEvent>::new())
        .send()
        .await
        .expect("Failed to submit events");

    assert_eq!(response.status(), 200);
    let result: BatchSubmitResponse = response.json().await.unwrap();
    assert!(result.accepted);
}

#[tokio::test]
async fn test_get_kel_with_audit() {
    let harness = get_harness().await;

    let (inception, _) = create_inception().await;
    let prefix = inception.event.prefix.clone();

    // Submit
    harness
        .client()
        .post(harness.url("/api/kels/events"))
        .json(&vec![inception])
        .send()
        .await
        .unwrap();

    // Get with audit flag
    let response = harness
        .client()
        .get(harness.url(&format!("/api/kels/kel/{}?audit=true", prefix)))
        .send()
        .await
        .expect("Failed to get KEL with audit");

    assert_eq!(response.status(), 200);

    let result: kels::KelResponse = response.json().await.unwrap();
    assert_eq!(result.events.len(), 1);
    // No audit records for a simple KEL
    assert!(result.audit_records.is_none());
}
