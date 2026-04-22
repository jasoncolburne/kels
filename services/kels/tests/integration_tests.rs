//! Integration tests for the KELS service.
//!
//! These tests share a single server instance to test concurrent request handling.
//! Each test creates unique prefixes, so they don't interfere with each other.
//! The shared server is initialized once on first test access.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{collections::HashMap, net::TcpListener, sync::OnceLock, time::Duration};

use cesr::{Digest256, test_digest, test_signature};
use ctor::dtor;
use kels_core::{
    KeyEventBuilder, SignedKeyEvent, SignedKeyEventPage, SoftwareKeyProvider,
    SubmitKeyEventsResponse, VerificationKeyCode,
};
use reqwest::Client;
use testcontainers::{ContainerAsync, Image, core::ImageExt, runners::AsyncRunner};
use testcontainers_modules::{postgres::Postgres, redis::Redis};
use tokio::{sync::OnceCell, time::sleep};

const TEST_CONTAINER_LABEL: (&str, &str) = ("kels-test", "true");

#[dtor]
fn cleanup_test_containers() {
    let _ = std::process::Command::new("docker")
        .args(["ps", "-q", "--filter", "label=kels-test=true"])
        .output()
        .map(|output| {
            let ids = String::from_utf8_lossy(&output.stdout);
            for id in ids.lines() {
                let _ = std::process::Command::new("docker")
                    .args(["rm", "-f", id])
                    .output();
            }
        });
}

/// Retry getting container port - testcontainers has a race where port may not be mapped yet
async fn retry_get_port<I: Image>(container: &ContainerAsync<I>, port: u16) -> Option<u16> {
    for _ in 0..10 {
        if let Ok(p) = container.get_host_port_ipv4(port).await {
            return Some(p);
        }
        sleep(Duration::from_millis(100)).await;
    }
    None
}

/// Shared test harness - initialized once, used by all tests.
/// Containers are labeled and cleaned up by `make clean-test-containers`.
struct SharedHarness {
    base_url: String,
    _postgres: ContainerAsync<Postgres>,
    _redis: ContainerAsync<Redis>,
}

/// Global shared harness - initialized once on first access
static SHARED_HARNESS: OnceLock<OnceCell<Option<SharedHarness>>> = OnceLock::new();

/// Get or initialize the shared test harness
async fn get_harness() -> Option<&'static SharedHarness> {
    let cell = SHARED_HARNESS.get_or_init(OnceCell::new);
    let harness = cell
        .get_or_init(|| async {
            match SharedHarness::new().await {
                Some(h) => Some(h),
                None => {
                    eprintln!("WARNING: Failed to initialize shared test harness");
                    None
                }
            }
        })
        .await;
    harness.as_ref()
}

impl SharedHarness {
    async fn new() -> Option<Self> {
        // Start Postgres container with label for cleanup
        let postgres = match Postgres::default()
            .with_label(TEST_CONTAINER_LABEL.0, TEST_CONTAINER_LABEL.1)
            .start()
            .await
        {
            Ok(p) => p,
            Err(e) => {
                panic!("ERROR: Postgres container failed to start: {}", e);
            }
        };

        let pg_host = match postgres.get_host().await {
            Ok(h) => h,
            Err(e) => {
                panic!("ERROR: failed to get Postgres host: {}", e);
            }
        };

        let pg_port = match retry_get_port(&postgres, 5432).await {
            Some(p) => p,
            None => {
                panic!("ERROR: failed to get Postgres port after retries");
            }
        };

        let database_url = format!(
            "postgres://postgres:postgres@{}:{}/postgres",
            pg_host, pg_port
        );

        // Start Redis container with label for cleanup
        let redis = match Redis::default()
            .with_label(TEST_CONTAINER_LABEL.0, TEST_CONTAINER_LABEL.1)
            .start()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                panic!("ERROR: Redis container failed to start: {}", e);
            }
        };

        let redis_host = match redis.get_host().await {
            Ok(h) => h,
            Err(e) => {
                panic!("ERROR: failed to get Redis host: {}", e);
            }
        };

        let redis_port = match retry_get_port(&redis, 6379).await {
            Some(p) => p,
            None => {
                panic!("ERROR: failed to get Redis port after retries");
            }
        };

        let redis_url = format!("redis://{}:{}", redis_host, redis_port);

        // Bind to a random port and keep the listener to avoid race conditions
        let std_listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(l) => l,
            Err(e) => {
                panic!("ERROR: failed to bind to random port: {}", e);
            }
        };
        let port = std_listener.local_addr().unwrap().port();
        std_listener.set_nonblocking(true).unwrap();

        let base_url = format!("http://127.0.0.1:{}", port);

        // Enable test endpoints for integration tests (unauthenticated prefixes)
        // SAFETY: called before spawning threads; no concurrent env reads yet.
        unsafe {
            std::env::set_var("KELS_TEST_ENDPOINTS", "true");
            std::env::set_var("KELS_NONCE_WINDOW_SECS", "0");
        }

        // Start the server in a dedicated thread with its own runtime.
        let db_url = database_url.clone();
        let rd_url = redis_url.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create server runtime");
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(std_listener)
                    .expect("Failed to convert listener");
                if let Err(e) = kels_service::run(listener, &db_url, Some(&rd_url), vec![]).await {
                    panic!("Server error: {}", e);
                }
            });
        });

        // Wait for server to be ready with timeout detection
        let health_url = format!("{}/health", base_url);
        let startup_client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        let mut server_ready = false;
        let mut consecutive_refused = 0;
        for i in 0..50 {
            match startup_client.get(&health_url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    server_ready = true;
                    break;
                }
                Ok(_) => {
                    consecutive_refused = 0;
                    sleep(Duration::from_millis(100)).await;
                }
                Err(e) => {
                    let err_str = e.to_string();
                    if err_str.contains("Connection refused") {
                        consecutive_refused += 1;
                        if i > 20 && consecutive_refused > 10 {
                            break;
                        }
                    } else {
                        consecutive_refused = 0;
                    }
                    sleep(Duration::from_millis(100)).await;
                }
            }
        }

        if !server_ready {
            panic!("Error: server did not become ready in time");
        }

        eprintln!("Shared test server ready at {}", base_url);

        Some(Self {
            base_url,
            _postgres: postgres,
            _redis: redis,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn client(&self) -> Client {
        Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap()
    }
}

/// Helper to create a signed inception event.
async fn create_inception() -> (SignedKeyEvent, KeyEventBuilder<SoftwareKeyProvider>) {
    let mut builder = KeyEventBuilder::new(
        SoftwareKeyProvider::new(
            VerificationKeyCode::Secp256r1,
            VerificationKeyCode::Secp256r1,
        ),
        None,
    );
    let icp = builder.incept().await.unwrap();
    (icp, builder)
}

/// Generate a valid CESR Blake3 digest to use as an anchor.
fn make_anchor(data: &str) -> Digest256 {
    Digest256::blake3_256(data.as_bytes())
}

/// Helper to create a signed interaction event.
async fn create_interaction(
    builder: &mut KeyEventBuilder<SoftwareKeyProvider>,
    anchor: &cesr::Digest256,
) -> SignedKeyEvent {
    builder.interact(anchor).await.unwrap()
}

// ==================== Tests ====================

#[tokio::test]
async fn test_health_check() {
    let Some(harness) = get_harness().await else {
        return;
    };

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
    let Some(harness) = get_harness().await else {
        return;
    };

    // Create an inception event
    let (inception, _builder) = create_inception().await;
    let prefix = inception.event.prefix;

    // Submit the event
    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/events"))
        .json(&vec![inception.clone()])
        .send()
        .await
        .expect("Failed to submit events");

    assert_eq!(response.status(), 200);
    let result: SubmitKeyEventsResponse = response.json().await.unwrap();
    assert!(result.applied);
    assert!(result.diverged_at.is_none());

    // Retrieve the KEL
    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/kel/fetch"))
        .header("content-type", "application/json")
        .json(&serde_json::json!({"prefix": prefix.to_string()}))
        .send()
        .await
        .expect("Failed to get KEL");

    assert_eq!(response.status(), 200);
    let page: SignedKeyEventPage = response.json().await.unwrap();
    assert_eq!(page.events.len(), 1);
    assert_eq!(page.events[0].event.said, inception.event.said);
    assert!(!page.has_more);
}

#[tokio::test]
async fn test_submit_multiple_events() {
    let Some(harness) = get_harness().await else {
        return;
    };

    // Create inception + interactions
    let (inception, mut builder) = create_inception().await;
    let prefix = inception.event.prefix;
    let ixn1 = create_interaction(&mut builder, &make_anchor("credential1")).await;
    let ixn2 = create_interaction(&mut builder, &make_anchor("credential2")).await;

    // Submit all events at once
    let events = vec![inception.clone(), ixn1.clone(), ixn2.clone()];
    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/events"))
        .json(&events)
        .send()
        .await
        .expect("Failed to submit events");

    assert_eq!(response.status(), 200);
    let result: SubmitKeyEventsResponse = response.json().await.unwrap();
    assert!(result.applied);

    // Retrieve and verify
    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/kel/fetch"))
        .header("content-type", "application/json")
        .json(&serde_json::json!({"prefix": prefix.to_string()}))
        .send()
        .await
        .expect("Failed to get KEL");

    let page: SignedKeyEventPage = response.json().await.unwrap();
    assert_eq!(page.events.len(), 3);
}

#[tokio::test]
async fn test_get_nonexistent_kel() {
    let Some(harness) = get_harness().await else {
        return;
    };

    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/kel/fetch"))
        .header("content-type", "application/json")
        .json(&serde_json::json!({"prefix": test_digest("nonexistent-prefix").to_string()}))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 404);
}

#[tokio::test]
async fn test_list_prefixes() {
    let Some(harness) = get_harness().await else {
        return;
    };

    // Create a KEL so there's at least one prefix
    let (inception, _) = create_inception().await;
    harness
        .client()
        .post(harness.url("/api/v1/kels/events"))
        .json(&vec![inception])
        .send()
        .await
        .unwrap();

    // List prefixes via signed POST
    let request = kels_core::SignedRequest {
        payload: kels_core::PaginatedSelfAddressedRequest::create(
            kels_core::generate_nonce(),
            None,
            None,
        )
        .unwrap(),
        signatures: HashMap::from([(test_digest("mock"), test_signature("mock"))]),
    };

    let response = harness
        .client()
        .post(harness.url("/api/test/prefixes"))
        .json(&request)
        .send()
        .await
        .expect("Failed to list prefixes");

    assert_eq!(response.status(), 200);

    let result: kels_core::PrefixListResponse = response.json().await.unwrap();
    assert!(!result.prefixes.is_empty());
}

#[tokio::test]
async fn test_idempotent_submit() {
    let Some(harness) = get_harness().await else {
        return;
    };

    let (inception, _) = create_inception().await;
    let prefix = inception.event.prefix;

    // Submit the same event twice
    for _ in 0..2 {
        let response = harness
            .client()
            .post(harness.url("/api/v1/kels/events"))
            .json(&vec![inception.clone()])
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        let result: SubmitKeyEventsResponse = response.json().await.unwrap();
        assert!(result.applied);
    }

    // Should still only have one event
    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/kel/fetch"))
        .header("content-type", "application/json")
        .json(&serde_json::json!({"prefix": prefix.to_string()}))
        .send()
        .await
        .unwrap();

    let page: SignedKeyEventPage = response.json().await.unwrap();
    assert_eq!(page.events.len(), 1);
}

#[tokio::test]
async fn test_submit_empty_events() {
    let Some(harness) = get_harness().await else {
        return;
    };

    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/events"))
        .json(&Vec::<SignedKeyEvent>::new())
        .send()
        .await
        .expect("Failed to submit events");

    assert_eq!(response.status(), 200);
    let result: SubmitKeyEventsResponse = response.json().await.unwrap();
    assert!(result.applied);
}

#[tokio::test]
async fn test_get_kel_with_audit() {
    let Some(harness) = get_harness().await else {
        return;
    };

    let (inception, _) = create_inception().await;
    let prefix = inception.event.prefix;

    // Submit
    harness
        .client()
        .post(harness.url("/api/v1/kels/events"))
        .json(&vec![inception])
        .send()
        .await
        .unwrap();

    // Get KEL
    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/kel/fetch"))
        .header("content-type", "application/json")
        .json(&serde_json::json!({"prefix": prefix.to_string()}))
        .send()
        .await
        .expect("Failed to get KEL");

    assert_eq!(response.status(), 200);
    let page: SignedKeyEventPage = response.json().await.unwrap();
    assert_eq!(page.events.len(), 1);

    // Get audit records from separate endpoint
    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/kel/recoveries"))
        .header("content-type", "application/json")
        .json(&serde_json::json!({"prefix": prefix.to_string()}))
        .send()
        .await
        .expect("Failed to get audit records");

    assert_eq!(response.status(), 200);
    let page: kels_core::RecoveryRecordPage = response.json().await.unwrap();
    // No recovery records for a simple KEL
    assert!(page.records.is_empty());
    assert!(!page.has_more);
}

#[tokio::test]
async fn test_list_prefixes_with_limit() {
    let Some(harness) = get_harness().await else {
        return;
    };

    // Create a few KELs
    for _ in 0..3 {
        let (inception, _) = create_inception().await;
        harness
            .client()
            .post(harness.url("/api/v1/kels/events"))
            .json(&vec![inception])
            .send()
            .await
            .unwrap();
    }

    // List with limit=2 via signed POST
    let request = kels_core::SignedRequest {
        payload: kels_core::PaginatedSelfAddressedRequest::create(
            kels_core::generate_nonce(),
            None,
            Some(2),
        )
        .unwrap(),
        signatures: HashMap::from([(test_digest("mock"), test_signature("mock"))]),
    };

    let response = harness
        .client()
        .post(harness.url("/api/test/prefixes"))
        .json(&request)
        .send()
        .await
        .expect("Failed to list prefixes");

    assert_eq!(response.status(), 200);
    let result: kels_core::PrefixListResponse = response.json().await.unwrap();
    assert!(result.prefixes.len() <= 2);
}

#[tokio::test]
async fn test_submit_event_missing_signature() {
    let Some(harness) = get_harness().await else {
        return;
    };

    // Create inception but clear signatures
    let (mut inception, _) = create_inception().await;
    inception.signatures.clear();

    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/events"))
        .json(&vec![inception])
        .send()
        .await
        .expect("Failed to submit events");

    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn test_submit_event_invalid_signature_format() {
    let Some(harness) = get_harness().await else {
        return;
    };

    // Create inception, serialize to JSON, then corrupt the signature field
    let (inception, _) = create_inception().await;
    let mut json_value: serde_json::Value = serde_json::to_value(vec![inception]).unwrap();
    json_value[0]["signatures"][0]["signature"] =
        serde_json::Value::String("invalid_not_cesr_signature".to_string());

    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/events"))
        .json(&json_value)
        .send()
        .await
        .expect("Failed to submit events");

    // Invalid CESR signature strings are rejected at deserialization (422 Unprocessable Entity)
    assert_eq!(response.status(), 422);
}

#[tokio::test]
async fn test_submit_rotation_event() {
    let Some(harness) = get_harness().await else {
        return;
    };

    // Create inception
    let (inception, mut builder) = create_inception().await;
    let prefix = inception.event.prefix;

    // Submit inception
    harness
        .client()
        .post(harness.url("/api/v1/kels/events"))
        .json(&vec![inception])
        .send()
        .await
        .unwrap();

    // Create rotation event
    let rot = builder.rotate().await.unwrap();

    // Submit rotation
    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/events"))
        .json(&vec![rot])
        .send()
        .await
        .expect("Failed to submit rotation");

    assert_eq!(response.status(), 200);
    let result: SubmitKeyEventsResponse = response.json().await.unwrap();
    assert!(result.applied);

    // Verify KEL now has 2 events
    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/kel/fetch"))
        .header("content-type", "application/json")
        .json(&serde_json::json!({"prefix": prefix.to_string()}))
        .send()
        .await
        .unwrap();

    let page: SignedKeyEventPage = response.json().await.unwrap();
    assert_eq!(page.events.len(), 2);
}

#[tokio::test]
async fn test_list_prefixes_pagination_with_cursor() {
    let Some(harness) = get_harness().await else {
        return;
    };

    // Create several KELs
    let mut prefixes = Vec::new();
    for _ in 0..3 {
        let (inception, _) = create_inception().await;
        prefixes.push(inception.event.prefix);
        harness
            .client()
            .post(harness.url("/api/v1/kels/events"))
            .json(&vec![inception])
            .send()
            .await
            .unwrap();
    }

    // Get first page with limit=1 via signed POST
    let request = kels_core::SignedRequest {
        payload: kels_core::PaginatedSelfAddressedRequest::create(
            kels_core::generate_nonce(),
            None,
            Some(1),
        )
        .unwrap(),
        signatures: HashMap::from([(test_digest("mock"), test_signature("mock"))]),
    };

    let response = harness
        .client()
        .post(harness.url("/api/test/prefixes"))
        .json(&request)
        .send()
        .await
        .expect("Failed to list prefixes");

    assert_eq!(response.status(), 200);
    let result: kels_core::PrefixListResponse = response.json().await.unwrap();
    assert_eq!(result.prefixes.len(), 1);

    // Use cursor to get next page if available
    if let Some(cursor) = &result.next_cursor {
        let request = kels_core::SignedRequest {
            payload: kels_core::PaginatedSelfAddressedRequest::create(
                kels_core::generate_nonce(),
                Some(*cursor),
                Some(1),
            )
            .unwrap(),
            signatures: HashMap::from([(test_digest("mock"), test_signature("mock"))]),
        };

        let response = harness
            .client()
            .post(harness.url("/api/test/prefixes"))
            .json(&request)
            .send()
            .await
            .expect("Failed to list prefixes with cursor");

        assert_eq!(response.status(), 200);
        let next_result: kels_core::PrefixListResponse = response.json().await.unwrap();
        // Second page should have different prefix(es) than first page
        if !next_result.prefixes.is_empty() {
            assert_ne!(result.prefixes[0].prefix, next_result.prefixes[0].prefix);
        }
    }
}

#[tokio::test]
async fn test_submit_decommission_event() {
    let Some(harness) = get_harness().await else {
        return;
    };

    // Create inception
    let (inception, mut builder) = create_inception().await;
    let prefix = inception.event.prefix;

    // Submit inception
    harness
        .client()
        .post(harness.url("/api/v1/kels/events"))
        .json(&vec![inception])
        .send()
        .await
        .unwrap();

    // Create decommission event - decommission() adds the dual-signed event to internal KEL
    let _ = builder.decommission().await.unwrap();

    // Get the properly signed decommission event from builder's KEL
    let events = builder.pending_events();
    let signed_dec = events.last().unwrap().clone();

    // Submit decommission
    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/events"))
        .json(&vec![signed_dec])
        .send()
        .await
        .expect("Failed to submit decommission");

    assert_eq!(response.status(), 200);
    let result: SubmitKeyEventsResponse = response.json().await.unwrap();
    assert!(result.applied);

    // Verify KEL now has 2 events (icp + dec)
    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/kel/fetch"))
        .header("content-type", "application/json")
        .json(&serde_json::json!({"prefix": prefix.to_string()}))
        .send()
        .await
        .unwrap();

    let page: SignedKeyEventPage = response.json().await.unwrap();
    assert_eq!(page.events.len(), 2);
}

#[tokio::test]
async fn test_recoveries_empty_for_nonexistent_prefix() {
    let Some(harness) = get_harness().await else {
        return;
    };

    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/kel/recoveries"))
        .header("content-type", "application/json")
        .json(
            &serde_json::json!({"prefix": test_digest("nonexistent-prefix-for-audit").to_string()}),
        )
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);
    let page: kels_core::RecoveryRecordPage = response.json().await.unwrap();
    assert!(page.records.is_empty());
}

#[tokio::test]
async fn test_submit_recovery_event_requires_dual_signature() {
    let Some(harness) = get_harness().await else {
        return;
    };

    // Create inception
    let (inception, mut builder) = create_inception().await;

    // Submit inception
    harness
        .client()
        .post(harness.url("/api/v1/kels/events"))
        .json(&vec![inception])
        .send()
        .await
        .unwrap();

    // Create recovery event (with rotation) - this creates dual-signed event internally
    let _ = builder.recover(true).await.unwrap();

    // Get the properly signed recovery event and strip one signature for testing
    let events = builder.pending_events();
    // Recovery creates a rec event first, then a rot event
    let rec_event = events.iter().find(|e| e.event.is_recover()).unwrap();
    let mut signed_rec = rec_event.clone();
    // Remove one signature to trigger dual signature validation error
    signed_rec.signatures.truncate(1);

    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/events"))
        .json(&vec![signed_rec])
        .send()
        .await
        .expect("Failed to submit recovery");

    assert_eq!(response.status(), 400);
    let error: kels_core::ErrorResponse = response.json().await.unwrap();
    assert!(error.error.contains("Dual signatures required"));
}

// ==================== Divergence / Recovery / Contest ====================

/// Submit conflicting interactions at the same serial to create divergence.
#[tokio::test]
async fn test_divergence_creation() {
    let Some(harness) = get_harness().await else {
        return;
    };

    // Create KEL: icp + 2 interactions
    let (inception, mut builder_a) = create_inception().await;
    let prefix = inception.event.prefix;

    let ixn1 = create_interaction(&mut builder_a, &make_anchor("ixn1")).await;
    let ixn2 = create_interaction(&mut builder_a, &make_anchor("ixn2")).await;

    // Submit icp + 2 interactions
    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/events"))
        .json(&vec![inception, ixn1, ixn2])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let result: SubmitKeyEventsResponse = response.json().await.unwrap();
    assert!(result.applied);
    assert!(result.diverged_at.is_none());

    // Clone builder at current state (after serial 2) to create a fork
    let mut builder_b = builder_a.clone();

    // Builder A creates interaction at serial 3
    let ixn3_a = create_interaction(&mut builder_a, &make_anchor("branch-a")).await;

    // Submit builder A's interaction
    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/events"))
        .json(&vec![ixn3_a])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let result: SubmitKeyEventsResponse = response.json().await.unwrap();
    assert!(result.applied);
    assert!(result.diverged_at.is_none());

    // Builder B creates a different interaction at serial 3 (same previous)
    let ixn3_b = create_interaction(&mut builder_b, &make_anchor("branch-b")).await;

    // Submit builder B's conflicting interaction — should cause divergence
    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/events"))
        .json(&vec![ixn3_b])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let result: SubmitKeyEventsResponse = response.json().await.unwrap();
    assert!(result.applied);
    assert_eq!(result.diverged_at, Some(3));

    // GET the KEL and verify divergence: two events at serial 3
    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/kel/fetch"))
        .header("content-type", "application/json")
        .json(&serde_json::json!({"prefix": prefix.to_string()}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let page: SignedKeyEventPage = response.json().await.unwrap();
    // 3 events (icp + 2 ixn) + 2 divergent events at serial 3 = 5
    assert_eq!(page.events.len(), 5);
    let serial_3_events: Vec<_> = page.events.iter().filter(|e| e.event.serial == 3).collect();
    assert_eq!(serial_3_events.len(), 2);
}

/// Create divergence and then recover from it.
#[tokio::test]
async fn test_recovery_from_divergence() {
    let Some(harness) = get_harness().await else {
        return;
    };

    // Create KEL: icp + 2 interactions
    let (inception, mut builder_a) = create_inception().await;
    let prefix = inception.event.prefix;

    let ixn1 = create_interaction(&mut builder_a, &make_anchor("rec-ixn1")).await;
    let ixn2 = create_interaction(&mut builder_a, &make_anchor("rec-ixn2")).await;

    harness
        .client()
        .post(harness.url("/api/v1/kels/events"))
        .json(&vec![inception, ixn1, ixn2])
        .send()
        .await
        .unwrap();

    // Fork
    let mut builder_b = builder_a.clone();

    // Create divergence
    let ixn3_a = create_interaction(&mut builder_a, &make_anchor("rec-branch-a")).await;
    harness
        .client()
        .post(harness.url("/api/v1/kels/events"))
        .json(&vec![ixn3_a])
        .send()
        .await
        .unwrap();

    let ixn3_b = create_interaction(&mut builder_b, &make_anchor("rec-branch-b")).await;
    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/events"))
        .json(&vec![ixn3_b])
        .send()
        .await
        .unwrap();
    let result: SubmitKeyEventsResponse = response.json().await.unwrap();
    assert!(result.applied);
    assert_eq!(result.diverged_at, Some(3));

    // Submit recovery from builder A (the legitimate owner).
    // recover(true) creates rec + rot events chaining from builder_a's tip (ixn3_a).
    let _ = builder_a.recover(true).await.unwrap();
    let all_events = builder_a.pending_events();
    let rec_idx = all_events
        .iter()
        .position(|e| e.event.is_recover())
        .unwrap();
    let recovery_events = all_events[rec_idx..].to_vec();

    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/events"))
        .json(&recovery_events)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let result: SubmitKeyEventsResponse = response.json().await.unwrap();
    assert!(result.applied);

    // GET KEL — should show the recovered chain
    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/kel/fetch"))
        .header("content-type", "application/json")
        .json(&serde_json::json!({"prefix": prefix.to_string()}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let page: SignedKeyEventPage = response.json().await.unwrap();
    // After recovery, the KEL should have the authoritative branch events
    assert!(page.events.iter().any(|e| e.event.is_recover()));

    // Subsequent normal appends should work (adversary events archived synchronously)
    let ixn_after = create_interaction(&mut builder_a, &make_anchor("post-recovery")).await;
    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/events"))
        .json(&vec![ixn_after])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let result: SubmitKeyEventsResponse = response.json().await.unwrap();
    assert!(result.applied);
    assert!(result.diverged_at.is_none());

    // Audit endpoint should return the recovery record with correct fields
    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/kel/recoveries"))
        .header("content-type", "application/json")
        .json(&serde_json::json!({"prefix": prefix.to_string()}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let page: kels_core::RecoveryRecordPage = response.json().await.unwrap();
    assert_eq!(page.records.len(), 1);
    let record = &page.records[0];
    assert_eq!(record.diverged_at, 3);
    assert_eq!(record.recovery_serial, 4);
    assert_eq!(record.owner_first_serial, 4);
    assert_eq!(record.kel_prefix, prefix);
    assert!(!record.said.to_string().is_empty());
    assert!(!record.rec_previous.to_string().is_empty());
}

/// Contest freezes a KEL after recovery key is revealed.
///
/// Flow: owner rotates recovery (revealing the recovery key), then the adversary
/// submits a contest at the same serial (creating divergence + freeze in one step)
/// via handle_overlap_submission.
#[tokio::test]
async fn test_contest_freezes_kel() {
    let Some(harness) = get_harness().await else {
        return;
    };

    // Create KEL: icp + 2 interactions
    let (inception, mut builder_a) = create_inception().await;
    let prefix = inception.event.prefix;

    let ixn1 = create_interaction(&mut builder_a, &make_anchor("cnt-ixn1")).await;
    let ixn2 = create_interaction(&mut builder_a, &make_anchor("cnt-ixn2")).await;

    harness
        .client()
        .post(harness.url("/api/v1/kels/events"))
        .json(&vec![inception, ixn1, ixn2])
        .send()
        .await
        .unwrap();

    // Fork before the recovery-revealing event
    let mut builder_b = builder_a.clone();

    // Builder A does rotate_recovery (reveals recovery key) at serial 3
    let ror_event = builder_a.rotate_recovery().await.unwrap();
    harness
        .client()
        .post(harness.url("/api/v1/kels/events"))
        .json(&vec![ror_event])
        .send()
        .await
        .unwrap();

    // Builder B (adversary who also knows recovery key) submits a contest at serial 3.
    // This hits handle_overlap_submission: old events reveal recovery, new event is contest → Contested.
    let contest_event = builder_b.contest().await.unwrap();

    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/events"))
        .json(&vec![contest_event])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let result: SubmitKeyEventsResponse = response.json().await.unwrap();
    assert!(result.applied);
    assert!(result.diverged_at.is_some());

    // GET KEL — should contain contest event
    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/kel/fetch"))
        .header("content-type", "application/json")
        .json(&serde_json::json!({"prefix": prefix.to_string()}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let page: SignedKeyEventPage = response.json().await.unwrap();
    assert!(page.events.iter().any(|e| e.event.is_contest()));

    // Further submissions should be rejected (KEL is frozen)
    let ixn_after = create_interaction(&mut builder_a, &make_anchor("post-contest")).await;
    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/events"))
        .json(&vec![ixn_after])
        .send()
        .await
        .unwrap();
    // Contested KEL should reject new events
    assert_ne!(response.status(), 200);
}

/// Contest on an already-divergent KEL where cnt_serial > diverged_at.
///
/// Regression test for claudit #3: the contest recovery-revealing check used
/// `cnt_serial` instead of `diverged_at` as the scan origin, causing valid
/// contests to be rejected when the owner's chain extended past the fork point.
///
/// Flow:
///   1. KEL: icp + ixn1 + ixn2 (serials 0-2)
///   2. Fork after ixn2 (owner = builder_a, adversary = builder_b)
///   3. Owner submits ixn(3) → accepted (no divergence yet)
///   4. Adversary submits ror(3) → divergence at serial 3 (reveals recovery key)
///   5. Owner submits cnt(4) chaining from ixn(3) → should succeed
///
/// The bug: `non_contest_recovery_revealed_since(cnt_serial=4)` scans from
/// serial 4, missing the adversary's ror at serial 3.
#[tokio::test]
async fn test_contest_on_divergent_kel_with_cnt_serial_above_diverged_at() {
    let Some(harness) = get_harness().await else {
        return;
    };

    // Step 1: Create KEL: icp + ixn1 + ixn2
    let (inception, mut builder_a) = create_inception().await;
    let prefix = inception.event.prefix;

    let ixn1 = create_interaction(&mut builder_a, &make_anchor("cnt3-ixn1")).await;
    let ixn2 = create_interaction(&mut builder_a, &make_anchor("cnt3-ixn2")).await;

    harness
        .client()
        .post(harness.url("/api/v1/kels/events"))
        .json(&vec![inception, ixn1, ixn2])
        .send()
        .await
        .unwrap();

    // Step 2: Fork after ixn2 — adversary steals keys
    let mut builder_b = builder_a.clone();

    // Step 3: Owner submits ixn(3) — accepted, no divergence yet
    let ixn3_a = create_interaction(&mut builder_a, &make_anchor("cnt3-owner-ixn3")).await;
    assert_eq!(ixn3_a.event.serial, 3);

    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/events"))
        .json(&vec![ixn3_a])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let result: SubmitKeyEventsResponse = response.json().await.unwrap();
    assert!(result.applied);
    assert!(result.diverged_at.is_none());

    // Step 4: Adversary submits ror(3) — divergence at serial 3, reveals recovery key
    let ror_b = builder_b.rotate_recovery().await.unwrap();
    assert_eq!(ror_b.event.serial, 3);

    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/events"))
        .json(&vec![ror_b])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let result: SubmitKeyEventsResponse = response.json().await.unwrap();
    assert!(result.applied);
    assert_eq!(result.diverged_at, Some(3));

    // Step 5: Owner submits cnt(4) chaining from ixn(3).
    // cnt_serial = 4 > diverged_at = 3.
    let cnt_event = {
        let mut contest_builder = builder_a.clone();
        contest_builder.contest().await.unwrap()
    };
    assert_eq!(cnt_event.event.serial, 4);
    assert!(cnt_event.event.is_contest());

    // Submit the contest. This hits handle_divergent_submission.
    // With the bug, non_contest_recovery_revealed_since(4) scans from serial 4,
    // missing the adversary's ror at serial 3.
    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/events"))
        .json(&vec![cnt_event])
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        200,
        "Contest should succeed — adversary ror at serial 3 reveals recovery key"
    );
    let result: SubmitKeyEventsResponse = response.json().await.unwrap();
    assert!(result.applied);
    assert!(result.diverged_at.is_some());

    // Verify the KEL contains the contest event
    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/kel/fetch"))
        .header("content-type", "application/json")
        .json(&serde_json::json!({"prefix": prefix.to_string()}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let page: SignedKeyEventPage = response.json().await.unwrap();
    assert!(page.events.iter().any(|e| e.event.is_contest()));
}

/// Contest on a non-divergent KEL where the adversary appended a ror.
///
/// The cnt itself creates the divergence and freezes the KEL in one step.
/// This tests handle_overlap_submission's contest path: the existing chain
/// has a recovery-revealing event, and the submitted batch ends with cnt.
///
/// Flow:
///   1. KEL: icp + ixn1 + ixn2 (serials 0-2)
///   2. Fork after ixn2 — adversary steals keys
///   3. Adversary submits ror(3) → accepted as normal append (no divergence)
///   4. Owner submits cnt(3) branching from ixn2 → creates divergence + freeze
#[tokio::test]
async fn test_contest_creates_divergence_on_linear_kel() {
    let Some(harness) = get_harness().await else {
        return;
    };

    // Step 1: Create KEL: icp + ixn1 + ixn2
    let (inception, mut builder_a) = create_inception().await;
    let prefix = inception.event.prefix;

    let ixn1 = create_interaction(&mut builder_a, &make_anchor("cntlin-ixn1")).await;
    let ixn2 = create_interaction(&mut builder_a, &make_anchor("cntlin-ixn2")).await;

    harness
        .client()
        .post(harness.url("/api/v1/kels/events"))
        .json(&vec![inception, ixn1, ixn2])
        .send()
        .await
        .unwrap();

    // Step 2: Fork after ixn2 — adversary steals keys
    let mut builder_b = builder_a.clone();

    // Step 3: Adversary submits ror(3) — accepted as normal append
    let ror_b = builder_b.rotate_recovery().await.unwrap();
    assert_eq!(ror_b.event.serial, 3);

    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/events"))
        .json(&vec![ror_b])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let result: SubmitKeyEventsResponse = response.json().await.unwrap();
    assert!(result.applied);
    assert!(result.diverged_at.is_none());

    // Step 4: Owner submits cnt(3) branching from ixn2.
    // This creates divergence at serial 3 and freezes the KEL.
    let cnt_event = {
        let mut contest_builder = builder_a.clone();
        contest_builder.contest().await.unwrap()
    };
    assert_eq!(cnt_event.event.serial, 3);
    assert!(cnt_event.event.is_contest());

    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/events"))
        .json(&vec![cnt_event])
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        200,
        "Contest should create divergence + freeze on linear KEL with adversary ror"
    );
    let result: SubmitKeyEventsResponse = response.json().await.unwrap();
    assert!(result.applied);
    assert!(result.diverged_at.is_some());

    // Verify the KEL is contested
    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/kel/fetch"))
        .header("content-type", "application/json")
        .json(&serde_json::json!({"prefix": prefix.to_string()}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let page: SignedKeyEventPage = response.json().await.unwrap();
    assert!(page.events.iter().any(|e| e.event.is_contest()));

    // Further submissions should be rejected
    let ixn_after = create_interaction(&mut builder_a, &make_anchor("cntlin-post")).await;
    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/events"))
        .json(&vec![ixn_after])
        .send()
        .await
        .unwrap();
    assert_ne!(response.status(), 200);
}

/// Submit overlapping events (some already exist on server) that diverge mid-chain.
/// This exercises handle_overlap_submission: the server deduplicates the overlap
/// and stores only the divergent event.
#[tokio::test]
async fn test_overlap_submission_creates_divergence() {
    let Some(harness) = get_harness().await else {
        return;
    };

    // Create KEL: icp + 2 interactions, then fork
    let (inception, mut builder_a) = create_inception().await;
    let prefix = inception.event.prefix;

    let ixn1 = create_interaction(&mut builder_a, &make_anchor("ovl-ixn1")).await;
    let ixn2 = create_interaction(&mut builder_a, &make_anchor("ovl-ixn2")).await;

    // Clone at fork point (after serial 2)
    let mut builder_b = builder_a.clone();

    // Builder A extends to serial 3
    let ixn3_a = create_interaction(&mut builder_a, &make_anchor("ovl-branch-a")).await;

    // Submit full chain from builder A: icp + ixn1 + ixn2 + ixn3_a
    harness
        .client()
        .post(harness.url("/api/v1/kels/events"))
        .json(&vec![inception, ixn1.clone(), ixn2.clone(), ixn3_a])
        .send()
        .await
        .unwrap();

    // Builder B creates a different serial 3
    let ixn3_b = create_interaction(&mut builder_b, &make_anchor("ovl-branch-b")).await;

    // Submit overlapping events: ixn1, ixn2 (already exist) + divergent ixn3_b.
    // Server deduplicates ixn1 and ixn2, then detects ixn3_b diverges from ixn3_a.
    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/events"))
        .json(&vec![ixn1, ixn2, ixn3_b])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let result: SubmitKeyEventsResponse = response.json().await.unwrap();
    assert!(result.applied);
    assert_eq!(result.diverged_at, Some(3));

    // Verify the KEL has divergent events
    let response = harness
        .client()
        .post(harness.url("/api/v1/kels/kel/fetch"))
        .header("content-type", "application/json")
        .json(&serde_json::json!({"prefix": prefix.to_string()}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let page: SignedKeyEventPage = response.json().await.unwrap();
    let serial_3_events: Vec<_> = page.events.iter().filter(|e| e.event.serial == 3).collect();
    assert_eq!(serial_3_events.len(), 2);
}
