//! Integration tests for the KELS service.
//!
//! These tests share a single server instance to test concurrent request handling.
//! Each test creates unique prefixes, so they don't interfere with each other.
//! The shared server is initialized once on first test access.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use cesr::{Digest, Matter};
use ctor::dtor;
use kels::{
    BatchKelsRequest, BatchSubmitResponse, KeyEventBuilder, SignedKeyEvent, SoftwareKeyProvider,
};
use reqwest::Client;
use std::net::TcpListener;
use std::sync::OnceLock;
use testcontainers::{ContainerAsync, Image, core::ImageExt, runners::AsyncRunner};
use testcontainers_modules::{postgres::Postgres, redis::Redis};
use tokio::sync::OnceCell;

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
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
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

        // Start the server in a dedicated thread with its own runtime.
        let db_url = database_url.clone();
        let rd_url = redis_url.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create server runtime");
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(std_listener)
                    .expect("Failed to convert listener");
                if let Err(e) = kels_service::run(listener, &db_url, &rd_url).await {
                    panic!("Server error: {}", e);
                }
            });
        });

        // Wait for server to be ready with timeout detection
        let health_url = format!("{}/health", base_url);
        let startup_client = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
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
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
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
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
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
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap()
    }
}

/// Helper to create a signed inception event.
async fn create_inception() -> (SignedKeyEvent, KeyEventBuilder<SoftwareKeyProvider>) {
    let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
    let icp = builder.incept().await.unwrap();
    (icp, builder)
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
    let Some(harness) = get_harness().await else {
        return;
    };

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
    let Some(harness) = get_harness().await else {
        return;
    };

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
    let Some(harness) = get_harness().await else {
        return;
    };

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
    let Some(harness) = get_harness().await else {
        return;
    };

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
    let Some(harness) = get_harness().await else {
        return;
    };

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
    let Some(harness) = get_harness().await else {
        return;
    };

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
    let Some(harness) = get_harness().await else {
        return;
    };

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
            .post(harness.url("/api/kels/events"))
            .json(&vec![inception])
            .send()
            .await
            .unwrap();
    }

    // List with limit=2
    let response = harness
        .client()
        .get(harness.url("/api/kels/prefixes?limit=2"))
        .send()
        .await
        .expect("Failed to list prefixes");

    assert_eq!(response.status(), 200);
    let result: kels::PrefixListResponse = response.json().await.unwrap();
    assert!(result.prefixes.len() <= 2);
}

#[tokio::test]
async fn test_batch_kels_exceeds_max_prefixes() {
    let Some(harness) = get_harness().await else {
        return;
    };

    // Create request with 51 prefixes (max is 50)
    let prefixes: Vec<String> = (0..51).map(|i| format!("prefix_{}", i)).collect();
    let request = BatchKelsRequest { prefixes };

    let response = harness
        .client()
        .post(harness.url("/api/kels/kels"))
        .json(&request)
        .send()
        .await
        .expect("Failed to send batch request");

    assert_eq!(response.status(), 400);
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
        .post(harness.url("/api/kels/events"))
        .json(&vec![inception])
        .send()
        .await
        .expect("Failed to submit events");

    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn test_batch_get_kels_with_missing_prefixes() {
    let Some(harness) = get_harness().await else {
        return;
    };

    // Create one KEL
    let (inception, _) = create_inception().await;
    let existing_prefix = inception.event.prefix.clone();

    harness
        .client()
        .post(harness.url("/api/kels/events"))
        .json(&vec![inception])
        .send()
        .await
        .unwrap();

    // Request with both existing and non-existing prefixes
    let request = BatchKelsRequest {
        prefixes: vec![existing_prefix.clone(), "nonexistent_prefix".to_string()],
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

    // Both prefixes should be in result, but nonexistent will have empty array
    assert!(result.contains_key(&existing_prefix));
    assert!(result.contains_key("nonexistent_prefix"));
    assert!(!result.get(&existing_prefix).unwrap().is_empty());
    assert!(result.get("nonexistent_prefix").unwrap().is_empty());
}

#[tokio::test]
async fn test_submit_event_invalid_signature_format() {
    let Some(harness) = get_harness().await else {
        return;
    };

    // Create inception and corrupt signature format
    let (mut inception, _) = create_inception().await;
    inception.signatures[0].signature = "invalid_not_cesr_signature".to_string();

    let response = harness
        .client()
        .post(harness.url("/api/kels/events"))
        .json(&vec![inception])
        .send()
        .await
        .expect("Failed to submit events");

    assert_eq!(response.status(), 400);
    let error: kels::ErrorResponse = response.json().await.unwrap();
    assert!(error.error.contains("Invalid signature format"));
}

#[tokio::test]
async fn test_submit_rotation_event() {
    let Some(harness) = get_harness().await else {
        return;
    };

    // Create inception
    let (inception, mut builder) = create_inception().await;
    let prefix = inception.event.prefix.clone();

    // Submit inception
    harness
        .client()
        .post(harness.url("/api/kels/events"))
        .json(&vec![inception])
        .send()
        .await
        .unwrap();

    // Create rotation event
    let rot = builder.rotate().await.unwrap();

    // Submit rotation
    let response = harness
        .client()
        .post(harness.url("/api/kels/events"))
        .json(&vec![rot])
        .send()
        .await
        .expect("Failed to submit rotation");

    assert_eq!(response.status(), 200);
    let result: BatchSubmitResponse = response.json().await.unwrap();
    assert!(result.accepted);

    // Verify KEL now has 2 events
    let response = harness
        .client()
        .get(harness.url(&format!("/api/kels/kel/{}", prefix)))
        .send()
        .await
        .unwrap();

    let events: Vec<SignedKeyEvent> = response.json().await.unwrap();
    assert_eq!(events.len(), 2);
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
        prefixes.push(inception.event.prefix.clone());
        harness
            .client()
            .post(harness.url("/api/kels/events"))
            .json(&vec![inception])
            .send()
            .await
            .unwrap();
    }

    // Get first page with limit=1
    let response = harness
        .client()
        .get(harness.url("/api/kels/prefixes?limit=1"))
        .send()
        .await
        .expect("Failed to list prefixes");

    assert_eq!(response.status(), 200);
    let result: kels::PrefixListResponse = response.json().await.unwrap();
    assert_eq!(result.prefixes.len(), 1);

    // Use cursor to get next page if available
    if let Some(cursor) = &result.next_cursor {
        let response = harness
            .client()
            .get(harness.url(&format!("/api/kels/prefixes?since={}&limit=1", cursor)))
            .send()
            .await
            .expect("Failed to list prefixes with cursor");

        assert_eq!(response.status(), 200);
        let next_result: kels::PrefixListResponse = response.json().await.unwrap();
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
    let prefix = inception.event.prefix.clone();

    // Submit inception
    harness
        .client()
        .post(harness.url("/api/kels/events"))
        .json(&vec![inception])
        .send()
        .await
        .unwrap();

    // Create decommission event - decommission() adds the dual-signed event to internal KEL
    let _ = builder.decommission().await.unwrap();

    // Get the properly signed decommission event from builder's KEL
    let events = builder.events();
    let signed_dec = events.last().unwrap().clone();

    // Submit decommission
    let response = harness
        .client()
        .post(harness.url("/api/kels/events"))
        .json(&vec![signed_dec])
        .send()
        .await
        .expect("Failed to submit decommission");

    assert_eq!(response.status(), 200);
    let result: BatchSubmitResponse = response.json().await.unwrap();
    assert!(result.accepted);

    // Verify KEL now has 2 events (icp + dec)
    let response = harness
        .client()
        .get(harness.url(&format!("/api/kels/kel/{}", prefix)))
        .send()
        .await
        .unwrap();

    let events: Vec<SignedKeyEvent> = response.json().await.unwrap();
    assert_eq!(events.len(), 2);
}

#[tokio::test]
async fn test_get_kel_not_found_with_audit() {
    let Some(harness) = get_harness().await else {
        return;
    };

    let response = harness
        .client()
        .get(harness.url("/api/kels/kel/Enonexistent_prefix_for_audit?audit=true"))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 404);
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
        .post(harness.url("/api/kels/events"))
        .json(&vec![inception])
        .send()
        .await
        .unwrap();

    // Create recovery event (with rotation) - this creates dual-signed event internally
    let _ = builder.recover(true).await.unwrap();

    // Get the properly signed recovery event and strip one signature for testing
    let events = builder.events();
    // Recovery creates a rec event first, then a rot event
    let rec_event = events.iter().find(|e| e.event.is_recover()).unwrap();
    let mut signed_rec = rec_event.clone();
    // Remove one signature to trigger dual signature validation error
    signed_rec.signatures.truncate(1);

    let response = harness
        .client()
        .post(harness.url("/api/kels/events"))
        .json(&vec![signed_rec])
        .send()
        .await
        .expect("Failed to submit recovery");

    assert_eq!(response.status(), 400);
    let error: kels::ErrorResponse = response.json().await.unwrap();
    assert!(error.error.contains("Dual signatures required"));
}
