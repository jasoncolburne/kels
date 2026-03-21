//! Integration tests for the KELS service.
//!
//! These tests share a single server instance to test concurrent request handling.
//! Each test creates unique prefixes, so they don't interfere with each other.
//! The shared server is initialized once on first test access.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use cesr::{Digest, Matter};
use chrono::Utc;
use ctor::dtor;
use kels::{
    KeyEventBuilder, SignedKeyEvent, SignedKeyEventPage, SoftwareKeyProvider, SubmitEventsResponse,
    VerificationKeyCode,
};
use reqwest::Client;
use std::{net::TcpListener, sync::OnceLock, time::Duration};
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
    let result: SubmitEventsResponse = response.json().await.unwrap();
    assert!(result.applied);
    assert!(result.diverged_at.is_none());

    // Retrieve the KEL
    let response = harness
        .client()
        .get(harness.url(&format!("/api/kels/kel/{}", prefix)))
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
    let result: SubmitEventsResponse = response.json().await.unwrap();
    assert!(result.applied);

    // Retrieve and verify
    let response = harness
        .client()
        .get(harness.url(&format!("/api/kels/kel/{}", prefix)))
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
        .get(harness.url("/api/kels/kel/Enonexistent_prefix_that_does_not_exist"))
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
        .post(harness.url("/api/kels/events"))
        .json(&vec![inception])
        .send()
        .await
        .unwrap();

    // List prefixes via signed POST
    let request = kels::SignedRequest {
        payload: kels::PrefixesRequest {
            timestamp: Utc::now().timestamp(),
            nonce: kels::generate_nonce(),
            since: None,
            limit: None,
        },
        peer_prefix: "mock".to_string(),
        signature: "mock".to_string(),
    };

    let response = harness
        .client()
        .post(harness.url("/api/test/prefixes"))
        .json(&request)
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
        let result: SubmitEventsResponse = response.json().await.unwrap();
        assert!(result.applied);
    }

    // Should still only have one event
    let response = harness
        .client()
        .get(harness.url(&format!("/api/kels/kel/{}", prefix)))
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
        .post(harness.url("/api/kels/events"))
        .json(&Vec::<SignedKeyEvent>::new())
        .send()
        .await
        .expect("Failed to submit events");

    assert_eq!(response.status(), 200);
    let result: SubmitEventsResponse = response.json().await.unwrap();
    assert!(result.applied);
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

    // Get KEL
    let response = harness
        .client()
        .get(harness.url(&format!("/api/kels/kel/{}", prefix)))
        .send()
        .await
        .expect("Failed to get KEL");

    assert_eq!(response.status(), 200);
    let page: SignedKeyEventPage = response.json().await.unwrap();
    assert_eq!(page.events.len(), 1);

    // Get audit records from separate endpoint
    let response = harness
        .client()
        .get(harness.url(&format!("/api/kels/kel/{}/audit", prefix)))
        .send()
        .await
        .expect("Failed to get audit records");

    assert_eq!(response.status(), 200);
    let audit_records: Vec<kels::KelsAuditRecord> = response.json().await.unwrap();
    // No audit records for a simple KEL
    assert!(audit_records.is_empty());
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

    // List with limit=2 via signed POST
    let request = kels::SignedRequest {
        payload: kels::PrefixesRequest {
            timestamp: Utc::now().timestamp(),
            nonce: kels::generate_nonce(),
            since: None,
            limit: Some(2),
        },
        peer_prefix: "mock".to_string(),
        signature: "mock".to_string(),
    };

    let response = harness
        .client()
        .post(harness.url("/api/test/prefixes"))
        .json(&request)
        .send()
        .await
        .expect("Failed to list prefixes");

    assert_eq!(response.status(), 200);
    let result: kels::PrefixListResponse = response.json().await.unwrap();
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
        .post(harness.url("/api/kels/events"))
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
    let result: SubmitEventsResponse = response.json().await.unwrap();
    assert!(result.applied);

    // Verify KEL now has 2 events
    let response = harness
        .client()
        .get(harness.url(&format!("/api/kels/kel/{}", prefix)))
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
        prefixes.push(inception.event.prefix.clone());
        harness
            .client()
            .post(harness.url("/api/kels/events"))
            .json(&vec![inception])
            .send()
            .await
            .unwrap();
    }

    // Get first page with limit=1 via signed POST
    let request = kels::SignedRequest {
        payload: kels::PrefixesRequest {
            timestamp: Utc::now().timestamp(),
            nonce: kels::generate_nonce(),
            since: None,
            limit: Some(1),
        },
        peer_prefix: "mock".to_string(),
        signature: "mock".to_string(),
    };

    let response = harness
        .client()
        .post(harness.url("/api/test/prefixes"))
        .json(&request)
        .send()
        .await
        .expect("Failed to list prefixes");

    assert_eq!(response.status(), 200);
    let result: kels::PrefixListResponse = response.json().await.unwrap();
    assert_eq!(result.prefixes.len(), 1);

    // Use cursor to get next page if available
    if let Some(cursor) = &result.next_cursor {
        let request = kels::SignedRequest {
            payload: kels::PrefixesRequest {
                timestamp: Utc::now().timestamp(),
                nonce: kels::generate_nonce(),
                since: Some(cursor.clone()),
                limit: Some(1),
            },
            peer_prefix: "mock".to_string(),
            signature: "mock".to_string(),
        };

        let response = harness
            .client()
            .post(harness.url("/api/test/prefixes"))
            .json(&request)
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
    let events = builder.pending_events();
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
    let result: SubmitEventsResponse = response.json().await.unwrap();
    assert!(result.applied);

    // Verify KEL now has 2 events (icp + dec)
    let response = harness
        .client()
        .get(harness.url(&format!("/api/kels/kel/{}", prefix)))
        .send()
        .await
        .unwrap();

    let page: SignedKeyEventPage = response.json().await.unwrap();
    assert_eq!(page.events.len(), 2);
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
    let events = builder.pending_events();
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

// ==================== Divergence / Recovery / Contest ====================

/// Submit conflicting interactions at the same serial to create divergence.
#[tokio::test]
async fn test_divergence_creation() {
    let Some(harness) = get_harness().await else {
        return;
    };

    // Create KEL: icp + 2 interactions
    let (inception, mut builder_a) = create_inception().await;
    let prefix = inception.event.prefix.clone();

    let ixn1 = create_interaction(&mut builder_a, &make_anchor("ixn1")).await;
    let ixn2 = create_interaction(&mut builder_a, &make_anchor("ixn2")).await;

    // Submit icp + 2 interactions
    let response = harness
        .client()
        .post(harness.url("/api/kels/events"))
        .json(&vec![inception, ixn1, ixn2])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let result: SubmitEventsResponse = response.json().await.unwrap();
    assert!(result.applied);
    assert!(result.diverged_at.is_none());

    // Clone builder at current state (after serial 2) to create a fork
    let mut builder_b = builder_a.clone();

    // Builder A creates interaction at serial 3
    let ixn3_a = create_interaction(&mut builder_a, &make_anchor("branch-a")).await;

    // Submit builder A's interaction
    let response = harness
        .client()
        .post(harness.url("/api/kels/events"))
        .json(&vec![ixn3_a])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let result: SubmitEventsResponse = response.json().await.unwrap();
    assert!(result.applied);
    assert!(result.diverged_at.is_none());

    // Builder B creates a different interaction at serial 3 (same previous)
    let ixn3_b = create_interaction(&mut builder_b, &make_anchor("branch-b")).await;

    // Submit builder B's conflicting interaction — should cause divergence
    let response = harness
        .client()
        .post(harness.url("/api/kels/events"))
        .json(&vec![ixn3_b])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let result: SubmitEventsResponse = response.json().await.unwrap();
    assert!(result.applied);
    assert_eq!(result.diverged_at, Some(3));

    // GET the KEL and verify divergence: two events at serial 3
    let response = harness
        .client()
        .get(harness.url(&format!("/api/kels/kel/{}", prefix)))
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
    let prefix = inception.event.prefix.clone();

    let ixn1 = create_interaction(&mut builder_a, &make_anchor("rec-ixn1")).await;
    let ixn2 = create_interaction(&mut builder_a, &make_anchor("rec-ixn2")).await;

    harness
        .client()
        .post(harness.url("/api/kels/events"))
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
        .post(harness.url("/api/kels/events"))
        .json(&vec![ixn3_a])
        .send()
        .await
        .unwrap();

    let ixn3_b = create_interaction(&mut builder_b, &make_anchor("rec-branch-b")).await;
    let response = harness
        .client()
        .post(harness.url("/api/kels/events"))
        .json(&vec![ixn3_b])
        .send()
        .await
        .unwrap();
    let result: SubmitEventsResponse = response.json().await.unwrap();
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
        .post(harness.url("/api/kels/events"))
        .json(&recovery_events)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let result: SubmitEventsResponse = response.json().await.unwrap();
    assert!(result.applied);

    // GET KEL — should show the recovered chain
    let response = harness
        .client()
        .get(harness.url(&format!("/api/kels/kel/{}", prefix)))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let page: SignedKeyEventPage = response.json().await.unwrap();
    // After recovery, the KEL should have the authoritative branch events
    assert!(page.events.iter().any(|e| e.event.is_recover()));

    // Subsequent normal appends should work
    let ixn_after = create_interaction(&mut builder_a, &make_anchor("post-recovery")).await;
    let response = harness
        .client()
        .post(harness.url("/api/kels/events"))
        .json(&vec![ixn_after])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let result: SubmitEventsResponse = response.json().await.unwrap();
    assert!(result.applied);
    assert!(result.diverged_at.is_none());
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
    let prefix = inception.event.prefix.clone();

    let ixn1 = create_interaction(&mut builder_a, &make_anchor("cnt-ixn1")).await;
    let ixn2 = create_interaction(&mut builder_a, &make_anchor("cnt-ixn2")).await;

    harness
        .client()
        .post(harness.url("/api/kels/events"))
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
        .post(harness.url("/api/kels/events"))
        .json(&vec![ror_event])
        .send()
        .await
        .unwrap();

    // Builder B (adversary who also knows recovery key) submits a contest at serial 3.
    // This hits handle_overlap_submission: old events reveal recovery, new event is contest → Contested.
    let contest_event = builder_b.contest().await.unwrap();

    let response = harness
        .client()
        .post(harness.url("/api/kels/events"))
        .json(&vec![contest_event])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let result: SubmitEventsResponse = response.json().await.unwrap();
    assert!(result.applied);
    assert!(result.diverged_at.is_some());

    // GET KEL — should contain contest event
    let response = harness
        .client()
        .get(harness.url(&format!("/api/kels/kel/{}", prefix)))
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
        .post(harness.url("/api/kels/events"))
        .json(&vec![ixn_after])
        .send()
        .await
        .unwrap();
    // Contested KEL should reject new events
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
    let prefix = inception.event.prefix.clone();

    let ixn1 = create_interaction(&mut builder_a, &make_anchor("ovl-ixn1")).await;
    let ixn2 = create_interaction(&mut builder_a, &make_anchor("ovl-ixn2")).await;

    // Clone at fork point (after serial 2)
    let mut builder_b = builder_a.clone();

    // Builder A extends to serial 3
    let ixn3_a = create_interaction(&mut builder_a, &make_anchor("ovl-branch-a")).await;

    // Submit full chain from builder A: icp + ixn1 + ixn2 + ixn3_a
    harness
        .client()
        .post(harness.url("/api/kels/events"))
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
        .post(harness.url("/api/kels/events"))
        .json(&vec![ixn1, ixn2, ixn3_b])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let result: SubmitEventsResponse = response.json().await.unwrap();
    assert!(result.applied);
    assert_eq!(result.diverged_at, Some(3));

    // Verify the KEL has divergent events
    let response = harness
        .client()
        .get(harness.url(&format!("/api/kels/kel/{}", prefix)))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let page: SignedKeyEventPage = response.json().await.unwrap();
    let serial_3_events: Vec<_> = page.events.iter().filter(|e| e.event.serial == 3).collect();
    assert_eq!(serial_3_events.len(), 2);
}
