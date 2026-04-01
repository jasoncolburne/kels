//! Integration tests for the KELS SADStore service.
//!
//! Shared server instance with Postgres + MinIO testcontainers.
//! Tests cover: PUT/GET SAD objects, chain record submission/fetch,
//! prefix computation, chain integrity rejection, effective SAID.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{net::TcpListener, sync::OnceLock, time::Duration};
use tokio::{sync::OnceCell, time::sleep};

use ctor::dtor;
use kels_core::{SadPointer, compute_sad_prefix};
use reqwest::Client;
use testcontainers::{
    ContainerAsync, GenericImage, Image,
    core::{ImageExt, WaitFor},
    runners::AsyncRunner,
};
use testcontainers_modules::postgres::Postgres;
use verifiable_storage::SelfAddressed;

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

async fn retry_get_port<I: Image>(container: &ContainerAsync<I>, port: u16) -> Option<u16> {
    for _ in 0..10 {
        if let Ok(p) = container.get_host_port_ipv4(port).await {
            return Some(p);
        }
        sleep(Duration::from_millis(100)).await;
    }
    None
}

async fn retry_get_port_generic(
    container: &ContainerAsync<GenericImage>,
    port: u16,
) -> Option<u16> {
    for _ in 0..10 {
        if let Ok(p) = container.get_host_port_ipv4(port).await {
            return Some(p);
        }
        sleep(Duration::from_millis(100)).await;
    }
    None
}

struct SharedHarness {
    base_url: String,
    _postgres: ContainerAsync<Postgres>,
    _minio: ContainerAsync<GenericImage>,
}

static SHARED_HARNESS: OnceLock<OnceCell<Option<SharedHarness>>> = OnceLock::new();

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
        // Start Postgres
        let postgres = Postgres::default()
            .with_label(TEST_CONTAINER_LABEL.0, TEST_CONTAINER_LABEL.1)
            .start()
            .await
            .expect("Postgres container failed to start");

        let pg_host = postgres
            .get_host()
            .await
            .expect("failed to get Postgres host");
        let pg_port = retry_get_port(&postgres, 5432)
            .await
            .expect("failed to get Postgres port");
        let database_url = format!(
            "postgres://postgres:postgres@{}:{}/postgres",
            pg_host, pg_port
        );

        // Start MinIO
        let minio = GenericImage::new("minio/minio", "latest")
            .with_exposed_port(9000.into())
            .with_wait_for(WaitFor::message_on_stderr("API:"))
            .with_label(TEST_CONTAINER_LABEL.0, TEST_CONTAINER_LABEL.1)
            .with_env_var("MINIO_ROOT_USER", "minioadmin")
            .with_env_var("MINIO_ROOT_PASSWORD", "minioadmin")
            .with_cmd(vec!["server".to_string(), "/data".to_string()])
            .start()
            .await
            .expect("MinIO container failed to start");

        let minio_host = minio.get_host().await.expect("failed to get MinIO host");
        let minio_port = retry_get_port_generic(&minio, 9000)
            .await
            .expect("failed to get MinIO port");
        let minio_endpoint = format!("http://{}:{}", minio_host, minio_port);

        // Bind to random port
        let std_listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind");
        let port = std_listener.local_addr().unwrap().port();
        std_listener.set_nonblocking(true).unwrap();
        let base_url = format!("http://127.0.0.1:{}", port);

        // Set env vars for the server
        unsafe {
            std::env::set_var("MINIO_ENDPOINT", &minio_endpoint);
            std::env::set_var("MINIO_REGION", "us-east-1");
            std::env::set_var("MINIO_ACCESS_KEY", "minioadmin");
            std::env::set_var("MINIO_SECRET_KEY", "minioadmin");
            std::env::set_var("KELS_SAD_BUCKET", "kels-sad-test");
            std::env::set_var("KELS_TEST_ENDPOINTS", "true");
        }

        // Start the server
        let db_url = database_url.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create server runtime");
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(std_listener)
                    .expect("Failed to convert listener");
                // No KELS service for chain signature verification in tests —
                // chain submission tests will fail sig verification. That's expected.
                // We test SAD object operations and structural validation.
                if let Err(e) =
                    kels_sadstore::run(listener, &db_url, None, "http://localhost:1", Vec::new())
                        .await
                {
                    panic!("Server error: {}", e);
                }
            });
        });

        // Wait for ready
        let health_url = format!("{}/health", base_url);
        let startup_client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        for _ in 0..50 {
            if let Ok(resp) = startup_client.get(&health_url).send().await
                && resp.status().is_success()
            {
                eprintln!("Shared test server ready at {}", base_url);
                return Some(Self {
                    base_url,
                    _postgres: postgres,
                    _minio: minio,
                });
            }
            sleep(Duration::from_millis(100)).await;
        }

        panic!("Server did not become ready in time");
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

// ==================== SAD Object Tests ====================

#[tokio::test]
async fn test_health_check() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let resp = harness
        .client()
        .get(harness.url("/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_put_and_get_sad_object() {
    let Some(harness) = get_harness().await else {
        return;
    };

    // Create a self-addressed JSON object
    let mut object = serde_json::json!({
        "said": "",
        "data": "test-content-123"
    });
    object.derive_said().unwrap();
    let said = object.get_said();

    // POST the object
    let resp = harness
        .client()
        .post(harness.url("/api/v1/sad"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&object).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // GET the object back
    let resp = harness
        .client()
        .get(harness.url(&format!("/api/v1/sad/{}", said)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let retrieved: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(retrieved.get_said(), said);
}

#[tokio::test]
async fn test_put_sad_object_idempotent() {
    let Some(harness) = get_harness().await else {
        return;
    };

    let mut object = serde_json::json!({
        "said": "",
        "data": "idempotent-test"
    });
    object.derive_said().unwrap();

    let body = serde_json::to_vec(&object).unwrap();

    // First POST
    let resp = harness
        .client()
        .post(harness.url("/api/v1/sad"))
        .header("content-type", "application/json")
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // Second POST — should return 200 (exists)
    let resp = harness
        .client()
        .post(harness.url("/api/v1/sad"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_post_sad_object_wrong_said_rejected() {
    let Some(harness) = get_harness().await else {
        return;
    };

    // Object with a tampered SAID that won't verify
    let object = serde_json::json!({
        "said": "Ewrong_said_that_does_not_match_content_",
        "data": "wrong-said-test"
    });

    let resp = harness
        .client()
        .post(harness.url("/api/v1/sad"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&object).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_get_sad_object_not_found() {
    let Some(harness) = get_harness().await else {
        return;
    };

    let resp = harness
        .client()
        .get(harness.url("/api/v1/sad/Enonexistent_said_should_return_404_______"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_post_sad_object_invalid_json_rejected() {
    let Some(harness) = get_harness().await else {
        return;
    };

    let resp = harness
        .client()
        .post(harness.url("/api/v1/sad"))
        .header("content-type", "application/json")
        .body("not json")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

// ==================== Prefix Computation Tests ====================

#[tokio::test]
async fn test_compute_sad_prefix_deterministic() {
    let p1 = compute_sad_prefix("Ekel_prefix_a", "kels/v1/mlkem-pubkey").unwrap();
    let p2 = compute_sad_prefix("Ekel_prefix_a", "kels/v1/mlkem-pubkey").unwrap();
    assert_eq!(p1, p2);
}

#[tokio::test]
async fn test_compute_sad_prefix_different_inputs() {
    let p1 = compute_sad_prefix("Ekel_prefix_a", "kels/v1/mlkem-pubkey").unwrap();
    let p2 = compute_sad_prefix("Ekel_prefix_b", "kels/v1/mlkem-pubkey").unwrap();
    let p3 = compute_sad_prefix("Ekel_prefix_a", "kels/v1/other-kind").unwrap();
    assert_ne!(p1, p2);
    assert_ne!(p1, p3);
}

// ==================== Chain Record Tests ====================

#[tokio::test]
async fn test_chain_fetch_not_found() {
    let Some(harness) = get_harness().await else {
        return;
    };

    let resp = harness
        .client()
        .get(harness.url("/api/v1/sad/pointers/Enonexistent_chain_prefix_________________"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_effective_said_not_found() {
    let Some(harness) = get_harness().await else {
        return;
    };

    let resp =
        harness
            .client()
            .get(harness.url(
                "/api/v1/sad/pointers/Enonexistent_chain_prefix_________________/effective-said",
            ))
            .send()
            .await
            .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_submit_record_invalid_said_rejected() {
    let Some(harness) = get_harness().await else {
        return;
    };

    // Create a record but tamper with the SAID
    let mut pointer = SadPointer::create(
        "Ekel_test_prefix".to_string(),
        "kels/v1/test-kind".to_string(),
        None,
    )
    .unwrap();
    pointer.kind = "tampered".to_string(); // Tamper after SAID computation

    let records = vec![kels_core::SignedSadPointer {
        pointer,
        signature: "fake_sig".to_string(),
        establishment_serial: 0,
    }];

    let resp = harness
        .client()
        .post(harness.url("/api/v1/sad/pointers"))
        .json(&records)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

// ==================== Prefix Listing Tests ====================

#[tokio::test]
async fn test_list_prefixes_empty() {
    let Some(harness) = get_harness().await else {
        return;
    };

    let body = kels_core::SignedRequest {
        payload: kels_core::PaginatedSelfAddressedRequest {
            timestamp: chrono::Utc::now().timestamp(),
            nonce: kels_core::generate_nonce(),
            cursor: None,
            limit: None,
        },
        peer_prefix: "test".to_string(),
        signature: "test".to_string(),
    };

    let resp = harness
        .client()
        .post(harness.url("/api/test/sad/prefixes"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: kels_core::PrefixListResponse = resp.json().await.unwrap();
    // May or may not be empty depending on test ordering, but should succeed
    assert!(body.prefixes.len() <= 100);
}

#[tokio::test]
async fn test_list_objects_empty() {
    let Some(harness) = get_harness().await else {
        return;
    };

    let body = kels_core::SignedRequest {
        payload: kels_core::PaginatedSelfAddressedRequest {
            timestamp: chrono::Utc::now().timestamp(),
            nonce: kels_core::generate_nonce(),
            cursor: None,
            limit: None,
        },
        peer_prefix: "test".to_string(),
        signature: "test".to_string(),
    };

    let resp = harness
        .client()
        .post(harness.url("/api/test/sad/saids"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}
