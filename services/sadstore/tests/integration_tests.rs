//! Integration tests for the KELS SADStore service.
//!
//! Shared server instance with Postgres + RustFS testcontainers.
//! Tests cover: PUT/GET SAD objects, SAD event submission/fetch,
//! prefix computation, chain integrity rejection, effective SAID.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{collections::HashMap, net::TcpListener, sync::OnceLock, time::Duration};
use tokio::{sync::OnceCell, time::sleep};

use cesr::{test_digest, test_signature};
use ctor::dtor;
use kels_core::{SadEvent, compute_sad_event_prefix};
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
    objects_endpoint: String,
    _postgres: ContainerAsync<Postgres>,
    _objects: ContainerAsync<GenericImage>,
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

        // Start the object store (RustFS)
        let objects = GenericImage::new("rustfs/rustfs", "latest")
            .with_exposed_port(9000.into())
            .with_wait_for(WaitFor::seconds(5))
            .with_label(TEST_CONTAINER_LABEL.0, TEST_CONTAINER_LABEL.1)
            .with_env_var("RUSTFS_ACCESS_KEY", "rustfsadmin")
            .with_env_var("RUSTFS_SECRET_KEY", "rustfsadmin")
            .with_env_var("RUSTFS_VOLUMES", "/data")
            .with_env_var("RUSTFS_ADDRESS", "0.0.0.0:9000")
            .with_env_var("RUSTFS_CONSOLE_ADDRESS", "0.0.0.0:9001")
            .start()
            .await
            .expect("object store container failed to start");

        let objects_host = objects
            .get_host()
            .await
            .expect("failed to get object store host");
        let objects_port = retry_get_port_generic(&objects, 9000)
            .await
            .expect("failed to get object store port");
        let objects_endpoint = format!("http://{}:{}", objects_host, objects_port);

        // Bind to random port
        let std_listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind");
        let port = std_listener.local_addr().unwrap().port();
        std_listener.set_nonblocking(true).unwrap();
        let base_url = format!("http://127.0.0.1:{}", port);

        // Set env vars for the server
        unsafe {
            std::env::set_var("OBJECTS_ENDPOINT", &objects_endpoint);
            std::env::set_var("OBJECTS_REGION", "us-east-1");
            std::env::set_var("OBJECTS_ACCESS_KEY", "rustfsadmin");
            std::env::set_var("OBJECTS_SECRET_KEY", "rustfsadmin");
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
                    objects_endpoint,
                    _postgres: postgres,
                    _objects: objects,
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

    /// Build an `ObjectStore` client pointing at the harness's RustFS
    /// container. Used by tests that need to manipulate the object store
    /// directly (e.g. simulating an object-store-only orphan to verify
    /// recovery via §5.1's RustFS-first ordered idempotent store).
    fn object_store_client(&self) -> kels_sadstore::ObjectStore {
        kels_sadstore::ObjectStore::new(
            &self.objects_endpoint,
            "us-east-1",
            "kels-sad-test",
            "rustfsadmin",
            "rustfsadmin",
        )
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

    // Fetch the object back (SAID in body, not URL)
    let resp = harness
        .client()
        .post(harness.url("/api/v1/sad/fetch"))
        .header("content-type", "application/json")
        .json(&serde_json::json!({ "said": said.to_string() }))
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
        "said": "Kwrong_said_that_does_not_match_content_data",
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
async fn test_fetch_sad_object_not_found() {
    let Some(harness) = get_harness().await else {
        return;
    };

    let resp = harness
        .client()
        .post(harness.url("/api/v1/sad/fetch"))
        .header("content-type", "application/json")
        .json(&serde_json::json!({ "said": test_digest("nonexistent").to_string() }))
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

// ==================== §5.1 Atomicity Tests ====================
// `SadObjectIndex::store` writes object store first then PG (auto-commit);
// HEAD-checks consult PG, not object store. The asymmetric behaviors below
// only become observable post-§5.1 — under the prior shape, a transient
// object-store orphan would short-circuit subsequent POSTs (sticky), and
// tests crashing between PUT and COMMIT would leave PG-orphans.

#[tokio::test]
async fn test_object_store_orphan_heals_on_repost() {
    // Simulate an object-store-only orphan (e.g. process crashed between
    // PUT and PG INSERT under the new ordering). A subsequent POST of the
    // same SAD must heal the orphan: idempotent PUT on RustFS, then PG
    // INSERT records the entry. Pre-§5.1 the HEAD check on object store
    // returned true and short-circuited without writing PG, leaving the
    // orphan sticky.
    let Some(harness) = get_harness().await else {
        return;
    };

    let mut object = serde_json::json!({
        "said": "",
        "data": "object-store-orphan-heal-test",
    });
    object.derive_said().unwrap();
    let said = object.get_said();
    let bytes = serde_json::to_vec(&object).unwrap();

    // Pre-condition: place bytes in object store directly, bypassing PG.
    harness
        .object_store_client()
        .put(&said, &bytes)
        .await
        .expect("direct object-store put failed");

    // Existence check should report `not tracked` (PG is the source of truth).
    let resp = harness
        .client()
        .post(harness.url("/api/v1/sad/exists"))
        .json(&serde_json::json!({ "said": said.to_string() }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        404,
        "PG-side existence check should miss before heal POST"
    );

    // POST the SAD — must succeed (201) and heal the orphan by inserting PG.
    let resp = harness
        .client()
        .post(harness.url("/api/v1/sad"))
        .header("content-type", "application/json")
        .body(bytes)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        201,
        "POST should heal object-store orphan and create PG entry"
    );

    // Post-condition: PG now tracks the object; existence reports OK.
    let resp = harness
        .client()
        .post(harness.url("/api/v1/sad/exists"))
        .json(&serde_json::json!({ "said": said.to_string() }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "PG-side existence check should hit after heal POST"
    );
}

#[tokio::test]
async fn test_head_check_consults_pg_not_object_store() {
    // After a successful POST, PG holds the entry. If object-store bytes
    // are independently deleted (external loss / TTL race / operator
    // intervention), the next POST of the same SAD must still short-
    // circuit to 200 because PG remains the source of truth post-§5.1.
    // Pre-§5.1 the HEAD check on object store would have missed and the
    // handler would have proceeded into `SadObjectIndex::store`, which
    // hit the DuplicateRecord shortcut and returned without rewriting
    // bytes — same observable outcome but for the wrong reason.
    let Some(harness) = get_harness().await else {
        return;
    };

    let mut object = serde_json::json!({
        "said": "",
        "data": "head-check-pg-source-of-truth",
    });
    object.derive_said().unwrap();
    let said = object.get_said();
    let bytes = serde_json::to_vec(&object).unwrap();

    // Initial POST populates both stores.
    let resp = harness
        .client()
        .post(harness.url("/api/v1/sad"))
        .header("content-type", "application/json")
        .body(bytes.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // Independently delete object-store bytes.
    harness
        .object_store_client()
        .delete(&said)
        .await
        .expect("direct object-store delete failed");

    // Re-POST: HEAD-check via PG sees the entry → 200 short-circuit.
    let resp = harness
        .client()
        .post(harness.url("/api/v1/sad"))
        .header("content-type", "application/json")
        .body(bytes)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "PG HEAD check should short-circuit even after object-store byte loss"
    );
}

#[tokio::test]
async fn test_repost_is_idempotent_under_pg_head_check() {
    // Plain idempotency under §5.1: repeat POSTs of identical bytes
    // produce 201 then 200 (HEAD via PG). Mirrors
    // `test_put_sad_object_idempotent` but pinned to the post-§5.1
    // contract: the second response is driven by PG presence, not
    // object-store presence.
    let Some(harness) = get_harness().await else {
        return;
    };

    let mut object = serde_json::json!({
        "said": "",
        "data": "duplicate-record-idempotence",
    });
    object.derive_said().unwrap();
    let bytes = serde_json::to_vec(&object).unwrap();

    let r1 = harness
        .client()
        .post(harness.url("/api/v1/sad"))
        .header("content-type", "application/json")
        .body(bytes.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(r1.status(), 201);

    let r2 = harness
        .client()
        .post(harness.url("/api/v1/sad"))
        .header("content-type", "application/json")
        .body(bytes)
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), 200);
}

// ==================== Prefix Computation Tests ====================

#[tokio::test]
async fn test_compute_sad_event_prefix_deterministic() {
    let p1 =
        compute_sad_event_prefix(test_digest("kel-prefix-a"), "kels/sad/v1/keys/mlkem").unwrap();
    let p2 =
        compute_sad_event_prefix(test_digest("kel-prefix-a"), "kels/sad/v1/keys/mlkem").unwrap();
    assert_eq!(p1, p2);
}

#[tokio::test]
async fn test_compute_sad_event_prefix_different_inputs() {
    let p1 =
        compute_sad_event_prefix(test_digest("kel-prefix-a"), "kels/sad/v1/keys/mlkem").unwrap();
    let p2 =
        compute_sad_event_prefix(test_digest("kel-prefix-b"), "kels/sad/v1/keys/mlkem").unwrap();
    let p3 = compute_sad_event_prefix(test_digest("kel-prefix-a"), "kels/v1/other-kind").unwrap();
    assert_ne!(p1, p2);
    assert_ne!(p1, p3);
}

// ==================== SEL Tests ====================

#[tokio::test]
async fn test_sel_fetch_not_found() {
    let Some(harness) = get_harness().await else {
        return;
    };

    let nonexistent = test_digest("nonexistent-chain-prefix");
    let body = kels_core::SadEventPageRequest {
        prefix: nonexistent,
        since: None,
        limit: None,
    };
    let resp = harness
        .client()
        .post(harness.url("/api/v1/sad/events/fetch"))
        .json(&body)
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

    let nonexistent = test_digest("nonexistent-chain-prefix");
    let body = kels_core::SadEventEffectiveSaidRequest {
        prefix: nonexistent,
    };
    let resp = harness
        .client()
        .post(harness.url("/api/v1/sad/events/effective-said"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_submit_event_invalid_said_rejected() {
    let Some(harness) = get_harness().await else {
        return;
    };

    // Create an event but tamper with the SAID
    let mut event = SadEvent::icp(test_digest("kel-test-prefix"), "kels/v1/test-kind").unwrap();
    event.topic = "tampered".to_string(); // Tamper after SAID computation

    let events = vec![event];

    let resp = harness
        .client()
        .post(harness.url("/api/v1/sad/events"))
        .json(&events)
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
        payload: kels_core::PaginatedSelfAddressedRequest::create(
            kels_core::generate_nonce(),
            None,
            None,
        )
        .unwrap(),
        signatures: HashMap::from([(test_digest("test"), test_signature("test"))]),
    };

    let resp = harness
        .client()
        .post(harness.url("/api/test/sad/events/prefixes"))
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
async fn test_list_iel_prefixes_empty() {
    let Some(harness) = get_harness().await else {
        return;
    };

    let body = kels_core::SignedRequest {
        payload: kels_core::PaginatedSelfAddressedRequest::create(
            kels_core::generate_nonce(),
            None,
            None,
        )
        .unwrap(),
        signatures: HashMap::from([(test_digest("test"), test_signature("test"))]),
    };

    let resp = harness
        .client()
        .post(harness.url("/api/test/iel/events/prefixes"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: kels_core::PrefixListResponse = resp.json().await.unwrap();
    assert!(body.prefixes.len() <= 100);
}

#[tokio::test]
async fn test_list_objects_empty() {
    let Some(harness) = get_harness().await else {
        return;
    };

    let body = kels_core::SignedRequest {
        payload: kels_core::PaginatedSelfAddressedRequest::create(
            kels_core::generate_nonce(),
            None,
            None,
        )
        .unwrap(),
        signatures: HashMap::from([(test_digest("test"), test_signature("test"))]),
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

// ==================== IEL fetch: request shape (#167 said-form) ====================
//
// The IEL fetch handler accepts either `prefix` OR `said` (exclusive). The
// happy-path said-form fetch (with real IEL fixtures) is exercised by Gap 3's
// verifier tests; here we pin the request-validation contract.

#[tokio::test]
async fn test_iel_fetch_rejects_both_prefix_and_said() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let body = serde_json::json!({
        "prefix": test_digest("any").to_string(),
        "said": test_digest("any").to_string(),
    });
    let resp = harness
        .client()
        .post(harness.url("/api/v1/iel/events/fetch"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_iel_fetch_rejects_neither_prefix_nor_said() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let body = serde_json::json!({});
    let resp = harness
        .client()
        .post(harness.url("/api/v1/iel/events/fetch"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_iel_fetch_said_form_unknown_returns_404() {
    let Some(harness) = get_harness().await else {
        return;
    };
    // SAID not in any IEL — subquery returns empty → empty page → 404.
    let body = serde_json::json!({
        "said": test_digest("not-in-any-iel").to_string(),
    });
    let resp = harness
        .client()
        .post(harness.url("/api/v1/iel/events/fetch"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}
