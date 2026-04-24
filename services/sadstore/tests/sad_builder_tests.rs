//! Integration tests for `SadEventBuilder` against real KELS + sadstore HTTP services.
//!
//! Why the full harness: `SadEventBuilder::flush` round-trips through
//! `submit_sad_events`, which the sadstore server verifies by calling
//! `AnchoredPolicyChecker` — the checker fetches anchors from a real KELS
//! HTTP service. There's no test mode that bypasses the policy check at the
//! service boundary; HTTP-level mocks would split invariants (the whole
//! reason we're not using them). So we bring up both services against
//! testcontainers: Postgres (×2, one per service), Redis (KELS pub/sub),
//! MinIO (sadstore object store), and both HTTP servers spawned in their
//! own threads. The harness is shared across tests via `OnceCell`; each
//! test marks itself `#[serial]` so cross-test state (prefixes, KEL nonce
//! cache, sadstore chain state) doesn't contaminate.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{net::TcpListener, sync::OnceLock, time::Duration};

use cesr::Digest256;
use ctor::dtor;
use kels_core::{
    KelsClient, KeyEventBuilder, SadEvent, SadEventBuilder, SadStoreClient, SoftwareKeyProvider,
    VerificationKeyCode, compute_sad_event_prefix,
};
use kels_policy::{AnchoredPolicyChecker, InMemoryPolicyResolver, Policy};
use reqwest::Client;
use serial_test::serial;
use testcontainers::{
    ContainerAsync, GenericImage, Image,
    core::{ImageExt, WaitFor},
    runners::AsyncRunner,
};
use testcontainers_modules::{postgres::Postgres, redis::Redis};
use tokio::{sync::OnceCell, time::sleep};
use verifiable_storage::SelfAddressed;

const TEST_CONTAINER_LABEL: (&str, &str) = ("kels-test", "true");
const TEST_TOPIC: &str = "kels/sad/v1/keys/mlkem";

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
    kels_url: String,
    sad_url: String,
    _pg_kels: ContainerAsync<Postgres>,
    _pg_sad: ContainerAsync<Postgres>,
    _redis: ContainerAsync<Redis>,
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
        // Surface server warn!/info! output in the test binary so we can see
        // what the sadstore/KELS services say when tests misbehave.
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                    tracing_subscriber::EnvFilter::new("info,kels_sadstore=debug")
                }),
            )
            .with_test_writer()
            .try_init();

        // --- Postgres for KELS ---
        let pg_kels = Postgres::default()
            .with_label(TEST_CONTAINER_LABEL.0, TEST_CONTAINER_LABEL.1)
            .start()
            .await
            .expect("KELS postgres failed to start");
        let pg_kels_host = pg_kels.get_host().await.expect("kels pg host");
        let pg_kels_port = retry_get_port(&pg_kels, 5432).await.expect("kels pg port");
        let kels_db_url = format!(
            "postgres://postgres:postgres@{}:{}/postgres",
            pg_kels_host, pg_kels_port
        );

        // --- Postgres for sadstore ---
        let pg_sad = Postgres::default()
            .with_label(TEST_CONTAINER_LABEL.0, TEST_CONTAINER_LABEL.1)
            .start()
            .await
            .expect("sadstore postgres failed to start");
        let pg_sad_host = pg_sad.get_host().await.expect("sad pg host");
        let pg_sad_port = retry_get_port(&pg_sad, 5432).await.expect("sad pg port");
        let sad_db_url = format!(
            "postgres://postgres:postgres@{}:{}/postgres",
            pg_sad_host, pg_sad_port
        );

        // --- Redis for KELS pub/sub ---
        let redis = Redis::default()
            .with_label(TEST_CONTAINER_LABEL.0, TEST_CONTAINER_LABEL.1)
            .start()
            .await
            .expect("redis failed to start");
        let redis_host = redis.get_host().await.expect("redis host");
        let redis_port = retry_get_port(&redis, 6379).await.expect("redis port");
        let redis_url = format!("redis://{}:{}", redis_host, redis_port);

        // --- MinIO for sadstore object store ---
        let minio = GenericImage::new("minio/minio", "latest")
            .with_exposed_port(9000.into())
            .with_wait_for(WaitFor::message_on_stderr("API:"))
            .with_label(TEST_CONTAINER_LABEL.0, TEST_CONTAINER_LABEL.1)
            .with_env_var("MINIO_ROOT_USER", "minioadmin")
            .with_env_var("MINIO_ROOT_PASSWORD", "minioadmin")
            .with_cmd(vec!["server".to_string(), "/data".to_string()])
            .start()
            .await
            .expect("MinIO failed to start");
        let minio_host = minio.get_host().await.expect("minio host");
        let minio_port = retry_get_port_generic(&minio, 9000)
            .await
            .expect("minio port");
        let minio_endpoint = format!("http://{}:{}", minio_host, minio_port);

        // --- Bind ports for both HTTP services ---
        let kels_listener = TcpListener::bind("127.0.0.1:0").expect("kels bind");
        let kels_port = kels_listener.local_addr().unwrap().port();
        kels_listener.set_nonblocking(true).unwrap();
        let kels_url = format!("http://127.0.0.1:{}", kels_port);

        let sad_listener = TcpListener::bind("127.0.0.1:0").expect("sad bind");
        let sad_port = sad_listener.local_addr().unwrap().port();
        sad_listener.set_nonblocking(true).unwrap();
        let sad_url = format!("http://127.0.0.1:{}", sad_port);

        // Shared env vars for both services (sadstore reads MinIO creds;
        // KELS reads test-endpoints + nonce window). SAFETY: called before
        // the server threads are spawned, so no concurrent env reads yet.
        unsafe {
            std::env::set_var("MINIO_ENDPOINT", &minio_endpoint);
            std::env::set_var("MINIO_REGION", "us-east-1");
            std::env::set_var("MINIO_ACCESS_KEY", "minioadmin");
            std::env::set_var("MINIO_SECRET_KEY", "minioadmin");
            std::env::set_var("KELS_SAD_BUCKET", "kels-sad-test");
            std::env::set_var("KELS_TEST_ENDPOINTS", "true");
            std::env::set_var("KELS_NONCE_WINDOW_SECS", "0");
        }

        // --- Spawn KELS ---
        let kels_db = kels_db_url.clone();
        let redis_for_kels = redis_url.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("kels runtime");
            rt.block_on(async move {
                let listener =
                    tokio::net::TcpListener::from_std(kels_listener).expect("kels listener");
                if let Err(e) =
                    kels_service::run(listener, &kels_db, Some(&redis_for_kels), vec![]).await
                {
                    panic!("KELS server error: {}", e);
                }
            });
        });

        // --- Spawn sadstore (pointed at the KELS URL for anchor lookups) ---
        let sad_db = sad_db_url.clone();
        let kels_for_sad = kels_url.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("sad runtime");
            rt.block_on(async move {
                let listener =
                    tokio::net::TcpListener::from_std(sad_listener).expect("sad listener");
                if let Err(e) =
                    kels_sadstore::run(listener, &sad_db, None, &kels_for_sad, Vec::new()).await
                {
                    panic!("sadstore server error: {}", e);
                }
            });
        });

        // Wait for both /health endpoints.
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        for url in [&kels_url, &sad_url] {
            let health = format!("{}/health", url);
            let mut ready = false;
            for _ in 0..100 {
                if let Ok(resp) = client.get(&health).send().await
                    && resp.status().is_success()
                {
                    ready = true;
                    break;
                }
                sleep(Duration::from_millis(100)).await;
            }
            if !ready {
                panic!("service not ready at {}", url);
            }
        }
        eprintln!("Harness ready: KELS={} SAD={}", kels_url, sad_url);

        Some(Self {
            kels_url,
            sad_url,
            _pg_kels: pg_kels,
            _pg_sad: pg_sad,
            _redis: redis,
            _minio: minio,
        })
    }
}

// ==================== Per-test setup helpers ====================

/// Incept a fresh KEL in the KELS service and return the KEL-level pieces
/// a subsequent SAD event flow needs: the prefix, the HTTP-backed builder
/// (ready to call `interact(said)` for anchoring), and the write_policy
/// SAD object (already uploaded to sadstore).
async fn setup_kel_and_policy(
    harness: &SharedHarness,
    label: &str,
) -> (
    Digest256,
    KeyEventBuilder<SoftwareKeyProvider>,
    Policy,
    SadStoreClient,
) {
    let provider = SoftwareKeyProvider::new(
        VerificationKeyCode::Secp256r1,
        VerificationKeyCode::Secp256r1,
    );
    let kels_client = KelsClient::new(&harness.kels_url).expect("kels client");
    let mut kel_builder = KeyEventBuilder::new(provider, Some(kels_client));
    kel_builder.incept().await.expect("incept KEL");
    let prefix = *kel_builder.prefix().expect("KEL has prefix after incept");

    // Build `endorse(prefix)` as both write_policy and governance_policy;
    // matches the exchange.rs single-endorser convention for tests.
    let policy =
        Policy::build(&format!("endorse({})", prefix), None, false).expect("build endorse policy");
    let sad_client = SadStoreClient::new(&harness.sad_url).expect("sad client");

    // Upload the policy so the server's resolver can find it.
    let policy_json = serde_json::to_value(&policy).unwrap();
    sad_client
        .post_sad_object(&policy_json)
        .await
        .unwrap_or_else(|e| panic!("upload policy for {}: {:?}", label, e));

    (prefix, kel_builder, policy, sad_client)
}

/// Build an `AnchoredPolicyChecker` for the given KEL + policy.
/// Returns owned handles plus a closure that builds the checker — the
/// checker borrows the other two, so callers must keep them alive.
fn build_checker_inputs(
    harness: &SharedHarness,
    policy: Policy,
) -> (kels_core::HttpKelSource, InMemoryPolicyResolver) {
    let kel_source = kels_core::HttpKelSource::new(&harness.kels_url, "/api/v1/kels/kel/fetch")
        .expect("kel source");
    let resolver = InMemoryPolicyResolver::new(vec![policy]);
    (kel_source, resolver)
}

/// Upload a fresh publication SAD to act as `content` for Est/Upd events.
async fn upload_publication(sad_client: &SadStoreClient, tag: &str) -> Digest256 {
    let mut object = serde_json::json!({
        "said": "",
        "tag": tag,
    });
    object.derive_said().unwrap();
    sad_client
        .post_sad_object(&object)
        .await
        .expect("upload publication");
    object.get_said()
}

// ==================== Tests ====================

#[tokio::test]
#[serial]
async fn publish_pending_makes_events_fetchable_by_said() {
    let Some(harness) = get_harness().await else {
        return;
    };

    let (_prefix, _kel_builder, policy, sad_client) =
        setup_kel_and_policy(harness, "publish-fetchable").await;
    let publication_said = upload_publication(&sad_client, "publish-fetchable").await;

    let mut builder = SadEventBuilder::new(Some(sad_client.clone()));
    builder
        .incept_deterministic(TEST_TOPIC, policy.said, policy.said, Some(publication_said))
        .unwrap();
    builder
        .update(upload_publication(&sad_client, "publish-fetchable-upd").await)
        .unwrap();

    // Before publish: events not in the object store.
    for event in builder.pending_events() {
        assert!(
            !sad_client.sad_object_exists(&event.said).await.unwrap(),
            "event {} should not be in object store before publish_pending",
            event.said
        );
    }

    builder
        .publish_pending()
        .await
        .expect("publish_pending should succeed");

    // After publish: each SAID fetchable, round-trips back to an identical SadEvent.
    for event in builder.pending_events() {
        let fetched = sad_client
            .get_sad_object(&event.said)
            .await
            .unwrap_or_else(|e| panic!("fetch {}: {:?}", event.said, e));
        let parsed: SadEvent = serde_json::from_value(fetched).expect("parse fetched SadEvent");
        assert_eq!(parsed.said, event.said);
        assert_eq!(parsed.version, event.version);
        assert_eq!(parsed.kind, event.kind);
        assert_eq!(parsed.content, event.content);
    }
}

#[tokio::test]
#[serial]
async fn publish_pending_idempotent() {
    let Some(harness) = get_harness().await else {
        return;
    };

    let (_prefix, _kel_builder, policy, sad_client) =
        setup_kel_and_policy(harness, "publish-idempotent").await;
    let publication_said = upload_publication(&sad_client, "publish-idempotent").await;

    let mut builder = SadEventBuilder::new(Some(sad_client.clone()));
    builder
        .incept_deterministic(TEST_TOPIC, policy.said, policy.said, Some(publication_said))
        .unwrap();

    builder.publish_pending().await.expect("first publish");
    builder
        .publish_pending()
        .await
        .expect("second publish is a no-op equivalent");

    // Both events still fetchable and unchanged.
    for event in builder.pending_events() {
        let fetched = sad_client.get_sad_object(&event.said).await.unwrap();
        let parsed: SadEvent = serde_json::from_value(fetched).unwrap();
        assert_eq!(parsed.said, event.said);
    }
}

#[tokio::test]
#[serial]
async fn flush_submits_and_absorbs() {
    let Some(harness) = get_harness().await else {
        return;
    };

    let (_prefix, mut kel_builder, policy, sad_client) =
        setup_kel_and_policy(harness, "flush-success").await;
    let publication_said = upload_publication(&sad_client, "flush-success").await;

    let mut builder = SadEventBuilder::new(Some(sad_client.clone()));
    let (icp_said, est_said) = builder
        .incept_deterministic(TEST_TOPIC, policy.said, policy.said, Some(publication_said))
        .unwrap();

    // Anchor both staged SAIDs in the owner's KEL — the server's write_policy
    // check walks the KEL to find them.
    kel_builder.interact(&icp_said).await.expect("anchor icp");
    kel_builder.interact(&est_said).await.expect("anchor est");

    let (kel_source, resolver) = build_checker_inputs(harness, policy);
    let checker = AnchoredPolicyChecker::new(&kel_source, &resolver);

    builder
        .flush(&checker)
        .await
        .expect("flush should succeed with anchors in place");

    // Server-side: chain readable via fetch_sad_events.
    let sel_prefix = compute_sad_event_prefix(
        *builder.sad_verification().unwrap().write_policy(),
        TEST_TOPIC,
    )
    .unwrap();
    let page = sad_client
        .fetch_sad_events(&sel_prefix, None)
        .await
        .expect("fetch submitted chain");
    assert_eq!(page.events.len(), 2);
    assert_eq!(page.events[0].said, icp_said);
    assert_eq!(page.events[1].said, est_said);

    // Builder-side: verification now holds the tip, pending is empty.
    let verification = builder
        .sad_verification()
        .expect("verification present after flush");
    assert_eq!(verification.current_event().said, est_said);
    assert_eq!(verification.current_event().version, 1);
    assert!(builder.pending_events().is_empty());
}

#[tokio::test]
#[serial]
async fn flush_failure_preserves_pending() {
    let Some(harness) = get_harness().await else {
        return;
    };

    // Mirror the success path EXCEPT: don't upload the write_policy SAD
    // object. The server's SadStorePolicyResolver can't resolve the policy
    // SAID, so `submit_sad_events` rejects the submission. This is a
    // server-side failure — the client-side checker passed to `flush` is
    // only used for post-submit absorption, which never runs.
    let provider = SoftwareKeyProvider::new(
        VerificationKeyCode::Secp256r1,
        VerificationKeyCode::Secp256r1,
    );
    let kels_client = KelsClient::new(&harness.kels_url).unwrap();
    let mut kel_builder = KeyEventBuilder::new(provider, Some(kels_client));
    kel_builder.incept().await.unwrap();
    let kel_prefix = *kel_builder.prefix().unwrap();

    let policy = Policy::build(&format!("endorse({})", kel_prefix), None, false).unwrap();
    let sad_client = SadStoreClient::new(&harness.sad_url).unwrap();
    // Deliberately skip `sad_client.post_sad_object(&policy_json)`.

    let publication_said = upload_publication(&sad_client, "flush-failure").await;

    let mut builder = SadEventBuilder::new(Some(sad_client.clone()));
    let (icp_said, est_said) = builder
        .incept_deterministic(TEST_TOPIC, policy.said, policy.said, Some(publication_said))
        .unwrap();
    kel_builder.interact(&icp_said).await.unwrap();
    kel_builder.interact(&est_said).await.unwrap();

    let kel_source =
        kels_core::HttpKelSource::new(&harness.kels_url, "/api/v1/kels/kel/fetch").unwrap();
    let resolver = InMemoryPolicyResolver::new(vec![policy]);
    let checker = AnchoredPolicyChecker::new(&kel_source, &resolver);

    let pending_before: Vec<_> = builder.pending_events().iter().map(|e| e.said).collect();

    let err = builder
        .flush(&checker)
        .await
        .expect_err("flush must fail — server can't resolve the write_policy");
    // Server-side rejection surfaces as ServerError; we don't assert a specific
    // variant beyond "some error" to stay resilient to server wording changes.
    let _ = err;

    // Pending events unchanged so the caller can reason about the
    // already-anchored KEL state.
    let pending_after: Vec<_> = builder.pending_events().iter().map(|e| e.said).collect();
    assert_eq!(pending_before, pending_after);
    assert_eq!(pending_after.len(), 2);
    assert!(builder.sad_verification().is_none());
}
