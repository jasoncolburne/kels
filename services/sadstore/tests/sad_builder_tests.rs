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

use std::{
    net::TcpListener,
    sync::{Arc, OnceLock},
    time::Duration,
};

use cesr::Digest256;
use ctor::dtor;
use kels_core::{
    KelsClient, KeyEventBuilder, PolicyChecker, SadEvent, SadEventBuilder, SadStoreClient,
    SoftwareKeyProvider, VerificationKeyCode, compute_sad_event_prefix,
};
use kels_policy::{AnchoredPolicyChecker, InMemoryPolicyResolver, Policy, PolicyResolver};
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

/// Build an `AnchoredPolicyChecker` from an `HttpKelSource` pointed at the
/// harness's KEL service plus an `InMemoryPolicyResolver` seeded with the
/// supplied policy. Returns the type-erased Arc the builder expects.
fn build_checker(harness: &SharedHarness, policy: Policy) -> Arc<dyn PolicyChecker + Send + Sync> {
    let kel_source: Arc<dyn kels_core::PagedKelSource + Send + Sync> = Arc::new(
        kels_core::HttpKelSource::new(&harness.kels_url, "/api/v1/kels/kel/fetch")
            .expect("kel source"),
    );
    let resolver: Arc<dyn PolicyResolver + Send + Sync> =
        Arc::new(InMemoryPolicyResolver::new(vec![policy]));
    Arc::new(AnchoredPolicyChecker::new(kel_source, resolver))
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
        .expect("upload publication")
}

// ==================== Tests ====================

/// Expanded-form SADs (parent with inline nested children) are stored under the
/// post-compaction canonical SAID — not the SAID the client computed on the
/// expanded form. The server returns the canonical value in the response body
/// so clients can locate what was actually stored. Closes the M3 audit
/// finding: without this round-trip, expanded-form posters would 404 on fetch.
#[tokio::test]
#[serial]
async fn post_sad_object_returns_canonical_said_for_expanded_form() {
    let Some(harness) = get_harness().await else {
        return;
    };

    let sad_client = SadStoreClient::new(&harness.sad_url).expect("sad client");

    // Build an expanded-form parent with a nested SAD inline. Both SAIDs are
    // computed by the client on the expanded shape; the server will compact
    // the child into a SAID-string reference and rederive the parent.
    let mut child = serde_json::json!({
        "said": "",
        "tag": "expanded-child",
    });
    child.derive_said().unwrap();

    let mut parent = serde_json::json!({
        "said": "",
        "child": child,
    });
    parent.derive_said().unwrap();
    let client_computed = parent.get_said();

    let returned = sad_client
        .post_sad_object(&parent)
        .await
        .expect("expanded-form post should succeed");

    // Compaction changes the bytes the SAID is computed over, so the canonical
    // SAID must differ from the client-computed value.
    assert_ne!(
        returned, client_computed,
        "compaction should produce a different SAID; if these match, the parent\
         had no nested SADs to compact and the test isn't exercising the path"
    );

    // The canonical SAID must be the one that locates the stored object.
    let _ = sad_client
        .get_sad_object(&returned)
        .await
        .expect("canonical SAID must locate the stored object");

    // Sanity: the client-computed (pre-compaction) SAID must NOT locate
    // anything — the server stored under the canonical SAID only.
    assert!(
        !sad_client
            .sad_object_exists(&client_computed)
            .await
            .unwrap(),
        "pre-compaction SAID must not exist server-side"
    );
}

#[tokio::test]
#[serial]
async fn publish_pending_makes_events_fetchable_by_said() {
    let Some(harness) = get_harness().await else {
        return;
    };

    let (_prefix, _kel_builder, policy, sad_client) =
        setup_kel_and_policy(harness, "publish-fetchable").await;
    let publication_said = upload_publication(&sad_client, "publish-fetchable").await;

    let mut builder = SadEventBuilder::new(Some(sad_client.clone()), None, None);
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

    let mut builder = SadEventBuilder::new(Some(sad_client.clone()), None, None);
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

    let policy_said = policy.said;
    let checker = build_checker(harness, policy);
    let mut builder = SadEventBuilder::new(Some(sad_client.clone()), None, Some(checker));
    let (icp_said, est_said) = builder
        .incept_deterministic(TEST_TOPIC, policy_said, policy_said, Some(publication_said))
        .unwrap();

    // Anchor both staged SAIDs in the owner's KEL — the server's write_policy
    // check walks the KEL to find them.
    kel_builder.interact(&icp_said).await.expect("anchor icp");
    kel_builder.interact(&est_said).await.expect("anchor est");

    let outcome = builder
        .flush()
        .await
        .expect("flush should succeed with anchors in place");
    assert!(
        outcome.diverged_at_at_submit.is_none(),
        "linear-chain flush must not report divergence, got {:?}",
        outcome.diverged_at_at_submit
    );

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

    let policy_said = policy.said;
    let kel_source: Arc<dyn kels_core::PagedKelSource + Send + Sync> = Arc::new(
        kels_core::HttpKelSource::new(&harness.kels_url, "/api/v1/kels/kel/fetch").unwrap(),
    );
    let resolver: Arc<dyn PolicyResolver + Send + Sync> =
        Arc::new(InMemoryPolicyResolver::new(vec![policy]));
    let checker: Arc<dyn PolicyChecker + Send + Sync> =
        Arc::new(AnchoredPolicyChecker::new(kel_source, resolver));

    let mut builder = SadEventBuilder::new(Some(sad_client.clone()), None, Some(checker));
    let (icp_said, est_said) = builder
        .incept_deterministic(TEST_TOPIC, policy_said, policy_said, Some(publication_said))
        .unwrap();
    kel_builder.interact(&icp_said).await.unwrap();
    kel_builder.interact(&est_said).await.unwrap();

    let pending_before: Vec<_> = builder.pending_events().iter().map(|e| e.said).collect();

    let err = builder
        .flush()
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

/// A retried submit of an already-applied batch must return the chain's
/// *current* divergence state — not unconditional `diverged_at: None`.
///
/// Without this signal, a client whose first flush succeeded server-side but
/// failed in phase 2 / 3 (Round 4 M1's terminology) can never learn that a
/// concurrent writer forked the chain at submit time. Their local
/// `sad_verification.diverged_at_version()` stays `None`, the next stager
/// call accepts when it should refuse with `KelsError::SelDivergent`, and the
/// builder's divergence-aware staging gate is silently defeated.
///
/// The test deliberately bypasses `SadEventBuilder` (which is single-actor and
/// refuses divergent state) to fork the chain at the HTTP layer, then re-submits
/// the second branch as a duplicate batch.
#[tokio::test]
#[serial]
async fn submit_dedup_returns_current_divergence_signal() {
    let Some(harness) = get_harness().await else {
        return;
    };

    let (_prefix, mut kel_builder, policy, sad_client) =
        setup_kel_and_policy(harness, "dedup-divergence").await;
    let publication_said = upload_publication(&sad_client, "dedup-divergence").await;

    // Stage v0 Icp + v1 Est via the builder, anchor + flush.
    let policy_said = policy.said;
    let checker = build_checker(harness, policy);
    let mut builder = SadEventBuilder::new(Some(sad_client.clone()), None, Some(checker));
    let (icp_said, est_said) = builder
        .incept_deterministic(TEST_TOPIC, policy_said, policy_said, Some(publication_said))
        .unwrap();
    kel_builder.interact(&icp_said).await.unwrap();
    kel_builder.interact(&est_said).await.unwrap();
    let _ = builder.flush().await.expect("initial flush succeeds");

    // Hand-build two conflicting v2 Upd events — both extend v1 (the Est tip)
    // with different content, producing distinct SAIDs at the same version.
    let v1_event = builder
        .sad_verification()
        .expect("verified after initial flush")
        .current_event()
        .clone();
    let content_a = upload_publication(&sad_client, "fork-a").await;
    let content_b = upload_publication(&sad_client, "fork-b").await;
    let v2_a = SadEvent::upd(&v1_event, content_a).unwrap();
    let v2_b = SadEvent::upd(&v1_event, content_b).unwrap();

    // Anchor both forks in the same KEL — the policy check evaluates each
    // event's SAID against the KEL anchors, and both SAIDs need to resolve.
    kel_builder.interact(&v2_a.said).await.unwrap();
    kel_builder.interact(&v2_b.said).await.unwrap();

    // First fork lands cleanly — chain is still linear after this.
    let r_a = sad_client
        .submit_sad_events(std::slice::from_ref(&v2_a))
        .await
        .expect("first fork accepted");
    assert!(r_a.applied);
    assert_eq!(
        r_a.diverged_at, None,
        "single v2 event should not produce divergence yet"
    );

    // Second fork creates divergence — server detects collision at v2.
    let r_b = sad_client
        .submit_sad_events(std::slice::from_ref(&v2_b))
        .await
        .expect("second fork accepted, chain becomes divergent");
    assert!(r_b.applied);
    assert_eq!(
        r_b.diverged_at,
        Some(2),
        "second event at v2 must report divergence at version 2"
    );

    // Now the load-bearing assertion: re-submit the second fork. All events
    // are present → dedup short-circuit → `applied: false`. Pre-fix this would
    // return `diverged_at: None` and silently mask the chain's state. After
    // the fix, the dedup path queries `first_divergent_version` and reports
    // the same `Some(2)` the original submit did.
    let r_retry = sad_client
        .submit_sad_events(std::slice::from_ref(&v2_b))
        .await
        .expect("retry of already-applied fork dedups");
    assert!(
        !r_retry.applied,
        "retry of already-applied batch must report applied=false"
    );
    assert_eq!(
        r_retry.diverged_at,
        Some(2),
        "dedup path must surface the chain's current divergence version, \
         not unconditional None"
    );
}

/// `SadEventBuilder::flush` heals a divergent chain end-to-end: walks back to
/// the divergence boundary via the local `sad_store`, stages an Rpr at
/// version `d` with `previous = v(d-1).said`, submits, and re-hydrates the
/// local token from the post-truncation server state. After the flush,
/// `effective_said` reports `divergent: false` server-side.
///
/// Pre-M1-followup, the high-level repair stager built Rpr at `owner_tip+1`,
/// so the server's `is_repair` truncation ran at `from_version = owner_tip+1`
/// — past the divergence point — and the chain stayed divergent. The
/// M1-followup walk-back (`SadEventBuilder::repair` Case A) constructs the
/// Rpr at the truncation boundary so divergence is actually resolved.
#[tokio::test]
#[serial]
async fn flush_repair_heals_divergent_chain() {
    use std::sync::Arc;

    let Some(harness) = get_harness().await else {
        return;
    };

    let (_prefix, mut kel_builder, policy, sad_client) =
        setup_kel_and_policy(harness, "divergent-repair").await;
    let publication_said = upload_publication(&sad_client, "divergent-repair").await;

    // First flush uses a shared `InMemorySadStore`. The store ends up holding
    // owner's v0 and v1 (the events the first builder authored), which the
    // repair builder's walk-back will use to find the divergence boundary.
    let owner_store: Arc<dyn kels_core::SadStore> = Arc::new(kels_core::InMemorySadStore::new());

    let policy_said = policy.said;
    let checker = build_checker(harness, policy.clone());
    let mut builder = SadEventBuilder::new(
        Some(sad_client.clone()),
        Some(Arc::clone(&owner_store)),
        Some(checker),
    );
    let (icp_said, est_said) = builder
        .incept_deterministic(TEST_TOPIC, policy_said, policy_said, Some(publication_said))
        .unwrap();
    kel_builder.interact(&icp_said).await.unwrap();
    kel_builder.interact(&est_said).await.unwrap();
    let _ = builder.flush().await.expect("initial flush succeeds");

    // Hand-build two conflicting v2 Upd events bypassing the (single-actor) builder.
    let v1_event = builder
        .sad_verification()
        .expect("verified after initial flush")
        .current_event()
        .clone();
    let content_a = upload_publication(&sad_client, "divergent-repair-a").await;
    let content_b = upload_publication(&sad_client, "divergent-repair-b").await;
    let v2_a = SadEvent::upd(&v1_event, content_a).unwrap();
    let v2_b = SadEvent::upd(&v1_event, content_b).unwrap();
    kel_builder.interact(&v2_a.said).await.unwrap();
    kel_builder.interact(&v2_b.said).await.unwrap();

    // Submit both forks to create server-side divergence.
    let r_a = sad_client
        .submit_sad_events(std::slice::from_ref(&v2_a))
        .await
        .expect("first fork accepted");
    assert!(r_a.applied);
    let r_b = sad_client
        .submit_sad_events(std::slice::from_ref(&v2_b))
        .await
        .expect("second fork accepted, chain becomes divergent");
    assert!(r_b.applied);
    assert_eq!(r_b.diverged_at, Some(2));

    // Confirm server-side divergence via the effective-SAID endpoint.
    let sel_prefix = compute_sad_event_prefix(policy_said, TEST_TOPIC).unwrap();
    let (_, divergent_before) = sad_client
        .fetch_sel_effective_said(&sel_prefix)
        .await
        .unwrap()
        .unwrap();
    assert!(
        divergent_before,
        "fixture invariant: chain must be divergent server-side before repair"
    );

    // Fresh builder hydrating from the divergent server, sharing the
    // `owner_store` populated by the initial flush. `with_prefix` issues
    // `verify_sad_events`, which walks both branches and produces a token
    // with `branches().len() == 2`. The repair stager walks back from
    // `branches().first().tip` (one of v2_a/v2_b — both fork from v1) via
    // `previous` SAIDs through `owner_store` until it finds v1, then builds
    // Rpr at version 2 with `previous = v1.said`. Server's `is_repair` path
    // archives both v2_a and v2_b and inserts the Rpr — chain becomes linear.
    let checker2 = build_checker(harness, policy);
    let mut repair_builder = SadEventBuilder::with_prefix(
        Some(sad_client.clone()),
        Some(Arc::clone(&owner_store)),
        Some(checker2),
        &sel_prefix,
    )
    .await
    .expect("with_prefix hydrates divergent chain");

    let hydrated = repair_builder
        .sad_verification()
        .expect("hydrated verification present");
    assert_eq!(
        hydrated.branches().len(),
        2,
        "hydration must preserve both branches post-round-6"
    );
    assert_eq!(hydrated.diverged_at_version(), Some(2));

    // Stage the repair — walks back to v1, builds Rpr at v2 with previous=v1.said.
    let repaired_content = upload_publication(&sad_client, "divergent-repair-c").await;
    let rpr_said = repair_builder
        .repair(Some(repaired_content))
        .await
        .expect("repair stages on divergent hydrated chain");

    // Sanity-check the boundary: the staged Rpr must be at the divergence
    // version (v2), not at owner_tip+1 (v3). This is the M1-followup
    // contract — pre-fix the high-level repair built at v3.
    let staged = repair_builder.pending_events().last().unwrap();
    assert_eq!(staged.said, rpr_said);
    assert_eq!(
        staged.version, 2,
        "M1-followup contract: Rpr at divergence version (v2), not at owner_tip+1 (v3)"
    );
    assert_eq!(
        staged.previous,
        Some(v1_event.said),
        "Rpr's previous = v1 (the v(d-1) tip shared by both branches)"
    );

    // Anchor the Rpr and flush. Server's is_repair path runs at from_version=2,
    // archives both v2_a and v2_b, inserts the Rpr. Builder re-hydrates from
    // the post-truncation linear chain.
    kel_builder.interact(&rpr_said).await.unwrap();
    let outcome = repair_builder
        .flush()
        .await
        .expect("flush of divergent-chain repair must succeed");
    assert!(outcome.applied, "repair must commit server-side");

    // Server-side: chain is now LINEAR — the M1-followup contract.
    let (_, divergent_after) = sad_client
        .fetch_sel_effective_said(&sel_prefix)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !divergent_after,
        "M1-followup contract: server-side chain must be linear after repair flush"
    );

    // Builder-side: pending cleared, post-truncation server state hydrated.
    assert!(repair_builder.pending_events().is_empty());
    let post_repair = repair_builder
        .sad_verification()
        .expect("verification re-hydrated post-flush");
    assert_eq!(
        post_repair.branches().len(),
        1,
        "post-truncation server chain has a single branch — local token reflects it"
    );
    assert_eq!(post_repair.diverged_at_version(), None);
    assert_eq!(
        post_repair.current_event().said,
        rpr_said,
        "current event is the freshly-committed Rpr"
    );

    // Idempotent retry: a follow-up flush with no pending events is a no-op.
    let outcome2 = repair_builder
        .flush()
        .await
        .expect("idempotent retry must succeed");
    assert!(!outcome2.applied);
}

/// `SadEventBuilder::flush` heals an adversarially-extended linear chain
/// end-to-end via the page-fetch + in-memory walk: paginated
/// `fetch_sad_events` pulls the chain segment into memory, the walk
/// traverses adversary's `previous` links there, probes `sad_store` for the
/// owner-authored boundary, builds Rpr at `v(K+1)` with `previous = vK.said`.
/// Multi-step adversary extension (T-K > 1) — pre-followup-extension this
/// would error with `InvalidKel` because the single-step probe hit a miss
/// and couldn't continue without adversary's intermediate events.
#[tokio::test]
#[serial]
async fn flush_repair_heals_adversarially_extended_chain() {
    use std::sync::Arc;

    let Some(harness) = get_harness().await else {
        return;
    };

    let (_prefix, mut kel_builder, policy, sad_client) =
        setup_kel_and_policy(harness, "adversary-extension").await;
    let publication_said = upload_publication(&sad_client, "adversary-extension").await;

    // Owner uses a shared sad_store from the start so v0/v1 land in it.
    let owner_store: Arc<dyn kels_core::SadStore> = Arc::new(kels_core::InMemorySadStore::new());

    let policy_said = policy.said;
    let checker = build_checker(harness, policy.clone());
    let mut builder = SadEventBuilder::new(
        Some(sad_client.clone()),
        Some(Arc::clone(&owner_store)),
        Some(checker),
    );
    let (icp_said, est_said) = builder
        .incept_deterministic(TEST_TOPIC, policy_said, policy_said, Some(publication_said))
        .unwrap();
    kel_builder.interact(&icp_said).await.unwrap();
    kel_builder.interact(&est_said).await.unwrap();
    let _ = builder.flush().await.expect("initial flush succeeds");

    // Owner's authoritative tip is v1 (the Est). vK = v1.
    let v1_event = builder
        .sad_verification()
        .expect("verified after initial flush")
        .current_event()
        .clone();
    assert_eq!(v1_event.version, 1);

    // Adversary extends the chain by THREE Upd events bypassing the (single-actor)
    // builder. T - K = 3 — pre-followup-extension the walk would error.
    let mut adv_prev = v1_event.clone();
    let mut adv_events = Vec::new();
    for i in 0..3 {
        let content = upload_publication(&sad_client, &format!("adversary-extension-{}", i)).await;
        let event = SadEvent::upd(&adv_prev, content).unwrap();
        kel_builder.interact(&event.said).await.unwrap();
        let r = sad_client
            .submit_sad_events(std::slice::from_ref(&event))
            .await
            .expect("adversary submit accepted");
        assert!(r.applied);
        assert_eq!(r.diverged_at, None, "linear extension; no divergence");
        adv_prev = event.clone();
        adv_events.push(event);
    }
    let v_t = adv_events.last().unwrap().clone();
    assert_eq!(v_t.version, 4, "T = K + 3 = 1 + 3 = 4");

    // Sanity: server-side chain is linear (no divergence).
    let sel_prefix = compute_sad_event_prefix(policy_said, TEST_TOPIC).unwrap();
    let (effective_before, divergent_before) = sad_client
        .fetch_sel_effective_said(&sel_prefix)
        .await
        .unwrap()
        .unwrap();
    assert!(!divergent_before);
    assert_eq!(
        effective_before.to_string(),
        v_t.said.to_string(),
        "effective SAID is the adversary's tip"
    );

    // Fresh builder hydrating from the (linear, adversary-extended) server,
    // sharing `owner_store` (which holds only owner's v0 and v1). `with_prefix`
    // verifies the chain via verify_sad_events, producing a token whose
    // current_event is the adversary's tip vT = v4. cached_tip is NOT in
    // owner_store — Case B.
    let checker2 = build_checker(harness, policy);
    let mut repair_builder = SadEventBuilder::with_prefix(
        Some(sad_client.clone()),
        Some(Arc::clone(&owner_store)),
        Some(checker2),
        &sel_prefix,
    )
    .await
    .expect("with_prefix hydrates linear adversary-extended chain");

    let hydrated = repair_builder
        .sad_verification()
        .expect("hydrated verification present");
    assert_eq!(hydrated.diverged_at_version(), None);
    assert_eq!(
        hydrated.current_event().said,
        v_t.said,
        "hydration sees adversary's tip as the cached tip"
    );

    // Stage the repair. The page-fetch + in-memory walk traverses
    // v_t → v3 → v2 → v1 (hit in owner_store) → boundary at v1. Builds Rpr
    // at version 2 with previous = v1.said.
    let repaired_content = upload_publication(&sad_client, "repaired-after-adversary").await;
    let rpr_said = repair_builder
        .repair(Some(repaired_content))
        .await
        .expect("repair walks back through multi-step adversary extension to vK");

    let staged = repair_builder.pending_events().last().unwrap();
    assert_eq!(staged.said, rpr_said);
    assert_eq!(
        staged.version, 2,
        "Rpr at v(K+1) = v2 (truncates adversary's v2..v4 and replaces with Rpr@v2)"
    );
    assert_eq!(
        staged.previous,
        Some(v1_event.said),
        "Rpr's previous = vK = v1 (the owner-authored boundary, hit in local store)"
    );

    // Anchor the Rpr and flush. Server's is_repair archives v2..v4 and
    // inserts Rpr@v2.
    kel_builder.interact(&rpr_said).await.unwrap();
    let outcome = repair_builder
        .flush()
        .await
        .expect("flush of multi-step adversary repair must succeed");
    assert!(outcome.applied);

    // Server-side: chain is now linear at [v0, v1, Rpr@v2].
    let (effective_after, divergent_after) = sad_client
        .fetch_sel_effective_said(&sel_prefix)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !divergent_after,
        "chain stays linear after repair (was already linear, just adversary-extended)"
    );
    assert_eq!(
        effective_after.to_string(),
        rpr_said.to_string(),
        "effective SAID is now the freshly-committed Rpr at v2"
    );

    // Builder-side: pending cleared, hydrated to the post-truncation tip.
    assert!(repair_builder.pending_events().is_empty());
    let post_repair = repair_builder
        .sad_verification()
        .expect("verification re-hydrated post-flush");
    assert_eq!(post_repair.branches().len(), 1);
    assert_eq!(post_repair.current_event().said, rpr_said);
    assert_eq!(post_repair.current_event().version, 2);
}
