//! Round-12 full-stack tests for the SE submit handler + builder.
//!
//! **Gap 10a — critical-subset coverage.** The plan's full taxonomy is
//! 30+ cases; this file ships ~10 high-value tests covering the
//! genuinely-new round-12 surface (HARD Upd auth, soft govfailed
//! Cnt/Dec live-handler elevation, sealed/unsealed routing matrix,
//! terminal-chain refusal). The remaining cases (gossip propagation,
//! more sealed-* combinations, prefix-derivation contract pin, etc.)
//! land in a follow-up Gap 10b pass; the Heisenbug-carry-forward
//! deployment-test sweep covers some of the same surface in the
//! interim.
//!
//! Why the full harness (carry-over from round-10): `SadEventBuilder::flush`
//! round-trips through `submit_sad_events`, which the sadstore server
//! verifies by calling `AnchoredPolicyChecker` (KEL anchoring) and
//! `RepositoryIelResolver` (IEL binding). HTTP-level mocks would split
//! invariants — bring the real services up against testcontainers
//! (Postgres x2, Redis, MinIO, KELS service, SADStore service).
//! Harness shared via `OnceCell`; tests `#[serial]` to keep state
//! isolated across the cross-test prefix space.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    net::TcpListener,
    sync::{Arc, OnceLock},
    time::Duration,
};

use cesr::Digest256;
use ctor::dtor;
use kels_core::{
    IdentityEvent, IdentityEventBuilder, IelVerification, KelsClient, KelsError, KeyEventBuilder,
    PolicyChecker, SadEvent, SadEventBuilder, SadStoreClient, SoftwareKeyProvider,
    SubmitSadEventsResponse, VerificationKeyCode,
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
const TEST_TOPIC: &str = "kels/sad/v1/test/r12";
const TEST_IEL_TOPIC: &str = "kels/iel/v1/test/r12-identity";

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
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                    tracing_subscriber::EnvFilter::new("info,kels_sadstore=debug")
                }),
            )
            .with_test_writer()
            .try_init();

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

        let redis = Redis::default()
            .with_label(TEST_CONTAINER_LABEL.0, TEST_CONTAINER_LABEL.1)
            .start()
            .await
            .expect("redis failed to start");
        let redis_host = redis.get_host().await.expect("redis host");
        let redis_port = retry_get_port(&redis, 6379).await.expect("redis port");
        let redis_url = format!("redis://{}:{}", redis_host, redis_port);

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

        let kels_listener = TcpListener::bind("127.0.0.1:0").expect("kels bind");
        let kels_port = kels_listener.local_addr().unwrap().port();
        kels_listener.set_nonblocking(true).unwrap();
        let kels_url = format!("http://127.0.0.1:{}", kels_port);

        let sad_listener = TcpListener::bind("127.0.0.1:0").expect("sad bind");
        let sad_port = sad_listener.local_addr().unwrap().port();
        sad_listener.set_nonblocking(true).unwrap();
        let sad_url = format!("http://127.0.0.1:{}", sad_port);

        unsafe {
            std::env::set_var("MINIO_ENDPOINT", &minio_endpoint);
            std::env::set_var("MINIO_REGION", "us-east-1");
            std::env::set_var("MINIO_ACCESS_KEY", "minioadmin");
            std::env::set_var("MINIO_SECRET_KEY", "minioadmin");
            std::env::set_var("KELS_SAD_BUCKET", "kels-sad-test");
            std::env::set_var("KELS_TEST_ENDPOINTS", "true");
            std::env::set_var("KELS_NONCE_WINDOW_SECS", "0");
            std::env::set_var("SADSTORE_MAX_EVENTS_PER_EVENT_LOG_PER_DAY", "10000");
        }

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

/// Ground-truth setup for any round-12 SE test: creates a KEL on the KELS
/// service, a single-endorser policy `endorse(KEL_PREFIX)` (acts as both
/// auth_policy and governance_policy on the IEL — testing-grade default),
/// uploads the policy SAD, incepts an IEL on the sadstore service via
/// `IdentityEventBuilder`, and anchors the IEL Icp's SAID in the KEL
/// through `kel_builder.interact`.
///
/// Returns everything individual tests need to drive SE staging:
/// the KEL builder (for anchoring SE event SAIDs), the SE-side policy
/// checker (for hydrating builders), the IEL prefix (= the SE chain's
/// `identity`), the policy SAD (for runtime policy resolution), and a
/// fresh `SadStoreClient`.
struct Setup {
    kel_builder: KeyEventBuilder<SoftwareKeyProvider>,
    iel_prefix: Digest256,
    iel_icp_said: Digest256,
    sad_client: SadStoreClient,
    /// Type-erased policy checker bound to the harness's KEL service.
    /// Cloning is cheap (`Arc`); per-builder construction uses `Arc::clone`.
    checker: Arc<dyn PolicyChecker + Send + Sync>,
}

async fn setup_kel_iel_policy(harness: &SharedHarness, label: &str) -> Setup {
    // --- KEL ---
    let provider = SoftwareKeyProvider::new(
        VerificationKeyCode::Secp256r1,
        VerificationKeyCode::Secp256r1,
    );
    let kels_client = KelsClient::new(&harness.kels_url).expect("kels client");
    let mut kel_builder = KeyEventBuilder::new(provider, Some(kels_client));
    kel_builder
        .incept()
        .await
        .unwrap_or_else(|e| panic!("incept KEL [{}]: {:?}", label, e));
    let kel_prefix = *kel_builder.prefix().expect("KEL has prefix after incept");

    // --- Policy: `endorse(KEL_PREFIX)`, used for both IEL auth + governance. ---
    // Round-12 IEL requires `immune: true` on both auth_policy and
    // governance_policy at Icp (see `docs/design/iel/events.md`'s
    // immunity rule). Build the policy with `immune=true` so the IEL
    // verifier accepts the inception.
    let policy = Policy::build(&format!("endorse({})", kel_prefix), None, true)
        .unwrap_or_else(|e| panic!("build policy [{}]: {:?}", label, e));

    let sad_client = SadStoreClient::new(&harness.sad_url).expect("sad client");
    let policy_json = serde_json::to_value(&policy).unwrap();
    sad_client
        .post_sad_object(&policy_json)
        .await
        .unwrap_or_else(|e| panic!("upload policy [{}]: {:?}", label, e));

    let checker = build_checker(harness, policy.clone());

    // --- IEL: incept via IdentityEventBuilder, anchor in KEL, flush. ---
    let mut iel_builder = IdentityEventBuilder::new(
        Some(sad_client.clone()),
        None,
        Some(Arc::clone(&checker)),
    );
    let iel_topic = format!("{}/{}", TEST_IEL_TOPIC, label);
    let iel_icp_said = iel_builder
        .incept(policy.said, policy.said, iel_topic)
        .unwrap_or_else(|e| panic!("incept IEL [{}]: {:?}", label, e));
    let iel_prefix = *iel_builder.prefix().expect("IEL has prefix after incept");

    // Anchor the IEL Icp's SAID in the owner's KEL — the IEL Icp is
    // self-authorized via `auth_policy`, which the server checks via
    // `is_anchored(iel_icp.said, auth_policy)` → the SAID must be in
    // owner's KEL anchor history.
    kel_builder
        .interact(&iel_icp_said)
        .await
        .unwrap_or_else(|e| panic!("anchor IEL Icp [{}]: {:?}", label, e));

    let _ = iel_builder
        .flush()
        .await
        .unwrap_or_else(|e| panic!("flush IEL [{}]: {:?}", label, e));

    Setup {
        kel_builder,
        iel_prefix,
        iel_icp_said,
        sad_client,
        checker,
    }
}

fn build_checker(harness: &SharedHarness, policy: Policy) -> Arc<dyn PolicyChecker + Send + Sync> {
    let kel_source: Arc<dyn kels_core::PagedKelSource + Send + Sync> = Arc::new(
        kels_core::HttpKelSource::new(&harness.kels_url, "/api/v1/kels/kel/fetch")
            .expect("kel source"),
    );
    let resolver: Arc<dyn PolicyResolver + Send + Sync> =
        Arc::new(InMemoryPolicyResolver::new(vec![policy]));
    Arc::new(AnchoredPolicyChecker::new(kel_source, resolver))
}

/// Upload a fresh content SAD object for use as `Upd` content.
async fn upload_content(sad_client: &SadStoreClient, tag: &str) -> Digest256 {
    let mut object = serde_json::json!({
        "said": "",
        "tag": tag,
    });
    object.derive_said().unwrap();
    sad_client
        .post_sad_object(&object)
        .await
        .expect("upload content")
}

/// Assert that the result is `Err` and its body fragment matches.
/// The `SadStoreClient` maps any HTTP non-2xx into
/// `KelsError::ServerError(body, _code)` — we match on the body fragment
/// to surface specific server-side rejections (e.g., "incomplete inception",
/// "Repair required", "Bad identity binding") rather than `is_err()`-only.
fn assert_err_contains<T: std::fmt::Debug>(
    result: Result<T, KelsError>,
    fragment: &str,
    context: &str,
) {
    match result {
        Ok(value) => panic!("{}: expected error containing {:?}, got Ok({:?})", context, fragment, value),
        Err(err) => {
            let msg = err.to_string();
            assert!(
                msg.contains(fragment),
                "{}: expected error body to contain {:?}, got: {}",
                context,
                fragment,
                msg
            );
        }
    }
}

/// Fetch the chain's effective SAID + divergence flag via HTTP.
async fn fetch_effective(
    sad_client: &SadStoreClient,
    prefix: &Digest256,
) -> Option<(String, bool)> {
    sad_client
        .fetch_sel_effective_said(prefix)
        .await
        .ok()
        .flatten()
}

/// Fetch the chain's events page (linear or divergent — server returns
/// what it has).
async fn fetch_chain(sad_client: &SadStoreClient, prefix: &Digest256) -> Vec<SadEvent> {
    sad_client
        .fetch_sad_events(prefix, None)
        .await
        .expect("fetch chain")
        .events
}

/// Verify a fetched chain owner-locally and return the verification token.
async fn verify_chain(
    sad_client: &SadStoreClient,
    setup: &Setup,
    prefix: &Digest256,
) -> kels_core::SelVerification {
    use kels_core::{AnchoredIelResolver, IelResolver, PagedIelSource};
    let iel_source: Arc<dyn PagedIelSource + Send + Sync> =
        Arc::new(sad_client.as_iel_source().expect("iel source"));
    let resolver: Arc<dyn IelResolver + Send + Sync> = Arc::new(AnchoredIelResolver::new(
        iel_source,
        Arc::clone(&setup.checker),
        kels_core::page_size(),
        kels_core::max_pages(),
    ));
    sad_client
        .verify_sad_events(prefix, Arc::clone(&setup.checker), resolver)
        .await
        .expect("verify chain")
}

// ==================== Tests ====================

/// Happy path: builder.incept_chain stages [Icp, Upd]; flush submits and
/// the chain lands on the server linearly.
#[tokio::test]
#[serial]
async fn incept_lands_chain_with_upd_in_same_batch() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let mut setup = setup_kel_iel_policy(harness, "incept-happy").await;
    let content = upload_content(&setup.sad_client, "incept-happy").await;

    let mut builder = SadEventBuilder::new(
        Some(setup.sad_client.clone()),
        None,
        Some(Arc::clone(&setup.checker)),
    );
    let (icp_said, upd_said) = builder
        .incept_chain(setup.iel_prefix, TEST_TOPIC, content)
        .await
        .expect("incept_chain stages [Icp, Upd]");

    // Anchor both staged SAIDs in the KEL — the server's auth/gov policy
    // checks walk the KEL to find them.
    setup
        .kel_builder
        .interact(&icp_said)
        .await
        .expect("anchor icp");
    setup
        .kel_builder
        .interact(&upd_said)
        .await
        .expect("anchor upd");

    let outcome = builder.flush().await.expect("flush");
    assert!(outcome.applied, "fresh chain should commit");
    assert!(outcome.diverged_at_at_submit.is_none());

    let prefix = *builder.prefix().expect("prefix");
    let events = fetch_chain(&setup.sad_client, &prefix).await;
    assert_eq!(events.len(), 2, "chain should have [Icp, Upd]");
    assert_eq!(events[0].kind, kels_core::SadEventKind::Icp);
    assert_eq!(events[1].kind, kels_core::SadEventKind::Upd);
    assert_eq!(events[0].identity, Some(setup.iel_prefix));
    assert_eq!(events[1].identity_event, Some(setup.iel_icp_said));
}

/// Submit just an `Icp` (no v1 `Upd`) — server rejects with the
/// "Incomplete inception" body fragment. Pins the inception batch rule.
/// Bypasses the builder (which always stages `[Icp, Upd]` together) by
/// hand-building the Icp via `SadEvent::icp` and submitting directly.
#[tokio::test]
#[serial]
async fn incept_alone_rejected_with_incomplete_inception() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let setup = setup_kel_iel_policy(harness, "incept-alone").await;

    // Hand-build the Icp without anchoring — the inception batch rule
    // fires *before* the auth check, so anchor state doesn't matter for
    // this test.
    let icp = SadEvent::icp(TEST_TOPIC, setup.iel_prefix).expect("build Icp");

    let result: Result<SubmitSadEventsResponse, KelsError> =
        setup.sad_client.submit_sad_events(&[icp]).await;
    assert_err_contains(
        result,
        "Incomplete inception",
        "lone Icp should be rejected by inception batch rule",
    );
}

/// HARD `Upd` auth check: govfailed Upd is rejected at submit time, the
/// chain does NOT advance, and the client gets an error with the
/// "not anchored" fragment in the body. Pins the round-12 design choice
/// that replaces the dual-policy SEL's soft-Upd behavior.
#[tokio::test]
#[serial]
async fn update_rejects_when_anchor_not_anchored_under_iel_resolved_auth_policy() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let mut setup = setup_kel_iel_policy(harness, "upd-hard-auth-fail").await;
    let content = upload_content(&setup.sad_client, "upd-hard-auth-fail").await;

    let mut builder = SadEventBuilder::new(
        Some(setup.sad_client.clone()),
        None,
        Some(Arc::clone(&setup.checker)),
    );
    let (icp_said, _upd_said) = builder
        .incept_chain(setup.iel_prefix, TEST_TOPIC, content)
        .await
        .expect("incept_chain");

    // Anchor only the Icp, NOT the Upd. The server's Upd auth check runs
    // `is_anchored(upd.said, auth_policy)`; the policy is `endorse(kel)`,
    // and the Upd's SAID isn't in the KEL → HARD-fail.
    setup
        .kel_builder
        .interact(&icp_said)
        .await
        .expect("anchor icp");

    let result = builder.flush().await;
    assert_err_contains(
        result,
        "not anchored",
        "govfailed Upd must HARD-fail (chain does not advance)",
    );
}

/// Live-handler govfailed-Cnt elevation: build a Cnt event without
/// anchoring it, submit. Server's Cnt governance check is SOFT, so the
/// event lands; chain becomes contested (content-based flag);
/// `policy_satisfied=false` propagates.
#[tokio::test]
#[serial]
async fn submit_lands_govfailed_cnt_chain_becomes_contested_with_policy_unsatisfied() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let mut setup = setup_kel_iel_policy(harness, "govfailed-cnt").await;
    let content = upload_content(&setup.sad_client, "govfailed-cnt").await;

    // First land [Icp, Upd] cleanly so we have a tip to extend.
    let mut builder = SadEventBuilder::new(
        Some(setup.sad_client.clone()),
        None,
        Some(Arc::clone(&setup.checker)),
    );
    let (icp_said, upd_said) = builder
        .incept_chain(setup.iel_prefix, TEST_TOPIC, content)
        .await
        .expect("incept_chain");
    setup
        .kel_builder
        .interact_batch(&[icp_said, upd_said])
        .await
        .unwrap();
    let _ = builder.flush().await.expect("flush incept");

    // Hand-build a Cnt extending the v1 tip; do NOT anchor it. The
    // governance anchor check fails → SOFT path → Cnt lands.
    let v1 = builder.last_event().cloned().expect("v1 tip");
    let cnt = SadEvent::cnt(&v1, setup.iel_icp_said).expect("build Cnt");

    let resp = setup
        .sad_client
        .submit_sad_events(std::slice::from_ref(&cnt))
        .await
        .expect("Cnt should land via SOFT path despite govfail");
    assert!(resp.applied, "Cnt must commit (terminal-event SOFT mapping)");

    // Verify the chain end-to-end: terminal flag content-based,
    // policy_satisfied=false. Chain effective SAID is the Dec/Cnt's own
    // SAID for Dec, or `contested:{prefix}` synthetic for Cnt — fetch
    // the verification token to assert the per-flag values directly.
    let prefix = *builder.prefix().expect("prefix");
    let v = verify_chain(&setup.sad_client, &setup, &prefix).await;
    assert!(v.is_contested(), "is_contested must be set content-based");
    assert!(
        !v.policy_satisfied(),
        "policy_satisfied must be false (govfail propagates)"
    );

    // And subsequent submits to the contested chain are refused.
    let further_content = upload_content(&setup.sad_client, "post-cnt").await;
    let further_upd = SadEvent::upd(&cnt, setup.iel_icp_said, further_content).expect("build Upd");
    let result = setup.sad_client.submit_sad_events(&[further_upd]).await;
    assert_err_contains(
        result,
        "is contested",
        "contested chain must reject further submissions",
    );
}

/// Symmetric govfailed-Dec: SOFT path lands; chain becomes
/// decommissioned content-based; `policy_satisfied=false`.
#[tokio::test]
#[serial]
async fn submit_lands_govfailed_dec_chain_becomes_decommissioned_with_policy_unsatisfied() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let mut setup = setup_kel_iel_policy(harness, "govfailed-dec").await;
    let content = upload_content(&setup.sad_client, "govfailed-dec").await;

    let mut builder = SadEventBuilder::new(
        Some(setup.sad_client.clone()),
        None,
        Some(Arc::clone(&setup.checker)),
    );
    let (icp_said, upd_said) = builder
        .incept_chain(setup.iel_prefix, TEST_TOPIC, content)
        .await
        .expect("incept_chain");
    setup
        .kel_builder
        .interact_batch(&[icp_said, upd_said])
        .await
        .unwrap();
    let _ = builder.flush().await.expect("flush incept");

    let v1 = builder.last_event().cloned().expect("v1 tip");
    let dec = SadEvent::dec(&v1, setup.iel_icp_said).expect("build Dec");
    let resp = setup
        .sad_client
        .submit_sad_events(&[dec])
        .await
        .expect("Dec should land via SOFT path");
    assert!(resp.applied);

    let prefix = *builder.prefix().expect("prefix");
    let v = verify_chain(&setup.sad_client, &setup, &prefix).await;
    assert!(v.is_decommissioned(), "is_decommissioned must be set content-based");
    assert!(!v.is_contested());
    assert!(!v.policy_satisfied());

    // Subsequent submits refused with "is decommissioned".
    let further_content = upload_content(&setup.sad_client, "post-dec").await;
    let further_upd = SadEvent::upd(
        v.current_event(),
        setup.iel_icp_said,
        further_content,
    )
    .expect("build Upd");
    let result = setup.sad_client.submit_sad_events(&[further_upd]).await;
    assert_err_contains(
        result,
        "is decommissioned",
        "decommissioned chain must reject further submissions",
    );
}

/// Cnt on an unsealed-divergent SE chain: rejected with "Repair required"
/// — `Rpr` is the natural unsealed-divergence resolver; `Cnt` is reserved
/// for sealed-divergent (where Rpr can't truncate behind the seal).
#[tokio::test]
#[serial]
async fn unsealed_divergent_chain_rejects_cnt_with_repair_required() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let mut setup = setup_kel_iel_policy(harness, "unsealed-div-cnt").await;
    let content = upload_content(&setup.sad_client, "unsealed-div-cnt").await;

    // 1. Land [Icp, Upd] cleanly.
    let mut builder = SadEventBuilder::new(
        Some(setup.sad_client.clone()),
        None,
        Some(Arc::clone(&setup.checker)),
    );
    let (icp_said, upd_said) = builder
        .incept_chain(setup.iel_prefix, TEST_TOPIC, content)
        .await
        .expect("incept_chain");
    setup
        .kel_builder
        .interact_batch(&[icp_said, upd_said])
        .await
        .unwrap();
    let _ = builder.flush().await.expect("flush incept");

    // 2. Create divergence by submitting two competing Upd events at v2
    //    (server accepts the second as a fork — overlap-creates-fork path).
    let v1 = builder.last_event().cloned().expect("v1");
    let content_a = upload_content(&setup.sad_client, "fork-a").await;
    let content_b = upload_content(&setup.sad_client, "fork-b").await;
    let v2_a = SadEvent::upd(&v1, setup.iel_icp_said, content_a).unwrap();
    let v2_b = SadEvent::upd(&v1, setup.iel_icp_said, content_b).unwrap();
    setup
        .kel_builder
        .interact_batch(&[v2_a.said, v2_b.said])
        .await
        .unwrap();
    let _ = setup.sad_client.submit_sad_events(&[v2_a]).await.expect("v2_a");
    let div_resp = setup
        .sad_client
        .submit_sad_events(&[v2_b])
        .await
        .expect("v2_b creates divergence");
    assert!(
        div_resp.diverged_at.is_some(),
        "second Upd should produce server-side divergence"
    );

    // 3. Try to Cnt — chain is unsealed-divergent (no Sea ever landed),
    //    so server rejects with "Repair required".
    let prefix = *builder.prefix().expect("prefix");
    let chain_after_div = fetch_chain(&setup.sad_client, &prefix).await;
    let last = chain_after_div.last().cloned().expect("post-div tip");
    let cnt = SadEvent::cnt(&last, setup.iel_icp_said).expect("build Cnt");
    let result = setup.sad_client.submit_sad_events(&[cnt]).await;
    assert_err_contains(
        result,
        "Repair required",
        "Cnt on unsealed-divergent must route to Rpr",
    );
}

/// Dec on unsealed-divergent: rejected with "Repair required".
/// Symmetric to the Cnt case above.
#[tokio::test]
#[serial]
async fn unsealed_divergent_chain_rejects_dec_with_repair_required() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let mut setup = setup_kel_iel_policy(harness, "unsealed-div-dec").await;
    let content = upload_content(&setup.sad_client, "unsealed-div-dec").await;

    let mut builder = SadEventBuilder::new(
        Some(setup.sad_client.clone()),
        None,
        Some(Arc::clone(&setup.checker)),
    );
    let (icp_said, upd_said) = builder
        .incept_chain(setup.iel_prefix, TEST_TOPIC, content)
        .await
        .expect("incept_chain");
    setup
        .kel_builder
        .interact_batch(&[icp_said, upd_said])
        .await
        .unwrap();
    let _ = builder.flush().await.expect("flush incept");

    let v1 = builder.last_event().cloned().expect("v1");
    let content_a = upload_content(&setup.sad_client, "fork-a").await;
    let content_b = upload_content(&setup.sad_client, "fork-b").await;
    let v2_a = SadEvent::upd(&v1, setup.iel_icp_said, content_a).unwrap();
    let v2_b = SadEvent::upd(&v1, setup.iel_icp_said, content_b).unwrap();
    setup
        .kel_builder
        .interact_batch(&[v2_a.said, v2_b.said])
        .await
        .unwrap();
    let _ = setup.sad_client.submit_sad_events(&[v2_a]).await.unwrap();
    let _ = setup.sad_client.submit_sad_events(&[v2_b]).await.unwrap();

    let prefix = *builder.prefix().expect("prefix");
    let chain = fetch_chain(&setup.sad_client, &prefix).await;
    let last = chain.last().cloned().expect("tip");
    let dec = SadEvent::dec(&last, setup.iel_icp_said).expect("build Dec");
    let result = setup.sad_client.submit_sad_events(&[dec]).await;
    assert_err_contains(
        result,
        "Repair required",
        "Dec on unsealed-divergent must route to Rpr",
    );
}

/// Builder-driven happy path: `contest()` extends the verified chain
/// and the resulting `Cnt` lands cleanly. Chain becomes contested;
/// further submissions refused with "is contested".
#[tokio::test]
#[serial]
async fn contest_terminates_chain() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let mut setup = setup_kel_iel_policy(harness, "contest-builder").await;
    let content = upload_content(&setup.sad_client, "contest-builder").await;

    let mut builder = SadEventBuilder::new(
        Some(setup.sad_client.clone()),
        None,
        Some(Arc::clone(&setup.checker)),
    );
    let (icp_said, upd_said) = builder
        .incept_chain(setup.iel_prefix, TEST_TOPIC, content)
        .await
        .expect("incept_chain");
    setup
        .kel_builder
        .interact_batch(&[icp_said, upd_said])
        .await
        .unwrap();
    let _ = builder.flush().await.expect("flush incept");

    let cnt_said = builder.contest().await.expect("stage Cnt via builder");
    setup
        .kel_builder
        .interact(&cnt_said)
        .await
        .expect("anchor Cnt");
    let outcome = builder.flush().await.expect("flush Cnt");
    assert!(outcome.applied);

    let prefix = *builder.prefix().expect("prefix");
    let v = verify_chain(&setup.sad_client, &setup, &prefix).await;
    assert!(v.is_contested(), "is_contested must be true after Cnt lands");
    assert!(
        v.policy_satisfied(),
        "anchored Cnt has governance auth — policy_satisfied stays true"
    );

    let further_content = upload_content(&setup.sad_client, "post-contest").await;
    let further_upd = SadEvent::upd(
        v.current_event(),
        setup.iel_icp_said,
        further_content,
    )
    .unwrap();
    let result = setup.sad_client.submit_sad_events(&[further_upd]).await;
    assert_err_contains(
        result,
        "is contested",
        "contested chain refuses further submissions",
    );
}

/// Builder-driven `decommission()` on a clean linear chain: Dec lands,
/// chain becomes decommissioned, further submissions refused.
#[tokio::test]
#[serial]
async fn decommission_terminates_chain() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let mut setup = setup_kel_iel_policy(harness, "decommission-builder").await;
    let content = upload_content(&setup.sad_client, "decommission-builder").await;

    let mut builder = SadEventBuilder::new(
        Some(setup.sad_client.clone()),
        None,
        Some(Arc::clone(&setup.checker)),
    );
    let (icp_said, upd_said) = builder
        .incept_chain(setup.iel_prefix, TEST_TOPIC, content)
        .await
        .expect("incept_chain");
    setup
        .kel_builder
        .interact_batch(&[icp_said, upd_said])
        .await
        .unwrap();
    let _ = builder.flush().await.expect("flush incept");

    let dec_said = builder
        .decommission()
        .await
        .expect("stage Dec via builder");
    setup
        .kel_builder
        .interact(&dec_said)
        .await
        .expect("anchor Dec");
    let outcome = builder.flush().await.expect("flush Dec");
    assert!(outcome.applied);

    let prefix = *builder.prefix().expect("prefix");
    let v = verify_chain(&setup.sad_client, &setup, &prefix).await;
    assert!(v.is_decommissioned());
    assert!(!v.is_contested());
    assert!(v.policy_satisfied(), "anchored Dec has governance auth");

    let further_content = upload_content(&setup.sad_client, "post-dec").await;
    let further_upd = SadEvent::upd(
        v.current_event(),
        setup.iel_icp_said,
        further_content,
    )
    .unwrap();
    let result = setup.sad_client.submit_sad_events(&[further_upd]).await;
    assert_err_contains(
        result,
        "is decommissioned",
        "decommissioned chain refuses further submissions",
    );
}

/// `decommission()` fail-fast on divergent: surfaces a typed
/// `DecommissionBlockedByDivergence` (round-12 deviations resolved in
/// Gap 6). The error stays generic — operator routes to `repair()`
/// (unsealed) or `contest()` (sealed) based on server response.
#[tokio::test]
#[serial]
async fn builder_decommission_fail_fasts_on_divergent_chain() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let mut setup = setup_kel_iel_policy(harness, "decommission-divergent").await;
    let content = upload_content(&setup.sad_client, "decommission-divergent").await;

    // Use a shared in-memory sad_store across both builders so the
    // refreshed `with_prefix` builder can hydrate the owner's view from
    // local. Server-side divergence (created below) is detected at
    // `decommission()` time via `verify_server_chain_pre_action`.
    let owner_store: Arc<dyn kels_core::SadStore> =
        Arc::new(kels_core::InMemorySadStore::new());

    let mut builder = SadEventBuilder::new(
        Some(setup.sad_client.clone()),
        Some(Arc::clone(&owner_store)),
        Some(Arc::clone(&setup.checker)),
    );
    let (icp_said, upd_said) = builder
        .incept_chain(setup.iel_prefix, TEST_TOPIC, content)
        .await
        .expect("incept_chain");
    setup
        .kel_builder
        .interact_batch(&[icp_said, upd_said])
        .await
        .unwrap();
    let _ = builder.flush().await.expect("flush incept");

    // Create divergence on the server (events bypass owner_store).
    let v1 = builder.last_event().cloned().unwrap();
    let content_a = upload_content(&setup.sad_client, "fork-a").await;
    let content_b = upload_content(&setup.sad_client, "fork-b").await;
    let v2_a = SadEvent::upd(&v1, setup.iel_icp_said, content_a).unwrap();
    let v2_b = SadEvent::upd(&v1, setup.iel_icp_said, content_b).unwrap();
    setup
        .kel_builder
        .interact_batch(&[v2_a.said, v2_b.said])
        .await
        .unwrap();
    let _ = setup.sad_client.submit_sad_events(&[v2_a]).await.unwrap();
    let _ = setup.sad_client.submit_sad_events(&[v2_b]).await.unwrap();

    // Refresh the builder. `with_prefix` hydrates from owner_store
    // (sees only the owner-authored Icp/Upd, NOT the divergent v2_b).
    // Then `decommission()` runs `verify_server_chain_pre_action` which
    // fetches the server's full view → sees the fork → fails with
    // `DecommissionBlockedByDivergence`.
    let prefix = *builder.prefix().expect("prefix");
    let mut div_builder = SadEventBuilder::with_prefix(
        Some(setup.sad_client.clone()),
        Some(Arc::clone(&owner_store)),
        Some(Arc::clone(&setup.checker)),
        &prefix,
    )
    .await
    .expect("with_prefix on divergent chain");
    let result = div_builder.decommission().await;
    assert!(
        matches!(
            result,
            Err(KelsError::DecommissionBlockedByDivergence(_))
        ),
        "decommission on divergent must error DecommissionBlockedByDivergence, got {:?}",
        result
    );
}

// ==================== Suppress unused-import warnings ====================
//
// `IdentityEvent`, `IelVerification`, `fetch_effective` are reserved for
// Gap 10b's expanded test taxonomy (gossip propagation, sealed-divergent
// matrix coverage, etc.).
#[allow(dead_code)]
fn _gap_10b_reserved() -> (
    Option<IdentityEvent>,
    Option<IelVerification>,
    fn(),
) {
    (None, None, || {})
}

#[allow(dead_code)]
async fn _gap_10b_unused_helpers(sad_client: &SadStoreClient, prefix: &Digest256) {
    let _ = fetch_effective(sad_client, prefix).await;
}
