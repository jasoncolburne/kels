//! Full-stack integration tests for `IdentityEventBuilder` and the IEL
//! submit handler.
//!
//! Mirrors the harness in `sad_builder_tests.rs`: spins up KELS + sadstore
//! HTTP services backed by testcontainers (Postgres ×2, Redis, MinIO) so that
//! the policy resolver can resolve immune policies and the anchored-policy
//! checker can walk real KELs. Each test marks itself `#[serial]` to avoid
//! cross-test contamination.
//!
//! Multi-sadstore gossip integration tests (`gossip_full_chain_appends_to_empty_sink`,
//! `gossip_propagates_cnt_to_divergent_sink`) are deferred: they need two
//! sadstore instances plus a gossip service, which is more harness than this
//! file should carry. Single-node submit/builder coverage is here; cross-node
//! convergence is covered separately by the federation shell scripts.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    net::TcpListener,
    sync::{Arc, OnceLock},
    time::Duration,
};

use ctor::dtor;
use kels_core::{
    IdentityEvent, IdentityEventBuilder, IdentityEventKind, KelsClient, KeyEventBuilder,
    PolicyChecker, SadStoreClient, SoftwareKeyProvider, VerificationKeyCode,
    compute_identity_event_prefix,
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

const TEST_CONTAINER_LABEL: (&str, &str) = ("kels-test", "true");
const TEST_TOPIC: &str = "kels/iel/v1/identity/test";

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

        // SAFETY: called before the server threads spawn, so no concurrent env reads.
        unsafe {
            std::env::set_var("MINIO_ENDPOINT", &minio_endpoint);
            std::env::set_var("MINIO_REGION", "us-east-1");
            std::env::set_var("MINIO_ACCESS_KEY", "minioadmin");
            std::env::set_var("MINIO_SECRET_KEY", "minioadmin");
            std::env::set_var("KELS_SAD_BUCKET", "kels-sad-test-iel");
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
        eprintln!("IEL harness ready: KELS={} SAD={}", kels_url, sad_url);

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

/// A KEL prefix + builder-with-anchoring + the immune `endorse(prefix)` policy
/// uploaded to the sadstore. Mirrors `setup_kel_and_policy` from
/// `sad_builder_tests.rs` but returns an immune policy (IEL requires immune).
async fn setup_kel_and_immune_policy(
    harness: &SharedHarness,
    label: &str,
) -> (
    cesr::Digest256,
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

    // Immune `endorse(prefix)` — IEL submit handler rejects non-immune policies.
    let policy = Policy::build(&format!("endorse({})", prefix), None, true)
        .expect("build immune endorse policy");

    let sad_client = SadStoreClient::new(&harness.sad_url).expect("sad client");
    let policy_json = serde_json::to_value(&policy).unwrap();
    sad_client
        .post_sad_object(&policy_json)
        .await
        .unwrap_or_else(|e| panic!("upload immune policy for {}: {:?}", label, e));

    (prefix, kel_builder, policy, sad_client)
}

/// Upload a non-immune `endorse(prefix)` policy to exercise the immunity-rejection paths.
async fn upload_non_immune_policy(
    harness: &SharedHarness,
    kel_prefix: &cesr::Digest256,
    label: &str,
) -> Policy {
    let policy = Policy::build(&format!("endorse({})", kel_prefix), None, false)
        .expect("build non-immune policy");
    let sad_client = SadStoreClient::new(&harness.sad_url).expect("sad client");
    let policy_json = serde_json::to_value(&policy).unwrap();
    sad_client
        .post_sad_object(&policy_json)
        .await
        .unwrap_or_else(|e| panic!("upload non-immune policy for {}: {:?}", label, e));
    policy
}

/// Build the `AnchoredPolicyChecker` for IEL flows. Same shape as SE's tests
/// — an HttpKelSource against the harness KELS plus an in-memory resolver
/// seeded with the supplied policies.
fn build_checker(
    harness: &SharedHarness,
    policies: Vec<Policy>,
) -> Arc<dyn PolicyChecker + Send + Sync> {
    let kel_source: Arc<dyn kels_core::PagedKelSource + Send + Sync> = Arc::new(
        kels_core::HttpKelSource::new(&harness.kels_url, "/api/v1/kels/kel/fetch")
            .expect("kel source"),
    );
    let resolver: Arc<dyn PolicyResolver + Send + Sync> =
        Arc::new(InMemoryPolicyResolver::new(policies));
    Arc::new(AnchoredPolicyChecker::new(kel_source, resolver))
}

/// Compute the IEL prefix for a `(auth_policy, governance_policy, topic)` triple.
fn iel_prefix_for(
    auth_policy: cesr::Digest256,
    governance_policy: cesr::Digest256,
    topic: &str,
) -> cesr::Digest256 {
    compute_identity_event_prefix(auth_policy, governance_policy, topic)
        .expect("compute IEL prefix")
}

/// Assert a `SadStoreClient` call returned an error whose `Display` contains
/// `fragment`. Tightens tests that previously asserted only `is_err()` — the
/// client maps every non-success response to `KelsError::ServerError(text, _)`,
/// so without a body-text check a regression on a different rejection path
/// (storage flake, structural error, anchor failure) would still pass.
#[track_caller]
fn assert_err_contains<T: std::fmt::Debug>(
    resp: &Result<T, kels_core::KelsError>,
    fragment: &str,
) {
    match resp {
        Ok(v) => panic!(
            "expected error containing {:?}, got Ok({:?})",
            fragment, v
        ),
        Err(e) => {
            let s = e.to_string();
            assert!(
                s.contains(fragment),
                "expected error to contain {:?}; got: {}",
                fragment,
                s
            );
        }
    }
}

/// Build, anchor, and submit one IEL `Icp` end-to-end. Returns the builder (with
/// verification populated) for further use.
async fn incept_and_flush(
    harness: &SharedHarness,
    label: &str,
) -> (
    IdentityEventBuilder,
    KeyEventBuilder<SoftwareKeyProvider>,
    Policy,
) {
    let (_kel_prefix, mut kel_builder, policy, sad_client) =
        setup_kel_and_immune_policy(harness, label).await;
    let checker = build_checker(harness, vec![policy.clone()]);
    let mut builder = IdentityEventBuilder::new(Some(sad_client.clone()), None, Some(checker));
    let icp_said = builder
        .incept(policy.said, policy.said, TEST_TOPIC)
        .expect("stage Icp");

    kel_builder
        .interact(&icp_said)
        .await
        .expect("anchor Icp under auth_policy");

    let _ = builder.flush().await.expect("flush Icp");
    (builder, kel_builder, policy)
}

// ==================== Tests ====================

#[tokio::test]
#[serial]
async fn incept_lands_chain() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let (_kel_prefix, mut kel_builder, policy, sad_client) =
        setup_kel_and_immune_policy(harness, "incept-lands").await;
    let checker = build_checker(harness, vec![policy.clone()]);

    let mut builder = IdentityEventBuilder::new(Some(sad_client.clone()), None, Some(checker));
    let icp_said = builder
        .incept(policy.said, policy.said, TEST_TOPIC)
        .expect("stage Icp");
    kel_builder.interact(&icp_said).await.expect("anchor Icp");

    let outcome = builder.flush().await.expect("flush Icp");
    assert!(outcome.applied);
    assert!(outcome.diverged_at_at_submit.is_none());

    let prefix = iel_prefix_for(policy.said, policy.said, TEST_TOPIC);
    let page = sad_client
        .fetch_identity_events(&prefix, None)
        .await
        .expect("fetch IEL");
    assert_eq!(page.events.len(), 1);
    assert_eq!(page.events[0].said, icp_said);
    assert_eq!(page.events[0].kind, IdentityEventKind::Icp);
    assert_eq!(page.events[0].auth_policy, policy.said);
    assert_eq!(page.events[0].governance_policy, policy.said);
}

#[tokio::test]
#[serial]
async fn evolve_appends_to_chain() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let (_kel_prefix, mut kel_builder, policy, sad_client) =
        setup_kel_and_immune_policy(harness, "evolve-appends").await;
    let checker = build_checker(harness, vec![policy.clone()]);

    let mut builder = IdentityEventBuilder::new(Some(sad_client.clone()), None, Some(checker));
    let icp_said = builder
        .incept(policy.said, policy.said, TEST_TOPIC)
        .expect("stage Icp");
    kel_builder.interact(&icp_said).await.expect("anchor Icp");
    let _ = builder.flush().await.expect("flush Icp");

    let evl_said = builder.evolve(None, None).expect("stage Evl");
    kel_builder.interact(&evl_said).await.expect("anchor Evl");
    let _ = builder.flush().await.expect("flush Evl");

    let prefix = iel_prefix_for(policy.said, policy.said, TEST_TOPIC);
    let page = sad_client
        .fetch_identity_events(&prefix, None)
        .await
        .unwrap();
    assert_eq!(page.events.len(), 2);
    assert_eq!(page.events[1].said, evl_said);
    assert_eq!(page.events[1].kind, IdentityEventKind::Evl);
    assert_eq!(page.events[1].version, 1);
}

#[tokio::test]
#[serial]
async fn evolve_with_auth_policy_evolves_branch_state() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let (_kel_prefix, mut kel_builder, policy_a, sad_client) =
        setup_kel_and_immune_policy(harness, "evolve-auth").await;
    // Second immune policy as the new auth_policy.
    let policy_b =
        upload_immune_policy(harness, kel_builder.prefix().unwrap(), "evolve-auth-b").await;
    let checker = build_checker(harness, vec![policy_a.clone(), policy_b.clone()]);

    let mut builder = IdentityEventBuilder::new(Some(sad_client.clone()), None, Some(checker));
    let icp_said = builder
        .incept(policy_a.said, policy_a.said, TEST_TOPIC)
        .unwrap();
    kel_builder.interact(&icp_said).await.unwrap();
    let _ = builder.flush().await.unwrap();

    let evl_said = builder.evolve(Some(policy_b.said), None).unwrap();
    kel_builder.interact(&evl_said).await.unwrap();
    let _ = builder.flush().await.unwrap();

    let v = builder.iel_verification().unwrap();
    let evl_event = v.current_event().unwrap();
    assert_eq!(evl_event.auth_policy, policy_b.said);
    assert_eq!(evl_event.governance_policy, policy_a.said); // unchanged
    assert_eq!(v.auth_policy_at(&icp_said), Some(policy_a.said));
    assert_eq!(v.auth_policy_at(&evl_said), Some(policy_b.said));
}

#[tokio::test]
#[serial]
async fn contest_terminates_chain() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let (_kel_prefix, mut kel_builder, policy, sad_client) =
        setup_kel_and_immune_policy(harness, "contest-terminates").await;
    let checker = build_checker(harness, vec![policy.clone()]);

    let mut builder = IdentityEventBuilder::new(Some(sad_client.clone()), None, Some(checker));
    let icp_said = builder
        .incept(policy.said, policy.said, TEST_TOPIC)
        .unwrap();
    kel_builder.interact(&icp_said).await.unwrap();
    let _ = builder.flush().await.unwrap();

    let cnt_said = builder.contest().await.expect("stage Cnt");
    kel_builder.interact(&cnt_said).await.expect("anchor Cnt");
    let _ = builder.flush().await.expect("flush Cnt");

    // Subsequent submission should fail with a 403 (ContestedIel surfaces from
    // the server as a generic ServerError in the client).
    let mut builder2 = IdentityEventBuilder::new(
        Some(sad_client.clone()),
        None,
        Some(build_checker(harness, vec![policy.clone()])),
    );
    let evl_event = IdentityEvent::evl(
        &builder
            .iel_verification()
            .and_then(|v| v.current_event())
            .or_else(|| builder.last_event())
            .expect("tip from Cnt builder")
            .clone(),
        None,
        None,
    )
    .expect("build Evl extending Cnt tip");
    let _ = builder2.flush().await.unwrap(); // empty pending
    let resp = sad_client
        .submit_identity_events(std::slice::from_ref(&evl_event))
        .await;
    // Terminal-state gate: server returns "IEL <prefix> is contested — no
    // further events accepted" once a Cnt has landed.
    assert_err_contains(&resp, "is contested");
    assert_err_contains(&resp, "no further events accepted");
}

#[tokio::test]
#[serial]
async fn decommission_terminates_chain() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let (_kel_prefix, mut kel_builder, policy, sad_client) =
        setup_kel_and_immune_policy(harness, "decommission-terminates").await;
    let checker = build_checker(harness, vec![policy.clone()]);

    let mut builder = IdentityEventBuilder::new(Some(sad_client.clone()), None, Some(checker));
    let icp_said = builder
        .incept(policy.said, policy.said, TEST_TOPIC)
        .unwrap();
    kel_builder.interact(&icp_said).await.unwrap();
    let _ = builder.flush().await.unwrap();

    let dec_said = builder.decommission().await.expect("stage Dec");
    kel_builder.interact(&dec_said).await.expect("anchor Dec");
    let _ = builder.flush().await.expect("flush Dec");

    // Subsequent submission must fail.
    let evl_event = IdentityEvent::evl(
        builder
            .iel_verification()
            .and_then(|v| v.current_event())
            .expect("tip after Dec"),
        None,
        None,
    )
    .unwrap();
    let resp = sad_client
        .submit_identity_events(std::slice::from_ref(&evl_event))
        .await;
    // Terminal-state gate: server returns "IEL <prefix> is decommissioned — no
    // further events accepted" once a Dec has landed.
    assert_err_contains(&resp, "is decommissioned");
    assert_err_contains(&resp, "no further events accepted");
}

#[tokio::test]
#[serial]
async fn divergent_chain_rejects_non_cnt_with_contest_required() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let (_kel_prefix, mut kel_builder, policy, sad_client) =
        setup_kel_and_immune_policy(harness, "divergent-rejects-evl").await;

    // Submit `[v0, v1_a, v1_b]` in a SINGLE batch to create divergence
    // pre-seal. Once v1_a lands, the seal advances to 1; subsequent sealed
    // submits at v=1 would trip the algorithmic ContestRequired trigger
    // before reaching save_batch's overlap-creates-fork branch. Submitting
    // the divergent pair in one batch lets save_batch handle the fork before
    // any seal exists. Tests `divergent_chain_rejects_dec` and
    // `divergent_chain_accepts_cnt_terminates` use the same shape.
    let v0 = IdentityEvent::icp(policy.said, policy.said, TEST_TOPIC).unwrap();
    let v1_a = IdentityEvent::evl(&v0, None, None).unwrap();
    let policy_b =
        upload_immune_policy(harness, kel_builder.prefix().unwrap(), "divergent-b").await;
    let v1_b = IdentityEvent::evl(&v0, Some(policy_b.said), None).unwrap();
    kel_builder.interact(&v0.said).await.unwrap();
    kel_builder.interact(&v1_a.said).await.unwrap();
    kel_builder.interact(&v1_b.said).await.unwrap();

    let resp_first = sad_client
        .submit_identity_events(&[v0.clone(), v1_a.clone(), v1_b.clone()])
        .await
        .expect("submit divergent batch");
    assert_eq!(resp_first.diverged_at, Some(1));

    // Subsequent Evl extending v1_a — the chain is divergent so this must
    // be rejected. The server returns "Contest required: IEL is divergent —
    // only Cnt resolves a divergent IEL".
    let v2 = IdentityEvent::evl(&v1_a, None, None).unwrap();
    kel_builder.interact(&v2.said).await.unwrap();
    let resp = sad_client.submit_identity_events(&[v2]).await;
    assert_err_contains(&resp, "Contest required");
    assert_err_contains(&resp, "divergent");
}

#[tokio::test]
#[serial]
async fn divergent_chain_rejects_dec_with_contest_required() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let (_kel_prefix, mut kel_builder, policy, sad_client) =
        setup_kel_and_immune_policy(harness, "divergent-rejects-dec").await;
    let policy_b =
        upload_immune_policy(harness, kel_builder.prefix().unwrap(), "divergent-dec-b").await;

    let v0 = IdentityEvent::icp(policy.said, policy.said, TEST_TOPIC).unwrap();
    let v1_a = IdentityEvent::evl(&v0, None, None).unwrap();
    let v1_b = IdentityEvent::evl(&v0, Some(policy_b.said), None).unwrap();
    for e in [&v0, &v1_a, &v1_b] {
        kel_builder.interact(&e.said).await.unwrap();
    }
    let _ = sad_client
        .submit_identity_events(&[v0.clone(), v1_a.clone(), v1_b.clone()])
        .await
        .expect("submit divergent batch");

    // Dec on a divergent chain must be rejected — only Cnt resolves
    // divergence. The X-1 routing rule ensures the divergent-rejection branch
    // fires before is_decommission, so we get "Contest required: ... divergent"
    // rather than acceptance or a generic 4xx.
    let dec = IdentityEvent::dec(&v1_a).unwrap();
    kel_builder.interact(&dec.said).await.unwrap();
    let resp = sad_client.submit_identity_events(&[dec]).await;
    assert_err_contains(&resp, "Contest required");
    assert_err_contains(&resp, "divergent");
}

#[tokio::test]
#[serial]
async fn divergent_chain_accepts_cnt_terminates() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let (_kel_prefix, mut kel_builder, policy, sad_client) =
        setup_kel_and_immune_policy(harness, "divergent-cnt").await;
    let policy_b =
        upload_immune_policy(harness, kel_builder.prefix().unwrap(), "divergent-cnt-b").await;

    let v0 = IdentityEvent::icp(policy.said, policy.said, TEST_TOPIC).unwrap();
    let v1_a = IdentityEvent::evl(&v0, None, None).unwrap();
    let v1_b = IdentityEvent::evl(&v0, Some(policy_b.said), None).unwrap();
    for e in [&v0, &v1_a, &v1_b] {
        kel_builder.interact(&e.said).await.unwrap();
    }
    let _ = sad_client
        .submit_identity_events(&[v0.clone(), v1_a.clone(), v1_b.clone()])
        .await
        .expect("submit divergent batch");

    // Cnt extending lower-SAID branch tip (deterministic across nodes). The
    // builder picks lower-SAID; mirror that here for the test.
    let lower = if v1_a.said.as_ref() < v1_b.said.as_ref() {
        &v1_a
    } else {
        &v1_b
    };
    let cnt = IdentityEvent::cnt(lower).unwrap();
    kel_builder.interact(&cnt.said).await.unwrap();

    // Cnt on a divergent chain must succeed AND mark the chain applied.
    let cnt_resp = sad_client
        .submit_identity_events(&[cnt])
        .await
        .expect("Cnt on divergent IEL accepted");
    assert!(cnt_resp.applied, "Cnt should report applied=true");

    // Subsequent submission rejected — the chain is now contested, so the
    // terminal-state gate fires before any routing.
    let evl_extra = IdentityEvent::evl(&v1_a, None, None).unwrap();
    kel_builder.interact(&evl_extra.said).await.unwrap();
    let resp = sad_client.submit_identity_events(&[evl_extra]).await;
    assert_err_contains(&resp, "is contested");
    assert_err_contains(&resp, "no further events accepted");
}

#[tokio::test]
#[serial]
async fn submit_rejects_non_immune_auth_policy_at_icp() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let (_kel_prefix, _kel_builder, immune_policy, sad_client) =
        setup_kel_and_immune_policy(harness, "non-immune-auth-icp").await;
    let non_immune = upload_non_immune_policy(
        harness,
        _kel_builder.prefix().unwrap(),
        "non-immune-auth-icp",
    )
    .await;

    // Icp with non-immune auth_policy — server must reject before anchoring
    // matters. Verifier emits "IEL Icp <said> declares non-immune auth_policy".
    let v0 = IdentityEvent::icp(non_immune.said, immune_policy.said, TEST_TOPIC).unwrap();
    let resp = sad_client.submit_identity_events(&[v0]).await;
    assert_err_contains(&resp, "non-immune auth_policy");
}

#[tokio::test]
#[serial]
async fn submit_rejects_non_immune_governance_policy_at_icp() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let (_kel_prefix, _kel_builder, immune_policy, sad_client) =
        setup_kel_and_immune_policy(harness, "non-immune-gov-icp").await;
    let non_immune = upload_non_immune_policy(
        harness,
        _kel_builder.prefix().unwrap(),
        "non-immune-gov-icp",
    )
    .await;

    let v0 = IdentityEvent::icp(immune_policy.said, non_immune.said, TEST_TOPIC).unwrap();
    let resp = sad_client.submit_identity_events(&[v0]).await;
    assert_err_contains(&resp, "non-immune governance_policy");
}

#[tokio::test]
#[serial]
async fn submit_rejects_non_immune_auth_policy_at_evl_evolution() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let (_kel_prefix, mut kel_builder, immune_policy, sad_client) =
        setup_kel_and_immune_policy(harness, "non-immune-auth-evl").await;
    let non_immune = upload_non_immune_policy(
        harness,
        kel_builder.prefix().unwrap(),
        "non-immune-auth-evl",
    )
    .await;

    let v0 = IdentityEvent::icp(immune_policy.said, immune_policy.said, TEST_TOPIC).unwrap();
    kel_builder.interact(&v0.said).await.unwrap();
    let _ = sad_client
        .submit_identity_events(std::slice::from_ref(&v0))
        .await
        .unwrap();

    // Evl evolving auth_policy to non-immune — must be rejected. Verifier
    // emits "IEL Evl <said> evolves auth_policy to non-immune".
    let v1 = IdentityEvent::evl(&v0, Some(non_immune.said), None).unwrap();
    kel_builder.interact(&v1.said).await.unwrap();
    let resp = sad_client.submit_identity_events(&[v1]).await;
    assert_err_contains(&resp, "evolves auth_policy to non-immune");
}

#[tokio::test]
#[serial]
async fn submit_rejects_non_immune_governance_policy_at_evl_evolution() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let (_kel_prefix, mut kel_builder, immune_policy, sad_client) =
        setup_kel_and_immune_policy(harness, "non-immune-gov-evl").await;
    let non_immune =
        upload_non_immune_policy(harness, kel_builder.prefix().unwrap(), "non-immune-gov-evl")
            .await;

    let v0 = IdentityEvent::icp(immune_policy.said, immune_policy.said, TEST_TOPIC).unwrap();
    kel_builder.interact(&v0.said).await.unwrap();
    let _ = sad_client
        .submit_identity_events(std::slice::from_ref(&v0))
        .await
        .unwrap();

    let v1 = IdentityEvent::evl(&v0, None, Some(non_immune.said)).unwrap();
    kel_builder.interact(&v1.said).await.unwrap();
    let resp = sad_client.submit_identity_events(&[v1]).await;
    assert_err_contains(&resp, "evolves governance_policy to non-immune");
}

#[tokio::test]
#[serial]
async fn submit_rejects_icp_not_anchored_under_declared_auth_policy() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let (_kel_prefix, _kel_builder, policy, sad_client) =
        setup_kel_and_immune_policy(harness, "icp-anchor-gate").await;

    // Submit Icp WITHOUT calling kel_builder.interact — the auth_policy
    // requires `endorse(KEL_PREFIX)` to anchor the Icp.said in this KEL, and
    // we deliberately skip that step. Handler returns "IEL anchoring not
    // satisfied — Icp must be anchored under its declared auth_policy".
    let v0 = IdentityEvent::icp(policy.said, policy.said, TEST_TOPIC).unwrap();
    let resp = sad_client.submit_identity_events(&[v0]).await;
    assert_err_contains(&resp, "anchoring not satisfied");
    assert_err_contains(&resp, "auth_policy");
}

#[tokio::test]
#[serial]
async fn submit_evl_at_sealed_version_returns_contest_required() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let (_kel_prefix, mut kel_builder, policy, sad_client) =
        setup_kel_and_immune_policy(harness, "evl-sealed-version").await;

    // v0 (Icp) + v1 (Evl) → seal at v1.
    let v0 = IdentityEvent::icp(policy.said, policy.said, TEST_TOPIC).unwrap();
    let v1 = IdentityEvent::evl(&v0, None, None).unwrap();
    kel_builder.interact(&v0.said).await.unwrap();
    kel_builder.interact(&v1.said).await.unwrap();
    let _ = sad_client
        .submit_identity_events(&[v0.clone(), v1.clone()])
        .await
        .unwrap();

    // Build a *different* Evl also at v1 (different SAID) — this would land at
    // version 1 which equals the seal. The submit handler's algorithmic
    // ContestRequired trigger fires.
    let policy_b =
        upload_immune_policy(harness, kel_builder.prefix().unwrap(), "evl-sealed-b").await;
    let v1_alt = IdentityEvent::evl(&v0, Some(policy_b.said), None).unwrap();
    kel_builder.interact(&v1_alt.said).await.unwrap();
    let resp = sad_client.submit_identity_events(&[v1_alt]).await;
    // Algorithmic ContestRequired: handler returns "Contest required: IEL Evl
    // at version <v> lands at or before evaluation seal <s>".
    assert_err_contains(&resp, "Contest required");
    assert_err_contains(&resp, "seal");
}

/// Pin that re-submitting the same Icp is an idempotent no-op (server dedups
/// by SAID rather than rejecting the second batch).
///
/// The actual v0-divergence rule (two distinct SAIDs at v=0 for the same
/// prefix is rejected) lives in the verifier's first-generation handling and
/// is covered by `v0_divergence_rejected` in
/// `lib/kels/src/types/iel/verification.rs` — it has no honest integration
/// expression because the public `IdentityEvent::icp` constructor pins the
/// SAID by the (auth, gov, topic) inputs that also pin the prefix.
#[tokio::test]
#[serial]
async fn duplicate_icp_dedups_idempotently() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let (_kel_prefix, mut kel_builder, policy_a, sad_client) =
        setup_kel_and_immune_policy(harness, "duplicate-icp-dedup").await;

    let v0 = IdentityEvent::icp(policy_a.said, policy_a.said, TEST_TOPIC).unwrap();
    kel_builder.interact(&v0.said).await.unwrap();
    let first = sad_client
        .submit_identity_events(std::slice::from_ref(&v0))
        .await
        .expect("first Icp submit");
    assert!(first.applied, "first Icp must report applied=true");

    let second = sad_client
        .submit_identity_events(std::slice::from_ref(&v0))
        .await
        .expect("duplicate Icp submit must succeed (dedup), not create v0 divergence");
    assert!(
        !second.applied,
        "duplicate Icp must report applied=false (no-op dedup)"
    );
}

// ==================== Helper: upload immune policy ====================

/// Spin up a second KEL and upload an immune `endorse(<that-kel-prefix>)`
/// policy. Used to give a divergent IEL a *different* auth_policy on its
/// second branch — building a second policy off the same KEL prefix would
/// collide with the first policy's SAID and make the two competing Evls
/// identical.
async fn upload_immune_policy(
    harness: &SharedHarness,
    _seed_kel_prefix: &cesr::Digest256,
    label: &str,
) -> Policy {
    let provider = SoftwareKeyProvider::new(
        VerificationKeyCode::Secp256r1,
        VerificationKeyCode::Secp256r1,
    );
    let kels_client = KelsClient::new(&harness.kels_url).expect("kels client");
    let mut second_kel = KeyEventBuilder::new(provider, Some(kels_client));
    second_kel
        .incept()
        .await
        .unwrap_or_else(|e| panic!("incept second KEL for {}: {:?}", label, e));
    let second_prefix = *second_kel.prefix().expect("second KEL has prefix");

    let policy = Policy::build(&format!("endorse({})", second_prefix), None, true)
        .expect("build immune policy");
    let sad_client = SadStoreClient::new(&harness.sad_url).expect("sad client");
    let policy_json = serde_json::to_value(&policy).unwrap();
    sad_client
        .post_sad_object(&policy_json)
        .await
        .unwrap_or_else(|e| panic!("upload immune policy for {}: {:?}", label, e));
    policy
}

// `incept_and_flush` is currently unused but provides a convenient handle for
// future tests that need an established IEL chain as a precondition.
#[allow(dead_code)]
async fn _suppress_incept_and_flush_unused(harness: &SharedHarness) {
    let _ = incept_and_flush(harness, "_unused").await;
}
