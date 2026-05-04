//! Full-stack tests for the #147 SE submit handler + builder.
//!
//! **Critical-subset coverage.** The plan's full taxonomy is 30+ cases;
//! this file ships ~10 high-value tests covering the genuinely-new #147
//! surface (HARD Upd auth, soft govfailed Cnt/Dec live-handler elevation,
//! sealed/unsealed routing matrix, terminal-chain refusal). The remaining
//! cases (gossip propagation, more sealed-* combinations, prefix-derivation
//! contract pin, etc.) land in a follow-up pass; the deployment-test
//! sweep covers some of the same surface in the interim.
//!
//! Why the full harness: `SadEventBuilder::flush`
//! round-trips through `submit_sad_events`, which the sadstore server
//! verifies by calling `AnchoredPolicyChecker` (KEL anchoring) and
//! `RepositoryIelResolver` (IEL binding). HTTP-level mocks would split
//! invariants — bring the real services up against testcontainers
//! (Postgres x2, Redis, RustFS, KELS service, SADStore service).
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
    PolicyChecker, SadEvent, SadEventBuilder, SadEventTerminalState, SadStoreClient,
    SoftwareKeyProvider, SubmitSadEventsResponse, VerificationKeyCode,
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
    /// Direct DB URL for the SAD-store Postgres container — used by
    /// integration tests that need to construct a `SadStoreRepository`
    /// in-process (e.g., to drive `RepositoryIelResolver` directly).
    sad_db_url: String,
    _pg_kels: ContainerAsync<Postgres>,
    _pg_sad: ContainerAsync<Postgres>,
    _redis: ContainerAsync<Redis>,
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
            .expect("object store failed to start");
        let objects_host = objects.get_host().await.expect("object store host");
        let objects_port = retry_get_port_generic(&objects, 9000)
            .await
            .expect("object store port");
        let objects_endpoint = format!("http://{}:{}", objects_host, objects_port);

        let kels_listener = TcpListener::bind("127.0.0.1:0").expect("kels bind");
        let kels_port = kels_listener.local_addr().unwrap().port();
        kels_listener.set_nonblocking(true).unwrap();
        let kels_url = format!("http://127.0.0.1:{}", kels_port);

        let sad_listener = TcpListener::bind("127.0.0.1:0").expect("sad bind");
        let sad_port = sad_listener.local_addr().unwrap().port();
        sad_listener.set_nonblocking(true).unwrap();
        let sad_url = format!("http://127.0.0.1:{}", sad_port);

        unsafe {
            std::env::set_var("OBJECTS_ENDPOINT", &objects_endpoint);
            std::env::set_var("OBJECTS_REGION", "us-east-1");
            std::env::set_var("OBJECTS_ACCESS_KEY", "rustfsadmin");
            std::env::set_var("OBJECTS_SECRET_KEY", "rustfsadmin");
            std::env::set_var("KELS_SAD_BUCKET", "kels-sad-test");
            std::env::set_var("KELS_TEST_ENDPOINTS", "true");
            std::env::set_var("KELS_NONCE_WINDOW_SECS", "0");
            std::env::set_var("SADSTORE_MAX_SEL_EVENTS_PER_PREFIX_PER_DAY", "10000");
            std::env::set_var("SADSTORE_MAX_IEL_EVENTS_PER_PREFIX_PER_DAY", "10000");
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
            sad_db_url,
            _pg_kels: pg_kels,
            _pg_sad: pg_sad,
            _redis: redis,
            _objects: objects,
        })
    }
}

// ==================== Per-test setup helpers ====================

/// Ground-truth setup for any #147 SE test: creates a KEL on the KELS
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
    /// The original endorse(KEL_PREFIX) policy used for both auth +
    /// governance on the IEL Icp. Tests that introduce additional
    /// policies (e.g., via `create_iel_divergence`) thread this through
    /// `verify_chain_with_policies` to seed the in-memory resolver.
    policy: Policy,
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
    // #147 IEL requires `immune: true` on both auth_policy and
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
    let mut iel_builder =
        IdentityEventBuilder::new(Some(sad_client.clone()), None, Some(Arc::clone(&checker)));
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
        policy,
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
        Ok(value) => panic!(
            "{}: expected error containing {:?}, got Ok({:?})",
            context, fragment, value
        ),
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
///
/// Mirrors the production `SadEventBuilder::verify_server_chain_pre_action`
/// flow: SE pre-walk over the source → collect identity_event SAIDs →
/// construct resolver via `with_queried_saids` → verify.
async fn verify_chain(
    sad_client: &SadStoreClient,
    setup: &Setup,
    prefix: &Digest256,
) -> kels_core::SelVerification {
    use kels_core::{AnchoredIelResolver, IelResolver, PagedIelSource};
    let queried = kels_core::collect_identity_event_saids(
        prefix,
        &sad_client.as_sad_source().expect("sad source"),
        kels_core::page_size(),
        kels_core::max_pages(),
    )
    .await
    .expect("SE pre-walk");
    let iel_source: Arc<dyn PagedIelSource + Send + Sync> =
        Arc::new(sad_client.as_iel_source().expect("iel source"));
    let resolver: Arc<dyn IelResolver + Send + Sync> = Arc::new(
        AnchoredIelResolver::new(
            iel_source,
            Arc::clone(&setup.checker),
            kels_core::page_size(),
            kels_core::max_pages(),
        )
        .with_queried_saids(queried),
    );
    sad_client
        .verify_sad_events(prefix, Arc::clone(&setup.checker), resolver)
        .await
        .expect("verify chain")
}

/// Stage and flush a fresh `[Icp, Upd]` SE chain bound to the IEL in
/// `setup`. Returns the v1 (Upd) event for callers that need to extend
/// the chain further.
async fn establish_se_chain(setup: &mut Setup, label: &str) -> SadEvent {
    let content = upload_content(&setup.sad_client, label).await;
    let mut builder = SadEventBuilder::new(
        Some(setup.sad_client.clone()),
        None,
        Some(Arc::clone(&setup.checker)),
    );
    let (icp_said, upd_said) = builder
        .incept_chain(setup.iel_prefix, TEST_TOPIC, content)
        .await
        .unwrap_or_else(|e| panic!("incept_chain [{}]: {:?}", label, e));
    setup
        .kel_builder
        .interact_batch(&[icp_said, upd_said])
        .await
        .unwrap_or_else(|e| panic!("anchor incept [{}]: {:?}", label, e));
    let _ = builder
        .flush()
        .await
        .unwrap_or_else(|e| panic!("flush incept [{}]: {:?}", label, e));
    builder.last_event().cloned().expect("v1 tip after flush")
}

/// Evolve the IEL one step: stage an `Evl` carrying the existing
/// auth/governance policies forward, anchor in the KEL, submit. Returns
/// the new IEL event's SAID.
///
/// Hand-built rather than via `IdentityEventBuilder::with_prefix` because
/// `with_prefix` would need an `IdentityStore` to hydrate from, and the
/// test harness skips that to keep setup lean.
async fn evolve_iel(setup: &mut Setup, _label: &str) -> Digest256 {
    use kels_core::IdentityEventKind;
    use verifiable_storage::Chained;

    let iel_chain: Vec<IdentityEvent> = setup
        .sad_client
        .fetch_identity_events(&setup.iel_prefix, None)
        .await
        .expect("fetch IEL")
        .events;
    let tip = iel_chain.into_iter().last().expect("non-empty IEL");

    let mut evl = tip.clone();
    evl.kind = IdentityEventKind::Evl;
    // Carry-forward unchanged: same auth_policy / governance_policy.
    evl.increment().unwrap();

    setup.kel_builder.interact(&evl.said).await.unwrap();
    let _ = setup
        .sad_client
        .submit_identity_events(std::slice::from_ref(&evl))
        .await
        .expect("submit IEL Evl");
    evl.said
}

/// Create IEL divergence: two competing v1 `Evl` events at the same
/// version, submitted in **one batch** so the IEL handler's per-batch
/// `save_batch` overlap-creates-fork path fires before the seal-check
/// would block subsequent submissions.
///
/// The two Evls differ via a `poison` discriminator on the auth_policy
/// (same endorse-form expression, different `poison` value → different
/// SAIDs, both satisfiable under the same KEL endorser). Both new
/// policies are immune so the IEL Evl immunity check passes.
///
/// Returns `(evl_a_said, evl_b_said, vec_of_new_policies)`. Tests that
/// run `verify_chain` post-divergence should pass the new policies via
/// `verify_chain_with_policies` so the test's `InMemoryPolicyResolver`
/// can resolve them during IEL re-verification.
async fn create_iel_divergence(
    setup: &mut Setup,
    label: &str,
) -> (Digest256, Digest256, Vec<Policy>) {
    use kels_core::IdentityEventKind;
    use verifiable_storage::Chained;

    let iel_chain: Vec<IdentityEvent> = setup
        .sad_client
        .fetch_identity_events(&setup.iel_prefix, None)
        .await
        .expect("fetch IEL")
        .events;
    assert_eq!(
        iel_chain.len(),
        1,
        "[{label}] expected single Icp before divergence"
    );
    let icp = iel_chain.into_iter().next().unwrap();

    // Build two policies that differ in their endorse-target. Both
    // must be IMMUNE (per IEL verifier rule on evolved policies); the
    // `Policy::build` rejects `Some(poison)` paired with
    // `immune=true` (mutually exclusive), so we differentiate via the
    // expression itself. The endorse target is a synthetic Digest256
    // unique to this test label — never used as a real KEL prefix, so
    // the policies are unsatisfiable in practice. That's fine: this
    // helper only needs the IEL Evls to LAND (governance check uses
    // the original tracked policy; immunity check passes since
    // `immune=true`). No SE chain we build here ever extends under
    // these synthetic policies.
    let fake_endorser_a = Digest256::blake3_256(format!("fake-endorser-a-{label}").as_bytes());
    let fake_endorser_b = Digest256::blake3_256(format!("fake-endorser-b-{label}").as_bytes());
    let policy_a =
        Policy::build(&format!("endorse({})", fake_endorser_a), None, true).expect("policy a");
    let policy_b =
        Policy::build(&format!("endorse({})", fake_endorser_b), None, true).expect("policy b");
    assert_ne!(
        policy_a.said, policy_b.said,
        "[{label}] policies must differ"
    );

    setup
        .sad_client
        .post_sad_object(&serde_json::to_value(&policy_a).unwrap())
        .await
        .expect("upload policy a");
    setup
        .sad_client
        .post_sad_object(&serde_json::to_value(&policy_b).unwrap())
        .await
        .expect("upload policy b");

    let mut evl_a = icp.clone();
    evl_a.kind = IdentityEventKind::Evl;
    evl_a.auth_policy = policy_a.said;
    evl_a.increment().unwrap();

    let mut evl_b = icp.clone();
    evl_b.kind = IdentityEventKind::Evl;
    evl_b.auth_policy = policy_b.said;
    evl_b.increment().unwrap();

    setup
        .kel_builder
        .interact_batch(&[evl_a.said, evl_b.said])
        .await
        .unwrap_or_else(|e| panic!("anchor IEL Evl divergent [{label}]: {e:?}"));

    // Submit BOTH Evls in one batch. `save_batch` sees pre-batch
    // seal=None so the second Evl triggers overlap-creates-fork. If
    // we submitted them in separate batches, after the first lands
    // pre-batch seal becomes 1 → the second hits the seal-check and
    // gets rejected with "Cannot fork at version 1 — sealed".
    let _ = setup
        .sad_client
        .submit_identity_events(&[evl_a.clone(), evl_b.clone()])
        .await
        .unwrap_or_else(|e| panic!("submit IEL Evl batch [{label}]: {e:?}"));

    (evl_a.said, evl_b.said, vec![policy_a, policy_b])
}

/// Verify a chain with extra policies registered in the
/// `InMemoryPolicyResolver`. Used by IelDivergent tests where
/// `create_iel_divergence` introduces new policies that the default
/// `setup.checker` doesn't know about.
async fn verify_chain_with_policies(
    sad_client: &SadStoreClient,
    harness: &SharedHarness,
    base_policy: Policy,
    extra: Vec<Policy>,
    prefix: &Digest256,
) -> kels_core::SelVerification {
    use kels_core::{AnchoredIelResolver, IelResolver, PagedIelSource};
    let mut all = vec![base_policy];
    all.extend(extra);
    let kel_source: Arc<dyn kels_core::PagedKelSource + Send + Sync> = Arc::new(
        kels_core::HttpKelSource::new(&harness.kels_url, "/api/v1/kels/kel/fetch")
            .expect("kel source"),
    );
    let resolver_inner: Arc<dyn PolicyResolver + Send + Sync> =
        Arc::new(InMemoryPolicyResolver::new(all));
    let checker: Arc<dyn PolicyChecker + Send + Sync> =
        Arc::new(AnchoredPolicyChecker::new(kel_source, resolver_inner));
    // SE pre-walk to collect identity_event SAIDs, mirroring the production
    // pattern in `SadEventBuilder::verify_server_chain_pre_action`.
    let queried = kels_core::collect_identity_event_saids(
        prefix,
        &sad_client.as_sad_source().expect("sad source"),
        kels_core::page_size(),
        kels_core::max_pages(),
    )
    .await
    .expect("SE pre-walk");
    let iel_source: Arc<dyn PagedIelSource + Send + Sync> =
        Arc::new(sad_client.as_iel_source().expect("iel source"));
    let iel_resolver: Arc<dyn IelResolver + Send + Sync> = Arc::new(
        AnchoredIelResolver::new(
            iel_source,
            Arc::clone(&checker),
            kels_core::page_size(),
            kels_core::max_pages(),
        )
        .with_queried_saids(queried),
    );
    sad_client
        .verify_sad_events(prefix, checker, iel_resolver)
        .await
        .expect("verify chain with policies")
}

/// Seal the SE chain with a `Sea` event. Mutates the chain on the
/// server; returns the seal event's SAID.
async fn seal_se_chain(setup: &mut Setup, v1_or_later: &SadEvent, label: &str) -> SadEvent {
    let sea = SadEvent::sea(v1_or_later, setup.iel_icp_said).expect("build Sea");
    setup
        .kel_builder
        .interact(&sea.said)
        .await
        .unwrap_or_else(|e| panic!("anchor Sea [{label}]: {e:?}"));
    let _ = setup
        .sad_client
        .submit_sad_events(std::slice::from_ref(&sea))
        .await
        .unwrap_or_else(|e| panic!("submit Sea [{label}]: {e:?}"));
    sea
}

/// Submit two competing Upd events at the next version to create
/// server-side divergence on the SE chain. Returns the two events.
async fn create_se_divergence(
    setup: &mut Setup,
    tip: &SadEvent,
    label: &str,
) -> (SadEvent, SadEvent) {
    let content_a = upload_content(&setup.sad_client, &format!("{label}-a")).await;
    let content_b = upload_content(&setup.sad_client, &format!("{label}-b")).await;
    let v_a = SadEvent::upd(tip, setup.iel_icp_said, content_a).unwrap();
    let v_b = SadEvent::upd(tip, setup.iel_icp_said, content_b).unwrap();
    setup
        .kel_builder
        .interact_batch(&[v_a.said, v_b.said])
        .await
        .unwrap();
    let _ = setup
        .sad_client
        .submit_sad_events(std::slice::from_ref(&v_a))
        .await
        .unwrap();
    let _ = setup
        .sad_client
        .submit_sad_events(std::slice::from_ref(&v_b))
        .await
        .unwrap();
    (v_a, v_b)
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
    assert!(outcome.diverged_at.is_none());

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
    let icp = SadEvent::icp(setup.iel_prefix, TEST_TOPIC).expect("build Icp");

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
/// "not anchored" fragment in the body. Pins the #147 design choice
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
    assert!(
        resp.applied,
        "Cnt must commit (terminal-event SOFT mapping)"
    );

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

    // And subsequent submits to the contested chain return 200 OK with
    // `terminal: Some(Contested)` (#147 follow-up —
    // gossip-race-already-terminal idempotency on owner-side too).
    let further_content = upload_content(&setup.sad_client, "post-cnt").await;
    let further_upd = SadEvent::upd(&cnt, setup.iel_icp_said, further_content).expect("build Upd");
    let resp = setup
        .sad_client
        .submit_sad_events(&[further_upd])
        .await
        .expect("contested chain returns 200 with terminal indicator");
    assert!(!resp.applied);
    assert_eq!(resp.terminal, Some(SadEventTerminalState::Contested));
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
    assert!(
        v.is_decommissioned(),
        "is_decommissioned must be set content-based"
    );
    assert!(!v.is_contested());
    assert!(!v.policy_satisfied());

    // Subsequent submits return 200 OK with `terminal: Some(Decommissioned)`.
    let further_content = upload_content(&setup.sad_client, "post-dec").await;
    let further_upd =
        SadEvent::upd(v.current_event(), setup.iel_icp_said, further_content).expect("build Upd");
    let resp = setup
        .sad_client
        .submit_sad_events(&[further_upd])
        .await
        .expect("decommissioned chain returns 200 with terminal indicator");
    assert!(!resp.applied);
    assert_eq!(resp.terminal, Some(SadEventTerminalState::Decommissioned));
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
    let _ = setup
        .sad_client
        .submit_sad_events(&[v2_a])
        .await
        .expect("v2_a");
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
    assert!(
        v.is_contested(),
        "is_contested must be true after Cnt lands"
    );
    assert!(
        v.policy_satisfied(),
        "anchored Cnt has governance auth — policy_satisfied stays true"
    );

    let further_content = upload_content(&setup.sad_client, "post-contest").await;
    let further_upd =
        SadEvent::upd(v.current_event(), setup.iel_icp_said, further_content).unwrap();
    let resp = setup
        .sad_client
        .submit_sad_events(&[further_upd])
        .await
        .expect("contested chain returns 200 with terminal indicator");
    assert!(!resp.applied);
    assert_eq!(resp.terminal, Some(SadEventTerminalState::Contested));
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

    let dec_said = builder.decommission().await.expect("stage Dec via builder");
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
    let further_upd =
        SadEvent::upd(v.current_event(), setup.iel_icp_said, further_content).unwrap();
    let resp = setup
        .sad_client
        .submit_sad_events(&[further_upd])
        .await
        .expect("decommissioned chain returns 200 with terminal indicator");
    assert!(!resp.applied);
    assert_eq!(resp.terminal, Some(SadEventTerminalState::Decommissioned));
}

/// `decommission()` fail-fast on divergent: surfaces a typed
/// `DecommissionBlockedByDivergence` (#147 deviations resolved in
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
    let owner_store: Arc<dyn kels_core::SadStore> = Arc::new(kels_core::InMemorySadStore::new());

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
        matches!(result, Err(KelsError::DecommissionBlockedByDivergence(_))),
        "decommission on divergent must error DecommissionBlockedByDivergence, got {:?}",
        result
    );
}

// ==================== Gap 10b: remaining taxonomy ====================
//
// The cases below complete the #147 plan's prescribed test list,
// minus the four gossip-propagation cases (which require a 2-SADStore
// harness — deferred to deployment-test sweep).

/// Pin the prefix-derivation contract: `compute_sad_event_prefix(identity, topic)`
/// returns the same digest the server's verifier checks against.
/// Pure-Rust unit test — no harness needed; lives in this file alongside
/// the full-stack tests because the contract is the foundation they
/// rest on.
#[test]
fn compute_sad_event_prefix_uses_identity_and_topic() {
    let id = Digest256::blake3_256(b"identity-A");
    let p1 = kels_core::compute_sad_event_prefix(id, "kels/sad/v1/topic-1").unwrap();
    let p2 = kels_core::compute_sad_event_prefix(id, "kels/sad/v1/topic-1").unwrap();
    assert_eq!(p1, p2, "deterministic on identical inputs");

    let id2 = Digest256::blake3_256(b"identity-B");
    let p_other_id = kels_core::compute_sad_event_prefix(id2, "kels/sad/v1/topic-1").unwrap();
    assert_ne!(p1, p_other_id, "different identity → different prefix");

    let p_other_topic = kels_core::compute_sad_event_prefix(id, "kels/sad/v1/topic-2").unwrap();
    assert_ne!(p1, p_other_topic, "different topic → different prefix");

    // Round-trip: build an Icp with the same inputs and verify its
    // prefix matches the standalone helper.
    let icp = SadEvent::icp(id, "kels/sad/v1/topic-1").unwrap();
    assert_eq!(icp.prefix, p1, "Icp prefix derivation matches helper");
}

/// `Upd` whose `identity_event` doesn't exist in the IEL → server
/// rejects with `BadIdentityBinding`-class error. The CESR digest of an
/// unrelated label can't be in any IEL's `policy_history`, so the
/// resolver returns `BadIdentityBinding` (not found).
#[tokio::test]
#[serial]
async fn update_rejects_when_identity_event_unknown_in_iel() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let mut setup = setup_kel_iel_policy(harness, "upd-unknown-iel-event").await;
    let v1 = establish_se_chain(&mut setup, "upd-unknown-iel-event").await;

    // Bind to a SAID that isn't any IEL event.
    let bogus_iel_event = Digest256::blake3_256(b"not-an-iel-event-for-this-identity");
    let content = upload_content(&setup.sad_client, "post-bogus").await;
    let upd = SadEvent::upd(&v1, bogus_iel_event, content).unwrap();
    setup.kel_builder.interact(&upd.said).await.unwrap();

    let result = setup.sad_client.submit_sad_events(&[upd]).await;
    assert_err_contains(
        result,
        "Bad identity binding",
        "unknown identity_event must surface BadIdentityBinding",
    );
}

/// `Upd` whose `identity_event` exists but lives in a DIFFERENT IEL
/// (prefix mismatch) → `BadIdentityBinding`. Defense-in-depth against
/// cross-IEL contamination.
#[tokio::test]
#[serial]
async fn update_rejects_when_identity_event_prefix_mismatches_branch_identity() {
    let Some(harness) = get_harness().await else {
        return;
    };
    // Setup #1: chain bound to IEL-A.
    let mut setup_a = setup_kel_iel_policy(harness, "upd-prefix-mismatch-A").await;
    let v1 = establish_se_chain(&mut setup_a, "upd-prefix-mismatch-A").await;

    // Setup #2: a separate IEL-B (same KEL would conflict; use a
    // different label so a fresh KEL is created). The `iel_icp_said`
    // returned belongs to IEL-B and is NOT in IEL-A's `policy_history`.
    let setup_b = setup_kel_iel_policy(harness, "upd-prefix-mismatch-B").await;

    // Bind setup_a's chain to setup_b's IEL Icp — prefix mismatch.
    let content = upload_content(&setup_a.sad_client, "cross-iel").await;
    let upd = SadEvent::upd(&v1, setup_b.iel_icp_said, content).unwrap();
    setup_a.kel_builder.interact(&upd.said).await.unwrap();

    let result = setup_a.sad_client.submit_sad_events(&[upd]).await;
    assert_err_contains(
        result,
        "Bad identity binding",
        "cross-IEL identity_event must surface BadIdentityBinding",
    );
}

/// `Upd` whose `identity_event` regresses the chain's monotonic ratchet
/// in IEL chain order → `BadIdentityBinding(monotonic)`. Sequence: bind
/// v1 to a later IEL Evl, then bind v2 to the earlier IEL Icp (regression).
#[tokio::test]
#[serial]
async fn update_rejects_when_identity_event_regresses_monotonic_ratchet() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let mut setup = setup_kel_iel_policy(harness, "monotonic-regression").await;

    // Evolve the IEL once to give us a later Evl event to bind v1 to.
    let iel_evl_said = evolve_iel(&mut setup, "monotonic-regression").await;

    // Build the SE chain manually so v1 binds to the LATER IEL event
    // (Evl), then attempt v2 binding to the EARLIER IEL Icp.
    let initial_content = upload_content(&setup.sad_client, "monotonic-init").await;
    let icp = SadEvent::icp(setup.iel_prefix, TEST_TOPIC).unwrap();
    let upd = SadEvent::upd(&icp, iel_evl_said, initial_content).unwrap();
    setup
        .kel_builder
        .interact_batch(&[icp.said, upd.said])
        .await
        .unwrap();
    let _ = setup
        .sad_client
        .submit_sad_events(&[icp.clone(), upd.clone()])
        .await
        .expect("incept ratcheted to IEL Evl");

    // v2 binds to the EARLIER IEL Icp → regression.
    let regress_content = upload_content(&setup.sad_client, "monotonic-regress").await;
    let v2 = SadEvent::upd(&upd, setup.iel_icp_said, regress_content).unwrap();
    setup.kel_builder.interact(&v2.said).await.unwrap();
    let result = setup.sad_client.submit_sad_events(&[v2]).await;
    assert_err_contains(
        result,
        "regresses prior ratchet",
        "ratchet regression must surface BadIdentityBinding(monotonic)",
    );
}

/// `Upd` binding to a divergent-IEL post-divergence event → HARD reject
/// with `IelDivergent`. The Upd is an advancement event; it cannot rest
/// on an unstable IEL state.
#[tokio::test]
#[serial]
async fn update_rejects_when_bound_iel_event_lives_on_divergent_iel_branch() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let mut setup = setup_kel_iel_policy(harness, "iel-divergent-upd").await;

    // 1. Establish a clean SE chain so we have a v1 tip.
    let v1 = establish_se_chain(&mut setup, "iel-divergent-upd-base").await;

    // 2. Create IEL divergence at v1 (two competing Evl events).
    let (evl_a, _evl_b, _new_policies) =
        create_iel_divergence(&mut setup, "iel-divergent-upd").await;

    // 3. Bind a new SE Upd to one of the post-divergence IEL events.
    //    HARD reject expected.
    let content = upload_content(&setup.sad_client, "post-iel-div").await;
    let upd = SadEvent::upd(&v1, evl_a, content).unwrap();
    setup.kel_builder.interact(&upd.said).await.unwrap();
    let result = setup.sad_client.submit_sad_events(&[upd]).await;
    assert_err_contains(
        result,
        "IEL is divergent",
        "Upd binding to post-divergence IEL event must HARD-fail",
    );
}

/// `Cnt` binding to a divergent-IEL post-divergence event → SOFT path
/// lands; chain becomes contested; `policy_satisfied=false`.
/// Symmetric to the anchor-fail soft case in Gap 10a.
#[tokio::test]
#[serial]
async fn submit_lands_iel_divergent_cnt_chain_becomes_contested_with_policy_unsatisfied() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let mut setup = setup_kel_iel_policy(harness, "iel-divergent-soft-cnt").await;
    let v1 = establish_se_chain(&mut setup, "iel-divergent-soft-cnt").await;
    let (evl_a, _evl_b, new_policies) =
        create_iel_divergence(&mut setup, "iel-divergent-soft-cnt").await;

    // Cnt bound to a post-divergence IEL event — SOFT.
    let cnt = SadEvent::cnt(&v1, evl_a).unwrap();
    setup.kel_builder.interact(&cnt.said).await.unwrap();
    let resp = setup
        .sad_client
        .submit_sad_events(std::slice::from_ref(&cnt))
        .await
        .expect("Cnt soft-passes IelDivergent for terminal kinds");
    assert!(resp.applied);

    let prefix = cnt.prefix;
    let v = verify_chain_with_policies(
        &setup.sad_client,
        harness,
        setup.policy.clone(),
        new_policies,
        &prefix,
    )
    .await;
    assert!(v.is_contested(), "is_contested set content-based");
    assert!(
        !v.policy_satisfied(),
        "IelDivergent soft path → policy_satisfied=false"
    );
}

/// `Dec` binding to a divergent-IEL post-divergence event → SOFT path
/// lands; chain becomes decommissioned; `policy_satisfied=false`.
#[tokio::test]
#[serial]
async fn submit_lands_iel_divergent_dec_chain_becomes_decommissioned_with_policy_unsatisfied() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let mut setup = setup_kel_iel_policy(harness, "iel-divergent-soft-dec").await;
    let v1 = establish_se_chain(&mut setup, "iel-divergent-soft-dec").await;
    let (evl_a, _evl_b, new_policies) =
        create_iel_divergence(&mut setup, "iel-divergent-soft-dec").await;

    let dec = SadEvent::dec(&v1, evl_a).unwrap();
    setup.kel_builder.interact(&dec.said).await.unwrap();
    let resp = setup
        .sad_client
        .submit_sad_events(std::slice::from_ref(&dec))
        .await
        .expect("Dec soft-passes IelDivergent for terminal kinds");
    assert!(resp.applied);

    let prefix = dec.prefix;
    let v = verify_chain_with_policies(
        &setup.sad_client,
        harness,
        setup.policy.clone(),
        new_policies,
        &prefix,
    )
    .await;
    assert!(v.is_decommissioned(), "is_decommissioned set content-based");
    assert!(!v.is_contested());
    assert!(!v.policy_satisfied());
}

/// Pre-divergence shared IEL events resolve cleanly even when the IEL
/// is divergent: an SE Upd binding to the IEL Icp (pre-divergence)
/// succeeds even after the IEL has diverged at v1.
#[tokio::test]
#[serial]
async fn pre_divergence_iel_event_resolves_even_when_iel_is_divergent() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let mut setup = setup_kel_iel_policy(harness, "iel-divergent-pre-shared").await;
    let v1 = establish_se_chain(&mut setup, "iel-divergent-pre-shared").await;
    let _ = create_iel_divergence(&mut setup, "iel-divergent-pre-shared").await;

    // Bind v2 to the IEL Icp — pre-divergence shared event. HARD pass.
    let content = upload_content(&setup.sad_client, "pre-div-content").await;
    let v2 = SadEvent::upd(&v1, setup.iel_icp_said, content).unwrap();
    setup.kel_builder.interact(&v2.said).await.unwrap();
    let resp = setup
        .sad_client
        .submit_sad_events(&[v2])
        .await
        .expect("pre-divergence IEL Icp resolves cleanly");
    assert!(resp.applied);
}

/// `Sea` advances `last_governance_version` and ratchets
/// `last_identity_event` forward.
#[tokio::test]
#[serial]
async fn seal_advances_last_governance_version_and_ratchets() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let mut setup = setup_kel_iel_policy(harness, "seal-advances").await;

    // Evolve the IEL so we have a later non-terminal IEL event to bind
    // the seal to (the builder picks the most recent IEL Icp/Evl).
    let iel_evl_said = evolve_iel(&mut setup, "seal-advances").await;

    let v1 = establish_se_chain(&mut setup, "seal-advances").await;

    // Build the seal directly so we control the binding (the builder's
    // `seal()` would also pick the latest IEL Evl; this manual path
    // makes the binding explicit in the test body).
    let sea = SadEvent::sea(&v1, iel_evl_said).unwrap();
    setup.kel_builder.interact(&sea.said).await.unwrap();
    let resp = setup
        .sad_client
        .submit_sad_events(std::slice::from_ref(&sea))
        .await
        .expect("Sea lands");
    assert!(resp.applied);

    let prefix = sea.prefix;
    let v = verify_chain(&setup.sad_client, &setup, &prefix).await;
    assert_eq!(
        v.last_governance_version(),
        Some(sea.version),
        "Sea must advance last_governance_version to the seal's version"
    );
    assert_eq!(
        v.last_identity_event(),
        Some(&iel_evl_said),
        "Sea must ratchet last_identity_event to the bound IEL Evl"
    );
    assert!(v.policy_satisfied());
}

/// Repair after divergence: chain has [Icp, Upd], two competing v2
/// events create divergence, owner Rpr at v2 with `previous = v1.said`
/// resolves it. Server's `truncate_and_replace` archives both v2 forks
/// and inserts the Rpr.
#[tokio::test]
#[serial]
async fn repair_resolves_divergence_archives_adversary_events() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let mut setup = setup_kel_iel_policy(harness, "repair-divergence").await;
    let v1 = establish_se_chain(&mut setup, "repair-divergence").await;

    // Create SE divergence.
    let (_v_a, _v_b) = create_se_divergence(&mut setup, &v1, "repair-divergence").await;

    // Build Rpr at v2 with previous = v1.said. Server's is_repair path
    // archives the two v2 forks and inserts the Rpr.
    let rpr = SadEvent::rpr(&v1, setup.iel_icp_said).unwrap();
    setup.kel_builder.interact(&rpr.said).await.unwrap();
    let resp = setup
        .sad_client
        .submit_sad_events(std::slice::from_ref(&rpr))
        .await
        .expect("Rpr lands");
    assert!(resp.applied);

    let prefix = rpr.prefix;
    let chain = fetch_chain(&setup.sad_client, &prefix).await;
    // Post-repair the chain is linear: [Icp, Upd, Rpr]; the two v2
    // forks were archived.
    assert_eq!(chain.len(), 3, "post-repair chain should be linear");
    assert_eq!(chain[2].kind, kels_core::SadEventKind::Rpr);
    assert_eq!(chain[2].said, rpr.said);
}

/// `Cnt` on a sealed-divergent chain: lands. Sealed-divergent means
/// `first_divergent_version <= last_governance_version` — `Rpr` cannot
/// truncate behind the seal, so `Cnt` is the only legitimate resolver.
///
/// **Single-node-untestable** (5-test family below): the sealed-divergent
/// state requires a fork at-or-behind the seal, but
/// `SadEventRepository::save_batch`'s seal check rejects exactly that
/// case ("Cannot fork at version X — sealed by evaluation at version Y").
/// In production the state arises transiently across federation when
/// node-A authors a Sea at the same version where node-B authored a
/// competing Upd before the two synced. Single-node tests can't
/// reproduce that race; a future Gap 10c could either (a) add a
/// test-only insert API that bypasses the seal-check, or (b) build a
/// 2-SADStore harness with gossip wiring. Until then the routing
/// branches are exercised at unit level (Gap 4 routing matrix in
/// `services/sadstore/src/handlers.rs::submit_sad_events`) and via
/// the Heisenbug deployment-test sweep.
#[tokio::test]
#[serial]
#[ignore = "single-node harness can't reach sealed-divergent state — see doc"]
async fn sealed_divergent_chain_accepts_cnt_terminates_with_contested() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let mut setup = setup_kel_iel_policy(harness, "sealed-div-accepts-cnt").await;
    let v1 = establish_se_chain(&mut setup, "sealed-div-accepts-cnt").await;

    // Seal first (advances last_governance_version to v2), THEN diverge
    // by submitting two competing v3 events — divergence at v3, seal at
    // v2 → sealed-divergent (seal >= div).
    let sea = seal_se_chain(&mut setup, &v1, "sealed-div-accepts-cnt").await;
    let (_v3a, _v3b) = create_se_divergence(&mut setup, &sea, "sealed-div-accepts-cnt").await;

    // Cnt extending the lower-SAID branch tip lands.
    let prefix = sea.prefix;
    let chain = fetch_chain(&setup.sad_client, &prefix).await;
    let post_seal_tip = chain.iter().min_by_key(|e| e.said).cloned().expect("tip");
    let cnt = SadEvent::cnt(&post_seal_tip, setup.iel_icp_said).unwrap();
    setup.kel_builder.interact(&cnt.said).await.unwrap();
    let resp = setup
        .sad_client
        .submit_sad_events(std::slice::from_ref(&cnt))
        .await
        .expect("Cnt accepts on sealed-divergent");
    assert!(resp.applied);

    let v = verify_chain(&setup.sad_client, &setup, &prefix).await;
    assert!(v.is_contested());
}

/// `Dec` on a sealed-divergent chain: rejected with `ContestRequired`.
/// Dec cannot resolve a sealed divergence; operator must Cnt instead.
///
/// See `sealed_divergent_chain_accepts_cnt_terminates_with_contested`
/// for why this 5-test family is `#[ignore]`'d in single-node testing.
#[tokio::test]
#[serial]
#[ignore = "single-node harness can't reach sealed-divergent state"]
async fn sealed_divergent_chain_rejects_dec_with_contest_required() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let mut setup = setup_kel_iel_policy(harness, "sealed-div-rejects-dec").await;
    let v1 = establish_se_chain(&mut setup, "sealed-div-rejects-dec").await;
    let sea = seal_se_chain(&mut setup, &v1, "sealed-div-rejects-dec").await;
    let (_v3a, _v3b) = create_se_divergence(&mut setup, &sea, "sealed-div-rejects-dec").await;

    let prefix = sea.prefix;
    let chain = fetch_chain(&setup.sad_client, &prefix).await;
    let tip = chain.iter().min_by_key(|e| e.said).cloned().expect("tip");
    let dec = SadEvent::dec(&tip, setup.iel_icp_said).unwrap();
    setup.kel_builder.interact(&dec.said).await.unwrap();
    let result = setup.sad_client.submit_sad_events(&[dec]).await;
    assert_err_contains(
        result,
        "Contest required",
        "Dec on sealed-divergent must route to Cnt",
    );
}

/// `Upd` on a sealed-divergent chain: rejected with `ContestRequired`.
/// Cannot Rpr behind the seal AND cannot extend a divergent chain → Cnt
/// is the only legitimate next move.
///
/// See `sealed_divergent_chain_accepts_cnt_terminates_with_contested`
/// for why this 5-test family is `#[ignore]`'d in single-node testing.
#[tokio::test]
#[serial]
#[ignore = "single-node harness can't reach sealed-divergent state"]
async fn sealed_divergent_chain_rejects_upd_with_contest_required() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let mut setup = setup_kel_iel_policy(harness, "sealed-div-rejects-upd").await;
    let v1 = establish_se_chain(&mut setup, "sealed-div-rejects-upd").await;
    let sea = seal_se_chain(&mut setup, &v1, "sealed-div-rejects-upd").await;
    let (_v3a, _v3b) = create_se_divergence(&mut setup, &sea, "sealed-div-rejects-upd").await;

    let prefix = sea.prefix;
    let chain = fetch_chain(&setup.sad_client, &prefix).await;
    let tip = chain.iter().min_by_key(|e| e.said).cloned().expect("tip");
    let content = upload_content(&setup.sad_client, "sealed-div-upd").await;
    let upd = SadEvent::upd(&tip, setup.iel_icp_said, content).unwrap();
    setup.kel_builder.interact(&upd.said).await.unwrap();
    let result = setup.sad_client.submit_sad_events(&[upd]).await;
    assert_err_contains(
        result,
        "Contest required",
        "Upd on sealed-divergent must route to Cnt",
    );
}

/// `Sea` on a sealed-divergent chain: rejected with `ContestRequired`.
///
/// See `sealed_divergent_chain_accepts_cnt_terminates_with_contested`
/// for why this 5-test family is `#[ignore]`'d in single-node testing.
#[tokio::test]
#[serial]
#[ignore = "single-node harness can't reach sealed-divergent state"]
async fn sealed_divergent_chain_rejects_sea_with_contest_required() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let mut setup = setup_kel_iel_policy(harness, "sealed-div-rejects-sea").await;
    let v1 = establish_se_chain(&mut setup, "sealed-div-rejects-sea").await;
    let sea = seal_se_chain(&mut setup, &v1, "sealed-div-rejects-sea").await;
    let (_v3a, _v3b) = create_se_divergence(&mut setup, &sea, "sealed-div-rejects-sea").await;

    let prefix = sea.prefix;
    let chain = fetch_chain(&setup.sad_client, &prefix).await;
    let tip = chain.iter().min_by_key(|e| e.said).cloned().expect("tip");
    let sea2 = SadEvent::sea(&tip, setup.iel_icp_said).unwrap();
    setup.kel_builder.interact(&sea2.said).await.unwrap();
    let result = setup.sad_client.submit_sad_events(&[sea2]).await;
    assert_err_contains(
        result,
        "Contest required",
        "Sea on sealed-divergent must route to Cnt",
    );
}

/// `Rpr` on a sealed-divergent chain: rejected with `ContestRequired`.
/// The sealed-divergent state foreclosed Rpr's resolution path.
///
/// See `sealed_divergent_chain_accepts_cnt_terminates_with_contested`
/// for why this 5-test family is `#[ignore]`'d in single-node testing.
#[tokio::test]
#[serial]
#[ignore = "single-node harness can't reach sealed-divergent state"]
async fn sealed_divergent_chain_rejects_rpr_with_contest_required() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let mut setup = setup_kel_iel_policy(harness, "sealed-div-rejects-rpr").await;
    let v1 = establish_se_chain(&mut setup, "sealed-div-rejects-rpr").await;
    let sea = seal_se_chain(&mut setup, &v1, "sealed-div-rejects-rpr").await;
    let (_v3a, _v3b) = create_se_divergence(&mut setup, &sea, "sealed-div-rejects-rpr").await;

    // Build Rpr at v3 (or whatever version below the seal) — should
    // reject with ContestRequired since seal is past it.
    let rpr = SadEvent::rpr(&sea, setup.iel_icp_said).unwrap();
    setup.kel_builder.interact(&rpr.said).await.unwrap();
    let result = setup.sad_client.submit_sad_events(&[rpr]).await;
    assert_err_contains(
        result,
        "Contest required",
        "Rpr on sealed-divergent must route to Cnt",
    );
}

/// Algorithmic ContestRequired: linear-sealed chain, Upd authored at
/// `version <= last_governance_version` (= the seal). The verifier
/// passes the auth check (Upd is anchored), but the routing matrix's
/// step-5 algorithmic trigger fires → 403 with "Contest required".
///
/// Setup: extend the chain past the seal so we have something to land,
/// but also re-author at-or-below the seal. Easiest construction:
/// build the chain to v3 (Icp, Upd, Sea, Upd) cleanly, then submit a
/// SECOND Upd at v3 — same version as the latest event, would create a
/// fork at v3 EXCEPT the matrix routes pre-batch divergence through
/// algorithmic trigger before save_batch sees it.
///
/// Pre-batch: chain is linear with seal at v2 (Sea). Authoring an Upd
/// at v2 (= seal version) triggers the algorithmic check.
#[tokio::test]
#[serial]
async fn contest_after_seal_via_algorithmic_trigger() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let mut setup = setup_kel_iel_policy(harness, "algorithmic-contest").await;
    let v1 = establish_se_chain(&mut setup, "algorithmic-contest").await;

    // Seal at v2.
    let sea = seal_se_chain(&mut setup, &v1, "algorithmic-contest").await;
    assert_eq!(sea.version, 2);

    // Author an Upd extending v1 → version = 2, same as sea. The chain
    // is linear (sea is the only event at v2), so the algorithmic
    // step-5 trigger fires (kind-relevant auth_policy passes — Upd is
    // anchored — but version <= seal).
    let content = upload_content(&setup.sad_client, "algorithmic-contest").await;
    let upd_at_seal = SadEvent::upd(&v1, setup.iel_icp_said, content).unwrap();
    setup.kel_builder.interact(&upd_at_seal.said).await.unwrap();
    let result = setup.sad_client.submit_sad_events(&[upd_at_seal]).await;
    assert_err_contains(
        result,
        "Contest required",
        "Upd at version <= seal on linear chain must algorithmically ContestRequired",
    );
}

/// `Dec` on a chain whose seal has advanced past the submitter's tip
/// lands cleanly — `Dec` is terminal so the algorithmic-`ContestRequired`
/// trigger excludes it (Gap 4 routing step 6.5 gates non-terminal AND
/// non-Rpr only).
#[tokio::test]
#[serial]
async fn active_sealed_chain_accepts_dec_terminates_decommissioned() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let mut setup = setup_kel_iel_policy(harness, "active-sealed-dec").await;
    let v1 = establish_se_chain(&mut setup, "active-sealed-dec").await;

    // Seal advances past v1 (sea is at v2).
    let sea = seal_se_chain(&mut setup, &v1, "active-sealed-dec").await;

    // Author a Dec at v3 extending the seal (linear, post-seal).
    let dec = SadEvent::dec(&sea, setup.iel_icp_said).unwrap();
    setup.kel_builder.interact(&dec.said).await.unwrap();
    let resp = setup
        .sad_client
        .submit_sad_events(std::slice::from_ref(&dec))
        .await
        .expect("Dec lands on linear sealed chain");
    assert!(resp.applied);

    let prefix = dec.prefix;
    let v = verify_chain(&setup.sad_client, &setup, &prefix).await;
    assert!(v.is_decommissioned());
    assert!(
        v.policy_satisfied(),
        "anchored Dec post-seal stays policy-satisfied"
    );
}

/// Upd binds to a later IEL Evl after the IEL evolved post-Icp →
/// chain advances; ratchet visible on the verification token.
#[tokio::test]
#[serial]
async fn update_appends_with_identity_event_binding_to_later_iel_evl() {
    let Some(harness) = get_harness().await else {
        return;
    };
    let mut setup = setup_kel_iel_policy(harness, "upd-binds-later-evl").await;

    // Establish the SE chain (binds to IEL Icp).
    let v1 = establish_se_chain(&mut setup, "upd-binds-later-evl").await;

    // Evolve the IEL.
    let evl_said = evolve_iel(&mut setup, "upd-binds-later-evl").await;

    // Author a v2 Upd binding to the new IEL Evl.
    let content = upload_content(&setup.sad_client, "post-evl").await;
    let upd = SadEvent::upd(&v1, evl_said, content).unwrap();
    setup.kel_builder.interact(&upd.said).await.unwrap();
    let resp = setup
        .sad_client
        .submit_sad_events(std::slice::from_ref(&upd))
        .await
        .expect("Upd binds to later IEL Evl cleanly");
    assert!(resp.applied);

    let prefix = upd.prefix;
    let v = verify_chain(&setup.sad_client, &setup, &prefix).await;
    assert_eq!(
        v.last_identity_event(),
        Some(&evl_said),
        "branch ratchet must advance to the IEL Evl"
    );
    assert!(v.policy_satisfied());
}

// ==================== RepositoryIelResolver walk-back ====================
//
// #147 follow-up: pin `RepositoryIelResolver`'s
// `iel_chain_positions` walk-back against the real IEL repository.
// The walk-back algorithm is unit-tested against a fake source at
// `lib/kels/src/iel_resolver.rs` (covers V=D base case + V=D+1
// non-trivial walk + pre-divergence-no-marker). The integration tests
// below exercise both V=D and V=D+1 cases through the postgres-backed
// repo — confirming the in-process pool walk + materialize-then-walk
// flow matches the unit-level algorithm.
#[tokio::test]
#[serial]
async fn repository_walk_back_different_branches_compares_iel_divergent() {
    use kels_core::IelResolver;
    use kels_sadstore::SadStoreRepository;
    use kels_sadstore::iel_resolver::RepositoryIelResolver;
    use verifiable_storage::RepositoryConnection;

    let Some(harness) = get_harness().await else {
        return;
    };
    let mut setup = setup_kel_iel_policy(harness, "walk-back-diff").await;
    let _v1 = establish_se_chain(&mut setup, "walk-back-diff").await;
    let (evl_a, evl_b, _) = create_iel_divergence(&mut setup, "walk-back-diff").await;

    let repo = SadStoreRepository::connect(&harness.sad_db_url)
        .await
        .expect("connect sadstore repo");
    let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::clone(&setup.checker);
    let resolver = RepositoryIelResolver::new(Arc::new(repo), checker);

    let positions = resolver
        .iel_chain_positions(&setup.iel_prefix, &[evl_a, evl_b])
        .await
        .expect("positions resolve");

    let p_a = positions.get(&evl_a).expect("a position");
    let p_b = positions.get(&evl_b).expect("b position");

    // Each event sits at v=D; its own SAID is its branch identity.
    assert_eq!(p_a.branch_marker, Some(evl_a));
    assert_eq!(p_b.branch_marker, Some(evl_b));

    // Different branches → IelDivergent (no canonical ordering across forks).
    assert!(matches!(p_a.try_cmp(p_b), Err(KelsError::IelDivergent(_))));
    assert!(matches!(p_b.try_cmp(p_a), Err(KelsError::IelDivergent(_))));
}

/// V=D+1 walk-back through the postgres-backed repo: a `Cnt` extending
/// one of the divergent v=1 Evls lands at v=2 (Cnt is the only kind IEL
/// routing accepts on a divergent chain). The Cnt's `branch_marker`
/// should trace back to the v=1 Evl on the same branch — exercising the
/// shared `walk_back_to_branch_identity` algorithm against a real chain
/// where the walk takes one non-trivial step.
#[tokio::test]
#[serial]
async fn repository_walk_back_v_d_plus_one_traces_to_v_d_ancestor() {
    use kels_core::{IdentityEvent, IelResolver};
    use kels_sadstore::SadStoreRepository;
    use kels_sadstore::iel_resolver::RepositoryIelResolver;
    use verifiable_storage::RepositoryConnection;

    let Some(harness) = get_harness().await else {
        return;
    };
    let mut setup = setup_kel_iel_policy(harness, "walk-back-vd1").await;
    let _v1 = establish_se_chain(&mut setup, "walk-back-vd1").await;
    let (evl_a, evl_b, _) = create_iel_divergence(&mut setup, "walk-back-vd1").await;

    // Fetch evl_a's full event so we can build a Cnt extending it.
    let iel_chain: Vec<IdentityEvent> = setup
        .sad_client
        .fetch_identity_events(&setup.iel_prefix, None)
        .await
        .expect("fetch IEL")
        .events;
    let evl_a_event = iel_chain
        .iter()
        .find(|e| e.said == evl_a)
        .cloned()
        .expect("evl_a in IEL");

    // Cnt extending evl_a at v=2 — post-divergence on the evl_a branch.
    // IEL routing accepts Cnt on divergent (contest path).
    let cnt = IdentityEvent::cnt(&evl_a_event).expect("build Cnt");
    setup
        .kel_builder
        .interact(&cnt.said)
        .await
        .expect("anchor Cnt");
    let _ = setup
        .sad_client
        .submit_identity_events(std::slice::from_ref(&cnt))
        .await
        .expect("submit Cnt");

    let repo = SadStoreRepository::connect(&harness.sad_db_url)
        .await
        .expect("connect sadstore repo");
    let checker: Arc<dyn PolicyChecker + Send + Sync> = Arc::clone(&setup.checker);
    let resolver = RepositoryIelResolver::new(Arc::new(repo), checker);

    let positions = resolver
        .iel_chain_positions(&setup.iel_prefix, &[evl_a, cnt.said])
        .await
        .expect("positions resolve");

    let p_evl_a = positions.get(&evl_a).expect("evl_a position");
    let p_cnt = positions.get(&cnt.said).expect("cnt position");

    // evl_a sits at v=D=1: its own SAID is its branch identity.
    assert_eq!(p_evl_a.branch_marker, Some(evl_a));
    // Cnt at v=D+1=2 walks back through `previous=evl_a` — branch
    // identity is evl_a (the v=D ancestor on this branch).
    assert_eq!(p_cnt.branch_marker, Some(evl_a));

    // Same branch → canonical chain order, not IelDivergent.
    use std::cmp::Ordering;
    assert_eq!(p_evl_a.try_cmp(p_cnt).unwrap(), Ordering::Less);
    assert_eq!(p_cnt.try_cmp(p_evl_a).unwrap(), Ordering::Greater);

    // Sanity: evl_b (other v=D branch) compares as IelDivergent vs both.
    let positions_b = resolver
        .iel_chain_positions(&setup.iel_prefix, &[evl_b, cnt.said])
        .await
        .expect("positions resolve");
    let p_evl_b = positions_b.get(&evl_b).expect("evl_b position");
    let p_cnt_b = positions_b.get(&cnt.said).expect("cnt position via b");
    assert!(matches!(
        p_evl_b.try_cmp(p_cnt_b),
        Err(KelsError::IelDivergent(_))
    ));
}

/// Server-internal-integrity-failure → 500 contract: when the receiver's
/// already-stored chain fails re-verification (DB tampering or
/// integrity loss), `verify_existing_chain` surfaces the failure as
/// `KelsError::ChainVerificationFailed` and the handler returns 500.
/// The client maps the 500 → `ServerError(_, ErrorCode::InternalError)`
/// with the variant's Display prefix preserved in the body so callers
/// can distinguish server-internal failures from routine 409 conflicts.
///
/// Tampering shape: directly UPDATE a stored row's `version` column
/// without recomputing its `said`. On re-verification the deserialized
/// event's `said` no longer matches the Blake3 of its (modified)
/// content, so `verify_said` fails inside `verifier.verify_page`.
#[tokio::test]
#[serial]
async fn submit_returns_500_when_existing_se_chain_fails_reverification() {
    use kels_sadstore::SadStoreRepository;
    use verifiable_storage::RepositoryConnection;

    let Some(harness) = get_harness().await else {
        return;
    };
    let mut setup = setup_kel_iel_policy(harness, "se-integrity-500").await;
    let content = upload_content(&setup.sad_client, "se-integrity-500").await;

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
    let prefix = *builder.prefix().expect("prefix");

    // Tamper: change v0's version to a bogus value. The said column stays
    // intact, so the (deserialized) event's recomputed Blake3 won't match
    // its said field on next re-verification.
    let repo = SadStoreRepository::connect(&harness.sad_db_url)
        .await
        .expect("connect sadstore repo");
    let rows_affected =
        sqlx::query("UPDATE sad_events SET version = 999 WHERE prefix = $1 AND version = 0")
            .bind(prefix.to_string())
            .execute(repo.sad_events.pool.inner())
            .await
            .expect("tamper sad_events row")
            .rows_affected();
    assert_eq!(rows_affected, 1, "tampering must hit exactly one row");

    // Now submit a fresh event. The handler's `verify_existing_chain` runs
    // the verifier over the on-disk chain (now including the tampered v0),
    // which surfaces a 500 with `ChainVerificationFailed` body prefix.
    let further_content = upload_content(&setup.sad_client, "post-tamper").await;
    let v1 = builder.last_event().cloned().expect("v1 tip");
    let v2 = SadEvent::upd(&v1, setup.iel_icp_said, further_content).expect("build Upd");
    let result = setup.sad_client.submit_sad_events(&[v2]).await;
    match result {
        Err(KelsError::ServerError(body, kels_core::ErrorCode::InternalError)) => {
            assert!(
                body.starts_with("Chain verification failed:"),
                "server-internal integrity failure must use the typed variant prefix; got: {body}"
            );
        }
        other => panic!(
            "expected ServerError(_, InternalError) with chain-verification body, got {other:?}"
        ),
    }
}

/// Audit: `RepositoryIelResolver::resolve_auth_policy_at`
/// (and the symmetric `resolve_governance_policy_at`) must consult the
/// verifier-adopted policy view via `IelVerification::auth_policy_at`,
/// not the raw `event.auth_policy` payload field. DB tampering of the
/// `auth_policy` column on a stored Icp row without recomputing its SAID
/// must surface as a verification failure (Blake3 mismatch in
/// `verify_said` during the resolver's `verification_for` walk), not a
/// silent leak of the tampered value to the SE verifier.
///
/// Per AGENTS.md §Verification Invariant ("the DB cannot be trusted"),
/// resolvers must re-verify on lookup; this test pins that contract on
/// the in-process `RepositoryIelResolver` consumed by the SE submit
/// handler.
#[tokio::test]
#[serial]
async fn repository_iel_resolver_resolve_at_detects_tampered_auth_policy() {
    use kels_core::IelResolver;
    use kels_sadstore::SadStoreRepository;
    use kels_sadstore::iel_resolver::RepositoryIelResolver;
    use verifiable_storage::RepositoryConnection;

    let Some(harness) = get_harness().await else {
        return;
    };
    let setup = setup_kel_iel_policy(harness, "iel-resolver-tamper").await;
    let identity = setup.iel_prefix;
    let icp_said = setup.iel_icp_said;

    let repo = Arc::new(
        SadStoreRepository::connect(&harness.sad_db_url)
            .await
            .expect("connect sadstore repo"),
    );
    let resolver = RepositoryIelResolver::new(Arc::clone(&repo), Arc::clone(&setup.checker));

    // Sanity: clean chain → resolver returns the verifier-adopted auth_policy.
    let pre_tamper_auth = resolver
        .resolve_auth_policy_at(&identity, &icp_said)
        .await
        .expect("clean chain resolves auth_policy");
    assert_eq!(
        pre_tamper_auth, setup.policy.said,
        "verifier-adopted auth_policy must equal the policy declared at Icp"
    );

    // Tamper: rewrite the auth_policy column on the Icp row to a different
    // (still-syntactically-valid) Digest256 without updating the SAID.
    // The deserialized event now has a tampered auth_policy field; on
    // verifier re-walk, `verify_said()` blake3-hashes the (modified)
    // content with the said field blanked and compares to the said
    // column — those no longer match.
    let bogus_auth = cesr::Digest256::blake3_256(b"bogus-tampered-auth-policy");
    let rows =
        sqlx::query("UPDATE iel_events SET auth_policy = $1 WHERE prefix = $2 AND said = $3")
            .bind(bogus_auth.to_string())
            .bind(identity.to_string())
            .bind(icp_said.to_string())
            .execute(repo.iel_events.pool.inner())
            .await
            .expect("tamper iel_events row")
            .rows_affected();
    assert_eq!(rows, 1, "tampering must hit exactly one row");

    // After tampering, the resolver must NOT silently return the bogus
    // value — `verification_for` runs the verifier, `verify_said` fails
    // on the tampered Icp, and the error propagates out.
    let result = resolver.resolve_auth_policy_at(&identity, &icp_said).await;
    assert!(
        result.is_err(),
        "tampered auth_policy must fail to resolve (re-verification catches it); got {result:?}",
    );

    // Symmetric pin for governance_policy resolution: the same tampered
    // chain fails on this path too because the chain re-walk happens in
    // `verification_for`, shared by both accessors.
    let result_gov = resolver
        .resolve_governance_policy_at(&identity, &icp_said)
        .await;
    assert!(
        result_gov.is_err(),
        "tampered chain must also fail governance_policy resolution; got {result_gov:?}",
    );
}

// ==================== Suppress unused-import warnings ====================
//
// The 4 gossip-propagation cases (full-chain to empty sink, Cnt to
// divergent sink, Cnt/Dec to active sink) need a 2-SADStore harness
// that's outside this file's scope; per the #147 plan they're
// covered by the Heisenbug-carry-forward deployment-test sweep
// (`clients/test/scripts/test-sadstore.sh` × 50+ runs after Gap 11).
// `IdentityEvent` / `IelVerification` / `fetch_effective` are kept in
// scope via this dead helper so a future in-process gossip test can
// use them without re-importing.
#[allow(dead_code)]
fn _gossip_cases_deferred_to_deployment_test()
-> (Option<IdentityEvent>, Option<IelVerification>, fn()) {
    (None, None, || {})
}

#[allow(dead_code)]
async fn _deferred_helper_keeps_fetch_effective_in_scope(
    sad_client: &SadStoreClient,
    prefix: &Digest256,
) {
    let _ = fetch_effective(sad_client, prefix).await;
}
