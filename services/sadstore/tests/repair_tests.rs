//! Repository-level tests for SAD chain repair: truncate_and_replace,
//! get_repairs, get_repair_records, and save_batch_with_verified_signatures.
//!
//! Uses a shared Postgres testcontainer (no MinIO or KELS service needed).
//! Each test connects independently to avoid cross-runtime pool issues.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{collections::HashMap, sync::OnceLock, time::Duration};
use tokio::{sync::OnceCell, time::sleep};

use cesr::{Matter, SigningKey, VerificationKey, generate_secp256r1};
use ctor::dtor;
use kels_core::{SadPointer, SadPointerSignature};
use serial_test::serial;
use testcontainers::{ContainerAsync, Image, core::ImageExt, runners::AsyncRunner};
use testcontainers_modules::postgres::Postgres;
use verifiable_storage::{Chained, SelfAddressed};
use verifiable_storage_postgres::RepositoryConnection;

use kels_sadstore::SadStoreRepository;

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

/// Shared container — keeps Postgres alive across tests. The database URL
/// is extracted once; each test creates its own connection pool from it.
struct SharedContainer {
    database_url: String,
    _postgres: ContainerAsync<Postgres>,
}

static SHARED_CONTAINER: OnceLock<OnceCell<Option<SharedContainer>>> = OnceLock::new();

async fn get_database_url() -> Option<&'static str> {
    let cell = SHARED_CONTAINER.get_or_init(OnceCell::new);
    let container = cell
        .get_or_init(|| async {
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

            // Run migrations once
            let repo = SadStoreRepository::connect(&database_url)
                .await
                .expect("failed to connect to database");
            repo.initialize().await.expect("failed to run migrations");
            drop(repo);

            Some(SharedContainer {
                database_url,
                _postgres: postgres,
            })
        })
        .await;
    container.as_ref().map(|c| c.database_url.as_str())
}

/// Connect a fresh repository for this test's tokio runtime.
async fn connect_repo() -> Option<SadStoreRepository> {
    let url = get_database_url().await?;
    Some(
        SadStoreRepository::connect(url)
            .await
            .expect("failed to connect to database"),
    )
}

// ==================== Helpers ====================

fn test_keys() -> (VerificationKey, SigningKey) {
    generate_secp256r1().unwrap()
}

fn keys_map(vk: &VerificationKey) -> HashMap<u64, VerificationKey> {
    HashMap::from([(0, vk.clone())])
}

fn sign_pointer(
    pointer: &SadPointer,
    sk: &SigningKey,
    establishment_serial: u64,
) -> SadPointerSignature {
    let sig = sk.sign(pointer.said.qb64().as_bytes()).unwrap();
    SadPointerSignature::create(pointer.said, sig, establishment_serial).unwrap()
}

/// Build a chain of v0..v(count-1) with valid signatures.
fn build_chain(
    kel_prefix: &str,
    kind: &str,
    count: usize,
    sk: &SigningKey,
) -> Vec<(SadPointer, SadPointerSignature)> {
    let mut pairs = Vec::with_capacity(count);
    let kel_digest = cesr::Digest::blake3_256(kel_prefix.as_bytes());
    let mut pointer = SadPointer::create(kel_digest, kind.to_string(), None).unwrap();
    pairs.push((pointer.clone(), sign_pointer(&pointer, sk, 0)));

    for i in 1..count {
        pointer.content_said = Some(cesr::Digest::blake3_256(
            format!("content_{}", i).as_bytes(),
        ));
        pointer.increment().unwrap();
        pairs.push((pointer.clone(), sign_pointer(&pointer, sk, 0)));
    }

    pairs
}

/// Build a replacement chain starting at `from_version`, linking to `previous_said`.
/// `content_tag` differentiates replacement chains so they produce unique SAIDs.
#[allow(clippy::too_many_arguments)]
fn build_replacement(
    previous_said: &cesr::Digest,
    prefix: &cesr::Digest,
    kel_prefix: &str,
    kind: &str,
    from_version: u64,
    count: usize,
    content_tag: &str,
    sk: &SigningKey,
) -> Vec<(SadPointer, SadPointerSignature)> {
    let mut pairs = Vec::with_capacity(count);

    let kel_digest = cesr::Digest::blake3_256(kel_prefix.as_bytes());
    let mut pointer = SadPointer {
        said: cesr::Digest::default(),
        prefix: *prefix,
        previous: Some(*previous_said),
        version: from_version,
        kel_prefix: kel_digest,
        kind: kind.to_string(),
        content_said: Some(cesr::Digest::blake3_256(
            format!("K{}_{}", content_tag, from_version).as_bytes(),
        )),
    };
    pointer.derive_said().unwrap();
    pairs.push((pointer.clone(), sign_pointer(&pointer, sk, 0)));

    for i in 1..count {
        pointer.content_said = Some(cesr::Digest::blake3_256(
            format!("K{}_{}", content_tag, from_version + i as u64).as_bytes(),
        ));
        pointer.increment().unwrap();
        pairs.push((pointer.clone(), sign_pointer(&pointer, sk, 0)));
    }

    pairs
}

// ==================== Tests ====================

#[tokio::test]
#[serial]
async fn test_get_repairs_empty() {
    let Some(repo) = connect_repo().await else {
        return;
    };

    let (repairs, has_more) = repo
        .sad_records
        .get_repairs("Knonexistent_prefix_________________________", 10, 0)
        .await
        .unwrap();

    assert!(repairs.is_empty());
    assert!(!has_more);
}

#[tokio::test]
#[serial]
async fn test_save_batch_and_truncate_and_replace() {
    let Some(repo) = connect_repo().await else {
        return;
    };

    let (vk, sk) = test_keys();
    let keys = keys_map(&vk);
    let kel_prefix = "Erepair_test_kel_1______________________________";
    let kind = "kels/v1/test-repair";

    // Save a 5-record chain: v0..v4
    let chain = build_chain(kel_prefix, kind, 5, &sk);
    let count = repo
        .sad_records
        .save_batch_with_verified_signatures(&chain, &keys)
        .await
        .unwrap();
    assert_eq!(count, 5);

    let prefix = chain[0].0.prefix;

    // Verify effective SAID is v4's SAID (non-divergent tip)
    let (effective, divergent) = repo
        .sad_records
        .effective_said(prefix.as_ref())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(effective, chain[4].0.said.to_string());
    assert!(!divergent);

    // Build replacement from v3 (replacing v3 and v4 with 2 new records)
    let previous_said = &chain[2].0.said; // v2 is the last kept record
    let replacement = build_replacement(
        previous_said,
        &prefix,
        kel_prefix,
        kind,
        3,
        2,
        "replacement",
        &sk,
    );

    repo.sad_records
        .truncate_and_replace(&replacement, &keys)
        .await
        .unwrap();

    // Verify effective SAID is now the new v4's SAID
    let (effective, divergent) = repo
        .sad_records
        .effective_said(prefix.as_ref())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(effective, replacement[1].0.said.to_string());
    assert!(!divergent);

    // Verify chain length is 5 (v0-v2 kept + v3-v4 replaced)
    let stored = repo
        .sad_records
        .get_stored(prefix.as_ref(), None, None)
        .await
        .unwrap();
    assert_eq!(stored.len(), 5);
    // First 3 unchanged, last 2 are replacements
    assert_eq!(stored[0].pointer.said, chain[0].0.said);
    assert_eq!(stored[2].pointer.said, chain[2].0.said);
    assert_eq!(stored[3].pointer.said, replacement[0].0.said);
    assert_eq!(stored[4].pointer.said, replacement[1].0.said);

    // Verify repair audit record was created
    let (repairs, has_more) = repo
        .sad_records
        .get_repairs(prefix.as_ref(), 10, 0)
        .await
        .unwrap();
    assert_eq!(repairs.len(), 1);
    assert!(!has_more);
    assert_eq!(repairs[0].pointer_prefix, prefix);
    assert_eq!(repairs[0].diverged_at_version, 3);

    // Verify archived records are accessible
    let (archived, has_more) = repo
        .sad_records
        .get_repair_records(repairs[0].said.as_ref(), 10, 0)
        .await
        .unwrap();
    assert_eq!(archived.len(), 2); // v3 and v4 were archived
    assert!(!has_more);
    // Archived records should be the original v3 and v4
    let archived_saids: Vec<&str> = archived.iter().map(|r| r.pointer.said.as_ref()).collect();
    assert!(archived_saids.contains(&chain[3].0.said.as_ref()));
    assert!(archived_saids.contains(&chain[4].0.said.as_ref()));
}

#[tokio::test]
#[serial]
async fn test_truncate_and_replace_empty_batch_fails() {
    let Some(repo) = connect_repo().await else {
        return;
    };

    let (vk, _) = test_keys();
    let keys = keys_map(&vk);
    let empty: Vec<(SadPointer, SadPointerSignature)> = Vec::new();

    let result = repo.sad_records.truncate_and_replace(&empty, &keys).await;
    assert!(result.is_err());
}

#[tokio::test]
#[serial]
async fn test_truncate_and_replace_bad_signature_rolls_back() {
    let Some(repo) = connect_repo().await else {
        return;
    };

    let (vk, sk) = test_keys();
    let (_, wrong_sk) = test_keys(); // different key for bad signature
    let keys = keys_map(&vk);
    let kel_prefix = "Erepair_bad_sig_kel_____________________________";
    let kind = "kels/v1/test-badsig";

    // Save a 3-record chain
    let chain = build_chain(kel_prefix, kind, 3, &sk);
    repo.sad_records
        .save_batch_with_verified_signatures(&chain, &keys)
        .await
        .unwrap();

    let prefix = chain[0].0.prefix;

    // Build replacement signed with the wrong key
    let replacement = build_replacement(
        &chain[1].0.said,
        &prefix,
        kel_prefix,
        kind,
        2,
        1,
        "bad_sig",
        &wrong_sk,
    );

    // Should fail — signature won't verify
    let result = repo
        .sad_records
        .truncate_and_replace(&replacement, &keys)
        .await;
    assert!(result.is_err());

    // Original chain should be intact (transaction rolled back)
    let stored = repo
        .sad_records
        .get_stored(prefix.as_ref(), None, None)
        .await
        .unwrap();
    assert_eq!(stored.len(), 3);
    assert_eq!(stored[2].pointer.said, chain[2].0.said);

    // No repair record should exist
    let (repairs, _) = repo
        .sad_records
        .get_repairs(prefix.as_ref(), 10, 0)
        .await
        .unwrap();
    assert!(repairs.is_empty());
}

#[tokio::test]
#[serial]
async fn test_get_repairs_pagination() {
    let Some(repo) = connect_repo().await else {
        return;
    };

    let (vk, sk) = test_keys();
    let keys = keys_map(&vk);
    let kel_prefix = "Erepair_pagination_kel__________________________";
    let kind = "kels/v1/test-paginate";

    // Save a 5-record chain
    let chain = build_chain(kel_prefix, kind, 5, &sk);
    repo.sad_records
        .save_batch_with_verified_signatures(&chain, &keys)
        .await
        .unwrap();

    let prefix = chain[0].0.prefix;

    // First repair: replace from v4
    let r1 = build_replacement(
        &chain[3].0.said,
        &prefix,
        kel_prefix,
        kind,
        4,
        1,
        "repair_a",
        &sk,
    );
    repo.sad_records
        .truncate_and_replace(&r1, &keys)
        .await
        .unwrap();

    // Second repair: replace from v4 again (replacing the first replacement)
    let r2 = build_replacement(
        &chain[3].0.said,
        &prefix,
        kel_prefix,
        kind,
        4,
        1,
        "repair_b",
        &sk,
    );
    repo.sad_records
        .truncate_and_replace(&r2, &keys)
        .await
        .unwrap();

    // Paginate with limit=1
    let (page1, has_more1) = repo
        .sad_records
        .get_repairs(prefix.as_ref(), 1, 0)
        .await
        .unwrap();
    assert_eq!(page1.len(), 1);
    assert!(has_more1);

    let (page2, has_more2) = repo
        .sad_records
        .get_repairs(prefix.as_ref(), 1, 1)
        .await
        .unwrap();
    assert_eq!(page2.len(), 1);
    assert!(!has_more2);

    // Different repair SAIDs
    assert_ne!(page1[0].said, page2[0].said);
}

#[tokio::test]
#[serial]
async fn test_get_repair_records_pagination() {
    let Some(repo) = connect_repo().await else {
        return;
    };

    let (vk, sk) = test_keys();
    let keys = keys_map(&vk);
    let kel_prefix = "Erepair_rec_paginate_kel________________________";
    let kind = "kels/v1/test-recpage";

    // Save a 4-record chain, replace from v1 (archiving v1, v2, v3 = 3 records)
    let chain = build_chain(kel_prefix, kind, 4, &sk);
    repo.sad_records
        .save_batch_with_verified_signatures(&chain, &keys)
        .await
        .unwrap();

    let prefix = chain[0].0.prefix;
    let replacement = build_replacement(
        &chain[0].0.said,
        &prefix,
        kel_prefix,
        kind,
        1,
        3,
        "replacement",
        &sk,
    );
    repo.sad_records
        .truncate_and_replace(&replacement, &keys)
        .await
        .unwrap();

    let (repairs, _) = repo
        .sad_records
        .get_repairs(prefix.as_ref(), 10, 0)
        .await
        .unwrap();
    assert_eq!(repairs.len(), 1);
    let repair_said = &repairs[0].said;

    // Paginate archived records: 3 total, limit=2
    let (page1, has_more1) = repo
        .sad_records
        .get_repair_records(repair_said.as_ref(), 2, 0)
        .await
        .unwrap();
    assert_eq!(page1.len(), 2);
    assert!(has_more1);

    let (page2, has_more2) = repo
        .sad_records
        .get_repair_records(repair_said.as_ref(), 2, 2)
        .await
        .unwrap();
    assert_eq!(page2.len(), 1);
    assert!(!has_more2);
}

#[tokio::test]
#[serial]
async fn test_get_repair_records_nonexistent() {
    let Some(repo) = connect_repo().await else {
        return;
    };

    let (records, has_more) = repo
        .sad_records
        .get_repair_records("Knonexistent_repair_said____________________", 10, 0)
        .await
        .unwrap();
    assert!(records.is_empty());
    assert!(!has_more);
}

#[tokio::test]
#[serial]
async fn test_truncate_and_replace_from_v0() {
    let Some(repo) = connect_repo().await else {
        return;
    };

    let (vk, sk) = test_keys();
    let keys = keys_map(&vk);
    let kel_prefix = "Erepair_full_replace_kel________________________";
    let kind = "kels/v1/test-fullrepl";

    // Save a 3-record chain
    let chain = build_chain(kel_prefix, kind, 3, &sk);
    repo.sad_records
        .save_batch_with_verified_signatures(&chain, &keys)
        .await
        .unwrap();

    let prefix = chain[0].0.prefix;

    // Replace the entire chain from v0
    // For v0 replacement, the record needs no previous and must re-derive the prefix
    let new_chain = build_chain(kel_prefix, kind, 2, &sk);
    // The new chain has the same prefix (deterministic from kel_prefix + kind)
    assert_eq!(new_chain[0].0.prefix, prefix);

    repo.sad_records
        .truncate_and_replace(&new_chain, &keys)
        .await
        .unwrap();

    // Chain should now be 2 records
    let stored = repo
        .sad_records
        .get_stored(prefix.as_ref(), None, None)
        .await
        .unwrap();
    assert_eq!(stored.len(), 2);
    assert_eq!(stored[0].pointer.said, new_chain[0].0.said);
    assert_eq!(stored[1].pointer.said, new_chain[1].0.said);

    // Repair should show 1 archived record (v2) — v0 and v1 are identical
    // and deduped, so only the tail beyond the replacement chain gets archived.
    let (repairs, _) = repo
        .sad_records
        .get_repairs(prefix.as_ref(), 10, 0)
        .await
        .unwrap();
    assert_eq!(repairs.len(), 1);
    assert_eq!(repairs[0].diverged_at_version, 2);

    let (archived, _) = repo
        .sad_records
        .get_repair_records(repairs[0].said.as_ref(), 10, 0)
        .await
        .unwrap();
    assert_eq!(archived.len(), 1);
}
