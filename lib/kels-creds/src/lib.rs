#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::unwrap_in_result)
)]

pub mod compaction;
pub mod credential;
pub mod disclosure;
pub mod edge;
pub mod error;
pub mod revocation;
pub mod rule;
pub mod schema;
pub mod store;
pub mod verification;

pub use compaction::{compact, compute_said_from_value, expand_all, expand_field};
pub use credential::{Credential, CredentialValue};
pub use disclosure::{PathToken, apply_disclosure, parse_disclosure};
pub use edge::{Edge, Edges};
pub use error::CredentialError;
pub use revocation::revocation_hash;
pub use rule::{Rule, Rules};
pub use schema::{CredentialSchema, SchemaField, validate_claims};
pub use store::{ChunkStore, CredentialStore, InMemoryChunkStore, InMemoryCredentialStore};
pub use verification::{CredentialVerification, verify_credential};
