#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::unwrap_in_result)
)]

pub mod compaction;
pub mod credential;
pub mod disclosure;
pub mod edge;
pub mod error;
pub mod json_api;
pub mod revocation;
pub mod rule;
pub mod schema;
pub mod store;
pub mod verification;

pub use compaction::{
    MAX_RECURSION_DEPTH, compact, compact_with_schema, expand_field, expand_with_schema,
    store_credentials,
};
pub use credential::{Compactable, Credential};
pub use disclosure::{PathToken, apply_disclosure, parse_disclosure};
pub use edge::{Edge, Edges};
pub use error::CredentialError;
pub use revocation::revocation_hash;
pub use rule::{Rule, Rules};
pub use schema::{
    Schema, SchemaField, SchemaFieldType, SchemaValidationReport, SchemaValidationResult,
};
pub use store::{InMemorySADStore, SADStore};
pub use verification::{CredentialVerification, verify_credential};
