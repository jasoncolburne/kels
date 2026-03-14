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

pub use compaction::{MAX_RECURSION_DEPTH, compact, expand_all, expand_field, store_credentials};
pub use credential::{Compactable, Credential};
pub use disclosure::{PathToken, apply_disclosure, parse_disclosure};
pub use edge::{Edge, Edges};
pub use error::CredentialError;
pub use revocation::revocation_hash;
pub use rule::{Rule, Rules};
pub use schema::{
    CredentialSchema, SchemaConstraint, SchemaEdge, SchemaField, SchemaRule,
    SchemaValidationReport, SchemaValidationResult,
};
pub use store::{InMemorySADStore, SADStore};
pub use verification::{CredentialVerification, verify_credential};
