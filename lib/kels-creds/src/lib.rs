#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::unwrap_in_result)
)]

pub(crate) mod compaction;
pub(crate) mod credential;
pub(crate) mod disclosure;
pub(crate) mod edge;
pub(crate) mod error;
pub(crate) mod json_api;
pub(crate) mod revocation;
pub(crate) mod rule;
pub(crate) mod schema;
pub(crate) mod store;
pub(crate) mod verification;

pub use credential::{Compactable, Credential};
pub use disclosure::{PathToken, apply_disclosure, parse_disclosure};
pub use edge::{Edge, Edges};
pub use error::CredentialError;
pub use revocation::revocation_hash;
pub use rule::{Rule, Rules};
pub use schema::{
    Schema, SchemaField, SchemaFieldType, SchemaValidationReport, SchemaValidationResult,
    validate_schema,
};
pub use store::{InMemorySADStore, SADStore, store_credentials};
pub use verification::{CredentialVerification, verify_credential};

pub use json_api::{
    EdgeInput, RuleInput, disclose, parse_edges, parse_rules, store, validate, verify,
};
