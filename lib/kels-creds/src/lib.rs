#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::unwrap_in_result)
)]

pub(crate) mod compaction;
pub(crate) mod credential;
pub(crate) mod disclosure;
pub(crate) mod edge;
pub(crate) mod error;
pub mod json_api;
pub(crate) mod rule;
pub(crate) mod schema;
pub(crate) mod store;
pub(crate) mod verification;

pub use credential::{Compactable, Credential};
pub use disclosure::{PathToken, apply_disclosure, parse_disclosure};
pub use edge::{Edge, Edges};
pub use error::CredentialError;
pub use rule::{Rule, Rules};
pub use schema::{
    Schema, SchemaField, SchemaFieldType, SchemaValidationReport, SchemaValidationResult,
    validate_schema, validate_schema_compliance, validate_schema_structure,
};
pub use store::{InMemorySADStore, SADStore, store_credentials};
pub use verification::{CredentialVerification, verify_credential};

// Re-export kels-policy types for convenience
pub use kels_policy::{
    InMemoryPolicyResolver, Policy, PolicyResolver, PolicyVerification, evaluate_policy,
};
