#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::unwrap_in_result)
)]

pub(crate) mod ast;
pub(crate) mod error;
pub(crate) mod evaluator;
pub(crate) mod identity_chain;
pub mod json_api;
pub(crate) mod parser;
pub(crate) mod policy;
pub(crate) mod policy_checker;
pub(crate) mod resolver;
pub(crate) mod verification;

pub use ast::PolicyNode;
pub use error::PolicyError;
pub use evaluator::{evaluate_anchored_policy, evaluate_signed_policy, poison_hash};
pub use identity_chain::{
    IDENTITY_CHAIN_TOPIC, advance as advance_identity_chain, compute_identity_prefix,
    create as create_identity_chain,
};
pub use parser::{canonicalize, parse};
pub use policy::Policy;
pub use policy_checker::AnchoredPolicyChecker;
pub use resolver::{InMemoryPolicyResolver, PolicyResolver};
pub use verification::{EndorsementStatus, PolicyVerification};
