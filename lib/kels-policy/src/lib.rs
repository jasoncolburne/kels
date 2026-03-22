#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::unwrap_in_result)
)]

pub(crate) mod ast;
pub(crate) mod error;
pub(crate) mod evaluator;
pub(crate) mod parser;
pub(crate) mod policy;
pub(crate) mod resolver;
pub(crate) mod verification;

pub use ast::PolicyNode;
pub use error::PolicyError;
pub use evaluator::{evaluate_policy, poison_hash};
pub use parser::{canonicalize, parse};
pub use policy::Policy;
pub use resolver::{InMemoryPolicyResolver, PolicyResolver};
pub use verification::{EndorsementStatus, PolicyVerification};
