//! Identity Event Log (IEL) types.
//!
//! IEL is the chain primitive that governs an identity. It carries
//! `auth_policy` and `governance_policy` declarations (at `Icp`) and
//! evolutions (at `Evl`); SE chains bind to specific IEL events by SAID to
//! resolve cross-chain authorization. Terminal lifecycle is `Cnt` (contest)
//! or `Dec` (decommission). Divergence is preserved as data and resolved by
//! `Cnt` — IEL has no `Rpr` kind and no archive.
//!
//! Design: `docs/design/iel/{events,event-log,verification,merge,reconciliation}.md`.

mod event;

pub use event::*;
