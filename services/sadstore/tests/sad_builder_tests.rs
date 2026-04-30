//! Integration tests for `SadEventBuilder`.
//!
//! **Round-12 Gap 5 stub.** The pre-round-12 tests in this file
//! (~1300 lines) targeted the old `incept_deterministic` / `evaluate` /
//! `repair(content)` shape and the old `write_policy` /
//! `governance_policy` SE fields. Gap 5 rewrote the builder around the
//! round-12 surface: `incept_chain(identity, topic, initial_content)`,
//! `update(content)`, `seal()`, `repair()`, `contest()`,
//! `decommission()`, with IEL bindings resolved from the server per-call.
//!
//! Per the round-12 plan's "Gap 10 — Tests (full-stack)" section, this
//! file gets a full rewrite against the new builder API with the
//! plan's prescribed test taxonomy (24+ cases covering happy paths,
//! soft/hard auth, sealed/unsealed routing, gossip propagation,
//! govfailed-terminal live-handler integration). The rewrite is
//! coordinated with the harness's KEL anchor convergence wait (Gap 9)
//! and the rest of the round-12 wiring.
//!
//! Until Gap 10 lands, this file ships as an empty-but-compiling stub
//! so the `make` pipeline stays green.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[test]
fn round12_gap5_placeholder_until_gap10_test_rewrite() {
    // intentionally empty; full test taxonomy lands in Gap 10.
}
