# [Round-12 follow-up → resolved] Gap 8 PUSH-direction post-sync check — chose Option 1

`services/gossip/src/sync.rs` (~lines 1807-1908 pre-fix) applied the PULL-shaped post-sync check (`new_said != local_said` against the local effective SAID) uniformly across both PUSH and PULL directions. On a successful PUSH the local SAID didn't change (we sent; remote advanced), so the check returned `false`, the loop classified success as `Failed`, and the entry re-queued. Self-healed next cycle but inflated retry metrics.

Chose **Option 1**: skip the post-sync state-advancement check on PUSH; trust HTTP-2xx from `forward_sad_events` as proof of remote acceptance.

Rationale: `HttpSelSink::store_page` (`lib/kels/src/types/sad/sync.rs:279-301`) already converts any non-2xx-non-409 remote response into `Err`. The remote's submit handler runs the verifier inside the request/response cycle, so verifier rejection surfaces as a 4xx and propagates back as `forward_sel_events.is_err()`. PUSH's HTTP-2xx therefore genuinely carries the remote's accept signal, which is structurally different from PULL where the local sink's verifier runs *after* the HTTP layer returns 2xx. The original Gap 8 anti-pattern was PULL-specific; KEL Phase 1 (the architectural reference) has no PUSH branch, so the uniform check was a copy-error rather than a design choice.

Implementation: dropped the shared `sync_ok` boolean; PUSH and PULL each end with their own outcome dispatch (PUSH returns `Repaired` directly on success; PULL keeps the local-SAID re-fetch). Direction-anchored comments replace the conflated comment block. `any_peer_differs` semantics (NoOp vs Failed) unchanged.
