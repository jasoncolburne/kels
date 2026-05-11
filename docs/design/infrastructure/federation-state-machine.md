# Federation State Machine

This document describes the Raft state machine used by the registry federation to manage the peer set.

## Overview

The federation uses [OpenRaft](https://github.com/datafuselabs/openraft) for distributed consensus. The Raft state machine is the replicated state that all federation members maintain identical copies of. It stores:

- **Peer set** - peers trusted by all nodes in the federation
- **Pending proposals** - addition and removal proposals awaiting multi-party approval
- **Completed proposals** - approved/withdrawn proposals (audit trail)
- **Votes** - stored by SAID

## Architecture

```
Leader                          Follower A                    Follower B
  |                                |                             |
  | client_write(AddPeer)          |                             |
  |----> Raft log append           |                             |
  |          |                     |                             |
  |          +---- replicate ----->|                             |
  |          +---- replicate ----------------------------------->|
  |          |                     |                             |
  |     apply() locally       apply() locally              apply() locally
  |     - verify anchoring    - verify anchoring           - verify anchoring
  |     - update state        - update state               - update state
```

## State Machine Data

```rust
pub struct StateMachineData {
    pub last_applied_log: Option<LogId<TypeConfig>>,
    pub last_membership: StoredMembership<TypeConfig>,
    pub active_peers: HashMap<String, Peer>,
    pub inactive_peers: HashMap<String, Peer>,
    pub pending_addition_proposals: HashMap<String, PeerAdditionProposal>,
    pub completed_addition_proposals: Vec<Vec<PeerAdditionProposal>>,
    pub pending_removal_proposals: HashMap<String, PeerRemovalProposal>,
    pub completed_removal_proposals: Vec<Vec<PeerRemovalProposal>>,
    pub votes: HashMap<String, Vote>,
}
```

### Peers

Active and inactive peers are stored in separate HashMaps, both keyed by `peer_prefix`. Active peers are the trusted peer set. Inactive peers are deactivated peers preserved for audit trail — when a peer is removed, it moves from `active_peers` to `inactive_peers` rather than being deleted.

### Member KELs

Member KELs are stored locally in `MemberKelRepository` (PostgreSQL), **not** in Raft state. Raft has no involvement in member KEL synchronization. The submit handler (`POST /api/v1/member-kels/events`) fans out to other registries only when the submitted prefix matches the receiver's own prefix — this means identity pushes to the local registry, which fans out, and other members just store. If fan-out fails for any member, the background sync loop fills in gaps — each node periodically fetches its own KEL from the identity service, compares effective SAIDs with each member's view, and pushes deltas to stale members. This decoupled design supports natural propagation of all KEL operations (including divergence resolution) without any Raft interaction. See [kel/recovery-workflow.md](kel/recovery-workflow.md).

### Proposals and Votes

Peer additions and removals go through a multi-party approval process:

1. A federation member **proposes** a peer addition or removal (`SubmitAdditionProposal` / `SubmitRemovalProposal`)
2. Other members **vote** on the proposal (`VotePeer`)
3. When the approval threshold is met, the peer is automatically added to or removed from the peer set
4. The proposal moves to the completed proposals list for auditing

Votes are stored separately in a `votes` HashMap keyed by SAID, not embedded in proposals.

## Request Types

| Request | Description | Who Can Submit |
|---------|-------------|----------------|
| `AddPeer` | Directly add a peer to the peer set | Leader (via DB sync or approved proposal) |
| `RemovePeer` | Remove a peer from the peer set | Leader |
| `SubmitAdditionProposal` | Create or withdraw a proposal for a new peer | Any member |
| `SubmitRemovalProposal` | Create or withdraw a proposal to remove a peer | Any member |
| `VotePeer` | Vote on a pending proposal (addition or removal) | Any member |

## Synchronous Apply (Pure State Machine)

The `StateMachineData::apply()` method is a pure, synchronous function that updates in-memory state. It handles:

- **AddPeer**: Inserts peer into `active_peers` HashMap
- **RemovePeer**: Moves peer from `active_peers` to `inactive_peers` (must be deactivated; rejects active peers)
- **SubmitAdditionProposal**: v0 creates an empty proposal checking for duplicate peers/proposals; v1 withdraws (only before any votes are cast)
- **SubmitRemovalProposal**: v0 creates a removal proposal checking the peer exists; v1 withdraws (only before any votes are cast)
- **VotePeer**: Records vote, checks threshold (from the proposal, not config).
  - If threshold met:
    - Additions: returns the approved proposal — the leader handler then creates the peer, anchors it, and submits `AddPeer`
    - Removals: returns the approved proposal — the leader handler then deactivates the peer, anchors it, and submits `RemovePeer`
    - Both: moves proposal to completed.

## Asynchronous Apply (Verification Layer)

The `StateMachineStore` implements OpenRaft's `RaftStateMachine` trait. Its async `apply()` method wraps the synchronous state machine with verification:

### AddPeer Verification

Before applying an `AddPeer` entry from the Raft log:

1. **Proposal threshold**: Find the completed addition proposal for this peer and extract its stored threshold. Reject if no completed proposal exists. Enforce the minimum threshold floor (`compute_approval_threshold(0)`, currently 3) — see [Threshold Verification](#threshold-verification).
2. **Vote threshold**: Count verified voters — each vote must pass SAID integrity (`verify_said()`) and be anchored in the voter's KEL (`verify_member_anchoring`). Reject if verified voters < proposal threshold.
3. **KEL anchoring**: Verify the peer's SAID is anchored in a federation member's KEL (`verify_member_anchoring`). This proves a trusted member authorized this peer.

Note: Self-anchoring (anchoring the peer's SAID in our own KEL) does not happen in `apply()`. It happens in the leader's HTTP handler before submitting the `AddPeer` request.

If threshold or anchoring verification fails, the entry is **skipped** (not applied to state). This means a rogue leader cannot add unauthorized peers — followers independently verify vote threshold and anchoring, rejecting unverified entries.

### RemovePeer Verification

Before applying a `RemovePeer` entry from the Raft log:

1. **Proposal threshold**: Find the completed removal proposal for this peer and extract its stored threshold. Reject if no completed proposal exists. Enforce the minimum threshold floor.
2. **Vote threshold**: Count verified voters from the completed removal proposal. Reject if verified voters < proposal threshold.
3. **KEL anchoring**: Verify the deactivated peer's SAID is anchored in the authorizing member's KEL.

### VotePeer Verification

Before applying a vote:

1. **Proposal mismatch**: Reject if the vote references a different proposal than claimed
2. **Proposal chain integrity**: Verify the proposal's chained SAID history
3. **Vote SAID integrity**: Verify the vote's own SAID is correct
4. **Vote anchoring**: Verify the vote is anchored in the voter's KEL

### SubmitAdditionProposal / SubmitRemovalProposal Verification

Before applying a proposal:

1. **Threshold floor**: Verify the proposal's `threshold` field meets the minimum floor (`compute_approval_threshold(0)`) — see [Threshold Verification](#threshold-verification). The exact-match check against current config happens in the leader's HTTP handler, not here.
2. **Proposal anchoring**: Verify the proposal's SAID is anchored in the proposer's KEL

### Approved Proposal Side Effects

When a `VotePeer` triggers addition approval (threshold met), the state machine returns `VoteRecorded { approved: true, proposal: Some(...) }`. The leader's HTTP handler then creates the Peer record, anchors the peer's SAID in its own KEL, and submits a separate `AddPeer` request to Raft. These side effects happen in the handler, not in the state machine's `apply()`.

When a `VotePeer` triggers removal approval, the state machine returns `RemovalApproved` with the proposal. The leader's HTTP handler then:

1. Deactivates the peer (sets `active = false`, increments version)
2. Anchors the deactivated peer's SAID in its own KEL
3. Submits a separate `RemovePeer` request to Raft

## Defense in Depth

The federation security model has multiple layers:

### Layer 1: Compile-Time Trust

`TRUSTED_REGISTRY_PREFIXES` is baked into binaries at compile time. Only these prefixes can participate in federation. This cannot be changed at runtime.

### Layer 2: KEL-Based Message Authentication

All Raft RPC messages between federation members are signed and verified against the sender's KEL. Messages from unknown or compromised prefixes are rejected.

### Layer 3: Follower-Side Verification

Each follower independently verifies every Raft log entry before applying it. The leader proposes entries, but followers are not obligated to accept them blindly. If a rogue leader submits an `AddPeer` without proper KEL anchoring, followers skip it.

### Layer 4: Multi-Party Voting

Peer additions and removals require a minimum of 3 votes from federation members (scaling to ceil(n/3) for larger federations). A single compromised registry cannot unilaterally modify the peer set.

### Layer 5: Tamper-Evident Chaining

Proposals and votes use content-addressed chaining (SAID + previous). Any tampering with the proposal history is detectable via chain verification.

## Peer Allowlist Consumers

The peer set flows to multiple consumers:

| Consumer | How It Gets Peers | Verification |
|----------|-------------------|--------------|
| State machine `apply()` | Direct Raft log entries | KEL anchoring, vote verification |
| Registry API (`/api/v1/peers`) | Reads from state machine | Pre-verified by state machine |
| Gossip allowlist refresh | Fetches from registry API | KEL verification of peer SAIDs |
| Registry client library | Fetches from registry API | KEL verification of peer SAIDs |

## Snapshot and Restore

The state machine supports snapshotting for efficient Raft log compaction:

- **Snapshot**: Serializes `active_peers`, `inactive_peers`, `pending_addition_proposals`, `completed_addition_proposals`, `pending_removal_proposals`, `completed_removal_proposals`, and `votes` to JSON
- **Restore**: Deserializes and verifies all proposal chains before accepting. Proposals with invalid chains are dropped during restore.

## KEL Sync Loop

Every node runs a background KEL sync loop (`sync.rs`) that periodically:

1. Fetches its own identity KEL using `forward_key_events` (HttpKelSource → RepositoryKelStore)
2. Compares its local effective SAID with each member's view
3. Pushes delta events directly to members with stale state via `POST /api/v1/member-kels/events`

Each node only pushes its own KEL — every node pushes its own, so all member KELs get distributed. The sync loop fills in gaps when the submit handler's eager fan-out fails to reach a member.

Flow: Identity service → sync loop → local MemberKelRepository → push deltas to stale members via HTTP

Raft is not involved in member KEL synchronization. Before Raft initialization, `sync_all_member_kels` bootstraps all member KELs from peer registries so that Raft log replay can verify vote anchoring.

## Approval Threshold

The voting threshold for peer approval scales with federation size:

| Federation Size (n) | Threshold |
|---------------------|-----------|
| 0-5 | 3 |
| 6-9 | 4 |
| 10+ | ceil(n/3) |

The minimum threshold of 3 prevents trivial collusion — even in the smallest viable federation (3 members), all members must agree.

## Threshold Verification

The approval threshold is stored on each proposal at creation time. Threshold verification is split across two layers:

### Leader Handler (Exact Match)

When a proposal is submitted via the HTTP API, the leader handler verifies `proposal.threshold == approval_threshold()` — rejecting proposals where the threshold doesn't match the current federation config. This runs only at real submission time, never during Raft log replay.

### Outer `apply()` (Floor Check)

When replaying Raft log entries (e.g., after a registry restart), the outer `apply()` only enforces a minimum threshold floor (`compute_approval_threshold(0)`, currently 3). It does **not** check against the current config because the config may have changed since the entry was originally committed — a federation that grew from 3 to 10 members would have a different `approval_threshold()` than when earlier proposals were accepted. An exact-match check during replay would incorrectly reject legitimate historical entries.

### Why Both Layers Are Needed

The exact-match check in the leader handler prevents a proposer from submitting a proposal with an artificially low threshold (e.g., threshold 3 in a 10-member federation where the correct threshold is 4). The floor check in `apply()` is defense-in-depth: if a forged proposal with a below-minimum threshold somehow enters the Raft log (e.g., through a bug or exploit), followers will reject it. Together with the floor check on `AddPeer`/`RemovePeer` verification, this ensures that no peer change can ever be approved with fewer than 3 verified votes, regardless of how the entry entered the log.

## Rogue Leader Attack

A compromised leader could attempt to:

1. **Add unauthorized peers via `AddPeer`**: Blocked by follower-side KEL anchoring verification
2. **Fabricate votes**: Blocked by vote SAID verification and KEL anchoring checks
3. **Tamper with proposal history**: Blocked by proposal chain verification
4. **Skip the voting process entirely**: Blocked by vote verification in `apply()` — followers check that a completed proposal with sufficient unique voter prefixes exists
5. **Forge a low-threshold proposal**: If three members collude and one becomes leader, they could craft a proposal with `threshold: 3` in a larger federation (e.g., 10 members, correct threshold 4). The leader handler's exact-match check rejects this at submission time. Even if the forged proposal enters the log, the floor check ensures followers never accept fewer than 3 verified votes. In the worst case — three colluding members successfully add a rogue peer — the resolution is straightforward: legitimate operators vote to remove the rogue peer via the standard removal proposal process.

The key insight is that the Raft log is just a proposal mechanism. Followers independently verify every entry and reject anything that doesn't meet the verification criteria.
