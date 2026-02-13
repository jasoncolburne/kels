# Federation State Machine

This document describes the Raft state machine used by the registry federation to manage the core peer set.

## Overview

The federation uses [OpenRaft](https://github.com/datafuselabs/openraft) for distributed consensus. The Raft state machine is the replicated state that all federation members maintain identical copies of. It stores:

- **Core peer set** - peers trusted by all nodes in the federation
- **Pending proposals** - proposals awaiting multi-party approval
- **Completed proposals** - approved/rejected/withdrawn proposals (audit trail)
- **Votes** - stored by SAID for privacy (proposals only reference vote SAIDs)

## Architecture

```
Leader                          Follower A                    Follower B
  |                                |                             |
  | client_write(AddPeer)          |                             |
  |----> Raft log append           |                             |
  |          |                     |                             |
  |          +---- replicate ----->|                              |
  |          +---- replicate ---------------------------------->|
  |          |                     |                             |
  |     apply() locally       apply() locally              apply() locally
  |     - verify anchoring    - verify anchoring           - verify anchoring
  |     - write to DB         - write to DB                - write to DB
  |     - update state        - update state               - update state
```

## State Machine Data

```rust
pub struct StateMachineData {
    pub last_applied_log: Option<LogId<TypeConfig>>,
    pub last_membership: StoredMembership<TypeConfig>,
    pub peers: HashMap<String, Peer>,
    pub pending_proposals: HashMap<String, PeerProposal>,
    pub completed_proposals: Vec<PeerProposal>,
    pub votes: HashMap<String, Vote>,
}
```

### Peers

The `peers` HashMap is the core peer set, keyed by `peer_id`. These are the peers trusted across all federation members. Regional peers are not stored here -- they live in each registry's local database only.

### Proposals and Votes

Core peer additions go through a multi-party approval process:

1. A federation member **proposes** a peer (`ProposeCorePeer`)
2. Other members **vote** on the proposal (`VoteCorePeer`)
3. When the approval threshold is met, the peer is automatically added to the core set
4. The proposal moves to `completed_proposals` for auditing

Votes are stored separately in a `votes` HashMap keyed by SAID. Proposals only store vote SAIDs (not the full vote data) for privacy. This allows verification of vote integrity without exposing voter details in the proposal chain.

## Request Types

| Request | Description | Who Can Submit |
|---------|-------------|----------------|
| `AddPeer` | Directly add a peer to the core set | Leader (via DB sync or approved proposal) |
| `RemovePeer` | Remove a peer from the core set | Leader |
| `ProposeCorePeer` | Create a proposal for a new core peer | Any member |
| `VoteCorePeer` | Vote on a pending proposal | Any member |
| `WithdrawProposal` | Cancel a pending proposal | Original proposer only |

## Synchronous Apply (Pure State Machine)

The `StateMachineData::apply()` method is a pure, synchronous function that updates in-memory state. It handles:

- **AddPeer**: Inserts peer into `peers` HashMap
- **RemovePeer**: Removes peer from `peers` HashMap
- **ProposeCorePeer**: Creates an empty proposal (v0, no votes yet), checking for duplicate peers and proposals
- **VoteCorePeer**: Records vote, checks threshold, auto-approves if threshold met (adding peer to core set and moving proposal to completed)
- **WithdrawProposal**: Only the original proposer can withdraw; moves to completed with `Withdrawn` status

## Asynchronous Apply (Verification Layer)

The `StateMachineStore` implements OpenRaft's `RaftStateMachine` trait. Its async `apply()` method wraps the synchronous state machine with verification:

### AddPeer Verification

Before applying an `AddPeer` entry from the Raft log:

1. **KEL anchoring**: Verify the peer's SAID is anchored in a federation member's KEL (`verify_member_anchoring`). This proves a trusted member authorized this peer.
2. **Self-anchoring**: Anchor the peer's SAID in our own KEL (so we also vouch for it).
3. **DB write**: Write the peer to our local PostgreSQL database via `upsert_peer_to_db`.

If anchoring verification fails, the entry is **skipped** (not applied to state). This means a rogue leader cannot add unauthorized peers -- followers independently verify and reject unanchored entries.

### VoteCorePeer Verification

Before applying a vote:

1. **Proposal mismatch**: Reject if the vote references a different proposal than claimed
2. **Proposal chain integrity**: Verify the proposal's chained SAID history
3. **Vote SAID integrity**: Verify the vote's own SAID is correct
4. **Vote anchoring**: Verify the vote is anchored in the voter's KEL

### ProposeCorePeer Verification

Before applying a proposal:

1. **Proposal anchoring**: Verify the proposal's SAID is anchored in the proposer's KEL

### Approved Proposal Side Effects

When a `VoteCorePeer` triggers approval (threshold met), the async layer also:

1. Anchors the approved peer's SAID in our KEL
2. Writes the peer to the local database

## Defense in Depth

The federation security model has multiple layers:

### Layer 1: Compile-Time Trust

`TRUSTED_REGISTRY_PREFIXES` is baked into binaries at compile time. Only these prefixes can participate in federation. This cannot be changed at runtime.

### Layer 2: KEL-Based Message Authentication

All Raft RPC messages between federation members are signed and verified against the sender's KEL. Messages from unknown or compromised prefixes are rejected.

### Layer 3: Follower-Side Verification

Each follower independently verifies every Raft log entry before applying it. The leader proposes entries, but followers are not obligated to accept them blindly. If a rogue leader submits an `AddPeer` without proper KEL anchoring, followers skip it.

### Layer 4: Multi-Party Voting

Core peer additions require a minimum of 3 votes from federation members (scaling to ceil(n/3) for larger federations). A single compromised registry cannot unilaterally add peers.

### Layer 5: Tamper-Evident Chaining

Proposals and votes use content-addressed chaining (SAID + previous). Any tampering with the proposal history is detectable via chain verification.

## Peer Allowlist Consumers

The core peer set flows to multiple consumers:

| Consumer | How It Gets Peers | Verification |
|----------|-------------------|--------------|
| State machine `apply()` | Direct Raft log entries | KEL anchoring, vote verification |
| Registry API (`/api/peers`) | Reads from state machine | Pre-verified by state machine |
| Gossip allowlist refresh | Fetches from registry API | KEL verification of peer SAIDs |
| Registry client library | Fetches from registry API | KEL verification of peer SAIDs |
| DB sync loop (leader) | Reads from local DB | Raft consensus replication |

## Snapshot and Restore

The state machine supports snapshotting for efficient Raft log compaction:

- **Snapshot**: Serializes `peers`, `pending_proposals`, `completed_proposals`, and `votes` to JSON
- **Restore**: Deserializes and verifies all proposal chains before accepting. Proposals with invalid chains are dropped during restore.

## DB Sync Loop

The leader runs a background sync loop (`sync.rs`) that reads core peers from the local PostgreSQL database and replicates changes to Raft. This allows the admin CLI to write directly to the database, with changes propagating automatically via consensus.

Flow: Admin CLI -> local DB -> sync loop (leader) -> Raft -> all followers

The reverse direction (Raft -> DB) happens immediately in the state machine `apply()` method.

## Approval Threshold

The voting threshold for core peer approval scales with federation size:

| Federation Size (n) | Threshold |
|---------------------|-----------|
| 0-5 | 3 |
| 6-9 | 4 |
| 10+ | ceil(n/3) |

The minimum threshold of 3 prevents trivial collusion — even in the smallest viable federation (3 members), all members must agree.

## Rogue Leader Attack

A compromised leader could attempt to:

1. **Add unauthorized peers via `AddPeer`**: Blocked by follower-side KEL anchoring verification
2. **Fabricate votes**: Blocked by vote SAID verification and KEL anchoring checks
3. **Tamper with proposal history**: Blocked by proposal chain verification
4. **Skip the voting process entirely**: Blocked by vote verification in `apply()` -- followers check that a completed proposal with sufficient unique voter prefixes exists

The key insight is that the Raft log is just a proposal mechanism. Followers independently verify every entry and reject anything that doesn't meet the verification criteria.
