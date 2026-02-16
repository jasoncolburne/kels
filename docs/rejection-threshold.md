# Rejection Threshold

## Problem

The approval threshold for core peer proposals is `ceil(n/3)` (minimum 3). With 21 federation members this is 7. Without a rejection mechanism, 7 approvals would add a peer to the core set even if the remaining 14 members all voted to reject. A supermajority saying "no" should not be overridden by a minority saying "yes."

More concretely: the approval threshold exists to prevent unilateral action by a single compromised registry. But it does nothing to prevent a colluding minority from pushing through a proposal over the objections of the majority. Rejection votes were recorded but had no effect on outcomes — proposals either reached threshold or expired.

## Design

A fixed rejection threshold of **2 votes** kills a proposal immediately.

Once the second rejection vote is recorded, the proposal is moved to the completed set with a rejected status. No further votes can be cast.

## Rationale

**Why not 1?** A single rejection would give any lone federation member veto power over all proposals. This creates a griefing vector — one compromised or uncooperative registry could block all core peer changes indefinitely. The federation would have no recourse short of removing that member from the trusted prefix set (which requires a full redeployment).

**Why not a majority?** Requiring `ceil(n/2)` rejections to block means stopping a colluding minority requires coordinating a majority — exactly as hard as approving the proposal in the first place. If collusion is detected, the honest members shouldn't need to mobilize more people to block than the colluders needed to approve.

**Why 2?** Two rejections is the minimum that prevents lone-actor griefing while keeping the coordination bar for blocking as low as possible. If two independent federation members agree something is wrong, that should be sufficient to stop it. This mirrors the security philosophy of dual-signature requirements elsewhere in the system (recovery events require both current and recovery key signatures).

## Interaction with Approval Threshold

The rejection threshold is checked **before** the approval threshold in both the state machine and the `status()` computation. If both thresholds are met (only possible with pre-existing data from before this change), rejection takes priority — fail secure.

In practice, proposals follow one of these paths:

1. Approvals accumulate, threshold met → **Approved** (0 or 1 rejections)
2. Second rejection arrives before approval threshold → **Rejected**
3. Neither threshold met before expiry → **Rejected** (expired)
4. Proposer withdraws → **Withdrawn**

## Implementation

- Constant: `REJECTION_THRESHOLD = 2` in `lib/kels/src/types/peer.rs`
- State machine: rejection count checked after each vote, before approval check
- `status()`: rejection count checked before approval count (fail secure)
- Rejected proposals are moved to the completed set (same as expired/approved)
