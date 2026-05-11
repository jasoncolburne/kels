# Branch Audit: KELS-129_builder-prep (Round 4) — 2026-04-20

Full review of all changed source files, handlers, verification logic, CLI, gossip sync, test scripts, migration, and design docs. Prior rounds: 10 findings, all resolved. 43 files changed, ~3200 diff lines.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 0        |
| Low      | 0    | 0        |

---

No new findings. The branch is clean.

---

## Positive Observations

- **Record kind as signed content is strictly better than query parameter.** The `?repair=true` flag was an out-of-band authorization channel. Now `Rpr` is embedded in the signed, content-addressed record — the repair intent is part of the SAID and cannot be injected by a third party modifying a URL parameter. All `new_repair`/`repair_sink` plumbing is fully removed with no orphans.

- **Dual seal design (checkpoint + establishment) is well-motivated.** `last_checkpoint_version` seals verified history; `establishment_version` protects the policy foundation. An attacker who compromises `write_policy` after v5 cannot repair back through v0/v1 to replace the checkpoint_policy declaration — the establishment seal catches this independently of the checkpoint seal. The two checks protect different invariants and cannot be collapsed.

- **Dedup-before-branch-detection eliminates a class of replay bugs.** Moving SAID dedup ahead of repair detection (handler lines 1247-1274) means historical Rpr records in gossip replays are filtered out before the `is_repair` check. Only genuinely new Rpr records trigger the repair path. The `truncate_and_replace` function's internal dedup is now redundant for the repair path but harmless — belt-and-suspenders.

- **validate_structure + verifier separation is clean and complete.** Record-level invariants (version constraints, required/forbidden fields per kind) live in `validate_structure()`. Chain-state reasoning (Est rejected when cp already established, Upd/Evl/Rpr rejected without cp) lives in the verifier. The verifier calls `validate_structure()` first and trusts its results, using `unreachable!()` for Icp at v1+ since validate_structure already rejected it. No logic is duplicated between the two layers.

- **Test scripts properly construct kind-typed JSON records.** `load-sad.sh` and `test-sadstore.sh` build v0 with `kind: "kels/sad/v1/pointer/icp"`, v1 with `kind: "kels/sad/v1/pointer/est"`, subsequent records with `kind: "kels/sad/v1/pointer/upd"`, and repairs with `kind: "kels/sad/v1/pointer/rpr"`. The `--repair` CLI flag is removed from all invocations.

- **Namespace rework is thorough and consistent.** `kels/events/v1/X` → `kels/kel/v1/events/X` for KEL events, `kels/exchange/v1/keys/mlkem` → `kels/sad/v1/keys/mlkem` for SAD pointer topics, `kels/identity/v1/chain` → `kels/sad/v1/identity/chain`. Exchange protocol constants (`kels/exchange/v1/protocols/essr`, `kels/exchange/v1/topics/exchange`) are correctly left unchanged — they name exchange protocol concepts, not pointer topics. All source, tests, shell scripts, and docs updated in one pass.
