# [Gap 1 → Gap 3] 4 schema-dependent `repair_tests.rs` cases

Gap 3 migrated `migrations/0001_initial.sql` in place (dropped `write_policy` / `governance_policy`, added NULLABLE `identity` / `identity_event`). All 7 `repair_tests.rs` cases now pass against the new schema, plus 22 `integration_tests.rs` and 13 SADStore lib tests.

Gap 3 also added `is_contested` / `is_decommissioned` to `SadEventRepository` and rewired `effective_said` + `list_prefixes` with the round-12 terminal-state precedence (Decommissioned > Contested > Divergent > linear).
