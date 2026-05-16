# [Gap 5 → #162] Builder-level IEL state caching retargeted to client-side caching strategy

Plan §Gap 5 originally called for cached IEL state on `SadEventBuilder` plus `iel_client` HTTP-fetch caching, so successive `update()` / `seal()` / `repair()` / `contest()` / `decommission()` calls within a single CLI invocation wouldn't each round-trip to the IEL HTTP endpoint. The deferral was originally targeted at #147 (CLI + script migration), where the CLI consumer drives the repeated-builder-call access pattern.

#147 closed without picking up the cache. End-of-round e2e (heisenbug long-loop) cleared without it, confirming the work was performance-only and not load-bearing for the round's correctness.

The narrow CLI-builder-cache framing was reframed during workstream-tracker review: the broader concept is "clients walk SEL/IEL/KEL dependency graphs repeatedly during lifecycle operations; we have no coherent caching strategy." The narrow item is one specific instance of the broader concern.

**Filed as #162** (Client-side dep-graph caching strategy for SEL/IEL/KEL) with the broader framing. Low priority — bounded by client session length, doesn't gate any feature. Revisit when a real workload demands it (harness perf feedback, high-volume SDK consumer, etc.). The motivating-instance section of #162 calls out builder-side IEL state caching by name, so the original Gap 5 work is preserved as a concrete subtask if/when the strategy is picked up.
