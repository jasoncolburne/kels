# [Gap 0 → Gap 5] `AnchoredIelResolver` moved from lib/policy to lib/kels

The impl uses only kels-core types (no policy DSL machinery), and the SE builder lives in lib/kels which can't import from lib/policy (downstream). Moving it upstream lets the builder construct one. The `pub use AnchoredIelResolver` re-export moved from `kels_policy` to `kels_core`. No external consumers existed before Gap 5 (verified).
