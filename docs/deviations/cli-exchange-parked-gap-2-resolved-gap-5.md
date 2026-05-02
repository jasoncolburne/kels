# [Gap 2 → Gap 5] CLI exchange commands parked

`cmd_exchange_publish_key` and `cmd_exchange_rotate_key` returned errors with descriptive "parked pending Gap 11 CLI rewrite" messages. The pre-round-12 flow declared `write_policy` / `governance_policy` inline at inception and computed the SEL prefix from `(write_policy, topic)`. Round-12 SE chains bind to an existing IEL via `identity` instead. Gap 11 reshapes the CLI surface to feed an IEL identity into `incept_chain(identity, topic, initial_content)`.

(Note: the *follow-on* parking of the same commands — Gap 5 → #147 — is tracked as a separate Open entry in the README index. This entry covers the Gap 2 → Gap 5 leg only.)
