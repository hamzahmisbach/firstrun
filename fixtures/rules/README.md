# Rules fixtures

One folder per case (docs/ARCHITECTURE.md 9.4): `events.jsonl` (synthetic 7.4 events, fake tokens, .test hosts), `contract.json`, `decoys.json`, `expected.json` (`level`, `rule_ids`, `severity_counts`, optional `rules_present`, `rules_absent`, `findings_count`, `notes_include`), optional `layers.json`, `coverage.json`, `meta.json` (`contractMeta`, `sinkIp`, `unwrap`). `expected.full.json` is a golden copy of the findings for a few demo-like cases; refresh with `UPDATE_GOLDEN=1 node --test test/rules.test.mjs`.

`server/test/rules.test.mjs` loads every folder automatically; adding a case is adding a folder.
