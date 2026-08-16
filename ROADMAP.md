# Roadmap

Direction, not dates. Ordeal ships when it is correct.

## Shipped

- Detection unit testing against inline events, positive and negative.
- Named-selection assertions (`selections:`).
- Telemetry replay from JSON, JSONL, EVTX-rendered, and winlogbeat exports.
- Adversarial mutation — ten semantics-preserving evasions, field-aware, payload-safe.
- `run`, `mutate`, `lint`, `list` commands with human, JSON, and JUnit output.
- Signed, SBOM-attested releases; GitHub Action; distroless image.

## Next

- **Vendor and extend the Sigma engine.** Fork `sigma-go` behind the existing
  `engine.Engine` interface and close the modifier gaps in [COVERAGE.md](COVERAGE.md):
  `windash`, `Field: null`, `base64offset`, `wide`, `re` sub-flags, `fieldref`.
- **Backend-differential lint.** Compile a rule to SPL / KQL / ES|QL and assert
  the compiled query means the same as the abstract rule — the failure mode where
  a rule converts cleanly and still never fires.
- **Differential correctness oracle.** Run every SigmaHQ rule through both the
  native engine and a reference evaluator; treat any disagreement as a bug.

## Later

- Attack-execution backend — detonate a technique, capture the real telemetry, assert the rule fires.
- Sigma v2 correlations (time-ordered fixtures).
- Mutation coverage scoring across a whole ruleset, tracked over time.

---

<sub>Built by <a href="https://principlebreach.com">Principle Breach</a> — offensive security research and advisory. Part of <a href="https://adversaryholdings.com">Adversary Holdings</a>.</sub>
