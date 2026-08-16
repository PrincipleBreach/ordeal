# Pull Request

## What This Changes

<!-- One or two sentences. What it does, and why. -->

## Type

- [ ] Bug fix
- [ ] New mutator
- [ ] Feature
- [ ] Documentation
- [ ] Maintenance — dependencies, CI, refactor

## Checklist

- [ ] `go test ./...` passes.
- [ ] `gofmt -s -l .` reports nothing.
- [ ] `go vet ./...` is clean.
- [ ] New behavior ships with a test. A bug fix ships with the test that failed
      before the fix.
- [ ] `ordeal run ./examples` still passes.
- [ ] Documentation updated where behavior changed — `README.md`, `docs/`,
      `schema/suite.schema.json`.
- [ ] `CHANGELOG.md` updated under `[Unreleased]`.

## New Mutator

Delete this section if no mutator is added or changed.

- [ ] The mutation is semantics-preserving — the mutated command does the same
      thing on the host, and only its surface form changes.
- [ ] The doc comment cites the technique (MITRE ATT&CK, the Sigma `windash`
      modifier, LOLBAS, ArgFuscator, Invoke-DOSfuscation, or a paper).
- [ ] Registered in `mutate.Catalog()`.
- [ ] A table test proves the transform.
- [ ] A table test proves it is a no-op when the technique does not apply.
- [ ] Documented in `docs/mutators.md` with a before → after example and the
      fix guidance.

**Technique and citation:**

<!-- The technique in one sentence, and the link. -->

## Verification

<!-- What you ran, and what it printed. Paste the relevant output. -->

```

```

## Notes for the Reviewer

<!-- Trade-offs taken, alternatives rejected, anything you want argued with.
     Optional. -->

---

<sub>Built by <a href="https://principlebreach.com">Principle Breach</a> — offensive security research and advisory. Part of <a href="https://adversaryholdings.com">Adversary Holdings</a>.</sub>
