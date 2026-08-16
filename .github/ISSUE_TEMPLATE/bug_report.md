---
name: Bug report
about: Ordeal did the wrong thing
title: ""
labels: bug
assignees: ""
---

**Do not use this template for a security vulnerability in Ordeal itself.**
See [SECURITY.md](../../SECURITY.md) — email security@principlebreach.com.

## What Happened

<!-- One or two sentences. -->

## What You Expected

<!-- The verdict, output, or exit code you expected instead. -->

## Reproduction

The command:

```bash
ordeal run ./rules
```

The suite (`<rule>.test.yml`):

```yaml

```

The rule (`rule.yml`), trimmed to the detection block if it is large:

```yaml

```

## Actual Output

<!-- Paste the full output. Add --format json if the human output is ambiguous. -->

```

```

Exit code: <!-- 0, 1, or 2 -->

## Environment

- Ordeal version: <!-- ordeal --version -->
- Install method: <!-- go install / homebrew / release archive / container / action -->
- OS and architecture:
- Go version, if built from source:

## Notes

<!-- Anything else: does it reproduce on the example rules, when it started, a
     narrower case you found while triaging. Optional. -->

---

<sub>Built by <a href="https://principlebreach.com">Principle Breach</a> — offensive security research.</sub>
