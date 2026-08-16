---
name: Feature request
about: Propose a capability or a new mutator
title: ""
labels: enhancement
assignees: ""
---

## The Problem

<!-- What can you not do today? Describe the situation, not the solution. -->

## The Proposal

<!-- What Ordeal should do instead. Include the command line or the YAML as you
     would want to write it. -->

```bash

```

## Alternatives Considered

<!-- What you tried, and why it is not enough. -->

<!-- ------------------------------------------------------------ -->

## For a New Mutator

Delete this section if the request is not a mutator.

**Technique.** <!-- What the evasion is, in one sentence. -->

**Before → after.** <!-- A concrete command line, both forms. -->

```
before:
after:
```

**Semantics-preserving.** <!-- Why the mutated command does the same thing on the
host. This is the bar — a mutation that changes behavior is a false finding. -->

**Citation.** <!-- MITRE ATT&CK technique, a Sigma modifier, LOLBAS, ArgFuscator,
Invoke-DOSfuscation, a paper, or an incident report. A mutator ships with an
anchor. -->

**Rules it evades.** <!-- Public rules that miss the mutated form, if you know of
any. -->

<!-- ------------------------------------------------------------ -->

## Scope

Ordeal keeps one format, one flag, and one way to do a thing. Say briefly why this
belongs in the tool rather than in a wrapper around it.

---

<sub>Built by <a href="https://principlebreach.com">Principle Breach</a> — offensive security research.</sub>
