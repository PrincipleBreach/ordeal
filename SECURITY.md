# Security Policy

Ordeal is built by [Principle Breach](https://principlebreach.com). We do this for
a living and we treat reports the way we would want ours treated: quickly,
privately, and with credit.

## Reporting a Vulnerability

Email **security@principlebreach.com**.

Do not open a public issue for a vulnerability in Ordeal itself. Do not disclose
publicly until a fix has shipped.

Include what you have:

- The version — `ordeal --version` — and the platform.
- Steps to reproduce, ideally a suite file and a rule that trigger it.
- The impact you believe it has.

Encrypt if you want to; ask for a key in a first message and we will send one.

### What to Expect

| Stage | Target |
| --- | --- |
| Acknowledgment | 3 business days |
| Initial assessment | 10 business days |
| Fix or mitigation for a confirmed issue | 90 days |

We will keep you updated, credit you in the release notes and the advisory unless
you ask us not to, and coordinate disclosure timing with you. If we disagree on
severity we will tell you why rather than go quiet.

## Supported Versions

| Version | Supported |
| --- | --- |
| 1.x | Yes |
| < 1.0 | No — upgrade |

Fixes land on the latest minor release of the supported line. There are no
backports to earlier minors.

## Scope

In scope — vulnerabilities in Ordeal itself:

- Code execution, path traversal, or file writes outside the working directory
  triggered by a crafted `.test.yml` suite, Sigma rule, or config file.
- Denial of service — unbounded memory, non-terminating parse or match — from
  crafted input.
- Anything in the release pipeline: build, signing, or the published action.

Out of scope:

- Vulnerabilities in a rule *you* wrote. Ordeal is the tool that finds those.
- Findings in dependencies with no exploitable path through Ordeal. Report those
  upstream; tell us if we should pin or patch.
- Missing hardening with no demonstrated impact.

## Threat Model

Ordeal reads local files, evaluates rules in-process, and writes a report. It
makes no network calls, executes nothing it reads, and needs no privileges beyond
read access to the paths you give it.

It is nonetheless a parser fed by whatever is in your repository. Treat suite
files, rules, and Sigma configs from untrusted sources as untrusted input, and
review a pull request that adds them the way you would review any other code.

## Mutation Output Is Not a Vulnerability

Ordeal's entire purpose is to generate evasions of detection rules. Its output
contains attack command strings — obfuscated PowerShell launchers, LOLBin download
invocations, carated and quoted command lines — and its test corpus contains more
of the same.

That is the product working. Reports of the form "the tool emits malicious
commands", "the repository contains attack strings", or "a scanner flagged the
example rules" are expected behavior, not vulnerabilities, and will be closed as
such.

The mutations are semantics-preserving transformations of command lines you
supplied in your own test fixtures. Ordeal never executes them.

Two operational notes that follow from this:

- Endpoint tooling on a build agent may flag Ordeal's output or corpus. Allowlist
  the path; do not disable the gate.
- Do not put live indicators in committed suites. Use documentation ranges
  (`198.51.100.0/24`, `example.com`) in fixtures.

---

<sub>Built by <a href="https://principlebreach.com">Principle Breach</a> — offensive security research and advisory. Part of <a href="https://adversaryholdings.com">Adversary Holdings</a>.</sub>
