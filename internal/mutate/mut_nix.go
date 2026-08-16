package mutate

import (
	"regexp"
	"strings"
)

// This file holds the Linux/macOS shell-obfuscation mutators.
//
// A correctness constraint governs every one of them. Linux process telemetry
// (auditd EXECVE, Sysmon-for-Linux) records the post-expansion argv, so an
// evasion typed at an interactive shell — cat${IFS}/etc/passwd — is already
// resolved to separate arguments in the log and the rule still fires. These
// tricks only survive when the obfuscated text is a literal argument to an
// interpreter's -c payload: bash -c "...", sh -c "...", and the same shape in
// cron, systemd ExecStart, ssh commands, and webshell system() calls. That is
// also where the great majority of SigmaHQ Linux rules match.
//
// So every mutator here operates ONLY inside the quoted payload of a shell -c
// invocation, and only on unquoted separators/tokens (expansions inside quotes
// bypass word splitting). Applied to a bare command line they would generate
// strings no real log contains — false findings — so they return nil there.

var shellInterpreters = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ash": true, "ksh": true,
}

// dashCPayload matches a `-c` flag followed by a single- or double-quoted payload.
var dashCPayload = regexp.MustCompile(`(^|\s)-c\s+(['"])`)

// nixPayload locates the quoted payload of a shell -c invocation in value. It
// returns the interpreter's basename (bash, sh, zsh, ...), the byte range
// [start,end) of the payload text (excluding the quotes), and ok=false when value
// is not a shell -c invocation. Only then can shell obfuscation survive in the
// logged command line. The interpreter matters because $IFS and brace expansion
// behave differently under zsh.
func nixPayload(value string) (interp string, start, end int, ok bool) {
	head, _ := commandToken(value)
	base := head
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	base = strings.ToLower(base)
	if !shellInterpreters[base] {
		return "", 0, 0, false
	}
	loc := dashCPayload.FindStringSubmatchIndex(value)
	if loc == nil {
		return "", 0, 0, false
	}
	quote := value[loc[4]] // opening quote char (group 2)
	payloadStart := loc[5] // just past the opening quote
	closing := strings.IndexByte(value[payloadStart:], quote)
	if closing < 0 {
		return "", 0, 0, false // unterminated payload; leave it alone
	}
	payloadEnd := payloadStart + closing
	if payloadEnd <= payloadStart {
		return "", 0, 0, false // empty payload
	}
	return base, payloadStart, payloadEnd, true
}

// firstWord returns the first word of the payload (the command being run) and
// its byte range within payload, splitting on the first unquoted whitespace.
func firstWord(payload string) (word string, start, end int) {
	i := 0
	for i < len(payload) && (payload[i] == ' ' || payload[i] == '\t') {
		i++
	}
	j := i
	for j < len(payload) && payload[j] != ' ' && payload[j] != '\t' {
		j++
	}
	return payload[i:j], i, j
}

// unquotedSpaces returns the indices of top-level (unquoted) separator spaces in
// payload — the only spaces that may be rewritten, since a space inside quotes
// does not split words.
func unquotedSpaces(payload string) []int {
	var out []int
	var quote byte
	for i := 0; i < len(payload); i++ {
		c := payload[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == ' ':
			out = append(out, i)
		}
	}
	return out
}

// editPayload returns value with its -c payload replaced by newPayload.
func editPayload(value string, start, end int, newPayload string) string {
	return value[:start] + newPayload + value[end:]
}

// wordLetters matches a run of at least four ASCII letters — the unit the
// token-obfuscation mutators split, matching the Windows helpers.
var nixWordLetters = regexp.MustCompile(`[A-Za-z]{4,}`)

// mutateFirstWord applies fn to the command word of a shell -c payload and splices
// the result back into value. It returns "" when there is no payload, the word is
// opaque, or fn made no change.
func mutateFirstWord(value string, fn func(word string) string) string {
	_, start, end, ok := nixPayload(value)
	if !ok {
		return ""
	}
	payload := value[start:end]
	word, ws, we := firstWord(payload)
	if word == "" || isOpaque(word) {
		return ""
	}
	mutated := fn(word)
	if mutated == word {
		return ""
	}
	newPayload := payload[:ws] + mutated + payload[we:]
	return editPayload(value, start, end, newPayload)
}

// --- Mutators ------------------------------------------------------------

// nixQuoteInsertion splits the command word of a -c payload with empty quote
// pairs. Quote removal is the final step of shell expansion, so gr”ep is the
// single word grep. Holds on bash, dash, and zsh.
type nixQuoteInsertion struct{}

func (nixQuoteInsertion) Name() string          { return "sh-quote-insertion" }
func (nixQuoteInsertion) Technique() string     { return "T1027" }
func (nixQuoteInsertion) Platforms() []Platform { return []Platform{Linux, MacOS} }
func (nixQuoteInsertion) Describe() string {
	return `Split a token in a shell -c payload with empty quotes (grep -> gr''ep)`
}
func (nixQuoteInsertion) Remediation() string {
	return "Strip paired and empty quotes at ingest before matching; or use |re allowing ['\"]* between keyword characters, and alert on empty quote pairs as a signal in their own right."
}
func (nixQuoteInsertion) Apply(value string) []Result {
	out := mutateFirstWord(value, func(w string) string {
		return nixWordLetters.ReplaceAllStringFunc(w, func(run string) string {
			mid := len(run) / 2
			return run[:mid] + "''" + run[mid:]
		})
	})
	if out == "" {
		return nil
	}
	return []Result{{Value: out, Note: "inserted empty quote pairs into the -c payload command word"}}
}

// nixBackslashEscape backslash-escapes letters of the command word. An unquoted
// backslash before an ordinary character preserves the character itself, so \c\a\t
// is cat. Holds on bash, dash, and zsh.
type nixBackslashEscape struct{}

func (nixBackslashEscape) Name() string          { return "sh-backslash-escape" }
func (nixBackslashEscape) Technique() string     { return "T1027" }
func (nixBackslashEscape) Platforms() []Platform { return []Platform{Linux, MacOS} }
func (nixBackslashEscape) Describe() string {
	return `Backslash-escape letters in a shell -c payload token (cat -> \c\at)`
}
func (nixBackslashEscape) Remediation() string {
	return "Delete backslashes preceding alphanumerics at ingest; or use |re allowing \\\\? between keyword characters, and treat repeated escaping of non-special characters as an obfuscation signal."
}

// forbiddenEscape are letters whose backslash form is a C escape (\n \t etc.),
// which would change the token; never escape these.
const forbiddenEscape = "abefnrtv"

func (nixBackslashEscape) Apply(value string) []Result {
	out := mutateFirstWord(value, func(w string) string {
		var b strings.Builder
		changed := false
		for i := 0; i < len(w); i++ {
			c := w[i]
			if c >= 'a' && c <= 'z' && !strings.ContainsRune(forbiddenEscape, rune(c)) {
				b.WriteByte('\\')
				changed = true
			}
			b.WriteByte(c)
		}
		if !changed {
			return w
		}
		return b.String()
	})
	if out == "" {
		return nil
	}
	return []Result{{Value: out, Note: "backslash-escaped letters in the -c payload command word"}}
}

// nixEmptyExpansion inserts an unset-parameter expansion into the command word.
// ${Z} with Z unset expands to nothing and is removed, so cu${Z}rl is curl. Holds
// on bash, dash, and zsh.
type nixEmptyExpansion struct{}

func (nixEmptyExpansion) Name() string          { return "sh-empty-expansion" }
func (nixEmptyExpansion) Technique() string     { return "T1027" }
func (nixEmptyExpansion) Platforms() []Platform { return []Platform{Linux, MacOS} }
func (nixEmptyExpansion) Describe() string {
	return "Insert an empty ${unset} expansion into a shell -c payload token (curl -> cu${Z}rl)"
}
func (nixEmptyExpansion) Remediation() string {
	return "Remove ${...} that resolve empty and $@/$* at ingest; alert on $ appearing inside otherwise-alphabetic tokens."
}
func (nixEmptyExpansion) Apply(value string) []Result {
	out := mutateFirstWord(value, func(w string) string {
		m := nixWordLetters.FindStringIndex(w)
		if m == nil {
			return w
		}
		mid := m[0] + (m[1]-m[0])/2
		return w[:mid] + "${Z}" + w[mid:]
	})
	if out == "" {
		return nil
	}
	return []Result{{Value: out, Note: "inserted an empty ${unset} expansion into the -c payload command word"}}
}

// nixAnsiCQuote wraps the command word in ANSI-C quoting. $'string' with no escape
// sequences is byte-identical to the literal. Holds on bash and zsh; not dash.
type nixAnsiCQuote struct{}

func (nixAnsiCQuote) Name() string          { return "sh-ansi-c-quote" }
func (nixAnsiCQuote) Technique() string     { return "T1027" }
func (nixAnsiCQuote) Platforms() []Platform { return []Platform{Linux, MacOS} }
func (nixAnsiCQuote) Describe() string {
	return "Wrap a shell -c payload token in ANSI-C quoting (nc -> $'nc')"
}
func (nixAnsiCQuote) Remediation() string {
	return "Decode $'...' including \\xNN escapes at ingest; use |re tolerating an optional \\$?' prefix on keywords."
}
func (nixAnsiCQuote) Apply(value string) []Result {
	out := mutateFirstWord(value, func(w string) string {
		if strings.ContainsAny(w, `'"$\`) {
			return w // keep it simple and provably identical
		}
		return "$'" + w + "'"
	})
	if out == "" {
		return nil
	}
	return []Result{{Value: out, Note: "wrapped the -c payload command word in ANSI-C quoting"}}
}

// nixLineContinuation inserts a backslash-newline into the command word. The pair
// is removed before tokenization, rejoining the word. Holds on bash, dash, zsh.
type nixLineContinuation struct{}

func (nixLineContinuation) Name() string          { return "sh-line-continuation" }
func (nixLineContinuation) Technique() string     { return "T1027" }
func (nixLineContinuation) Platforms() []Platform { return []Platform{Linux, MacOS} }
func (nixLineContinuation) Describe() string {
	return "Insert a backslash-newline into a shell -c payload token (wget -> wg\\<newline>et)"
}
func (nixLineContinuation) Remediation() string {
	return "Strip backslash-newline sequences at ingest and decode auditd hex-encoded argv before matching."
}
func (nixLineContinuation) Apply(value string) []Result {
	out := mutateFirstWord(value, func(w string) string {
		m := nixWordLetters.FindStringIndex(w)
		if m == nil {
			return w
		}
		mid := m[0] + (m[1]-m[0])/2
		return w[:mid] + "\\\n" + w[mid:]
	})
	if out == "" {
		return nil
	}
	return []Result{{Value: out, Note: "inserted a backslash-newline into the -c payload command word"}}
}

// nixTrailingComment appends an unquoted comment to the payload. A # starting a
// word comments to end of line, leaving the executed words unchanged.
type nixTrailingComment struct{}

func (nixTrailingComment) Name() string          { return "sh-trailing-comment" }
func (nixTrailingComment) Technique() string     { return "T1027" }
func (nixTrailingComment) Platforms() []Platform { return []Platform{Linux, MacOS} }
func (nixTrailingComment) Describe() string {
	return "Append an unquoted comment to a shell -c payload (id -u -> id -u # ...)"
}
func (nixTrailingComment) Remediation() string {
	return "Prefer |contains over |endswith and strip trailing comments at ingest."
}
func (nixTrailingComment) Apply(value string) []Result {
	_, start, end, ok := nixPayload(value)
	if !ok {
		return nil
	}
	payload := value[start:end]
	if strings.Contains(payload, "#") {
		return nil
	}
	newPayload := payload + " # ordeal"
	return []Result{{Value: editPayload(value, start, end, newPayload), Note: "appended an unquoted comment to the -c payload"}}
}

// nixIFSSubstitution replaces the first unquoted separator space in the payload
// with ${IFS}. Unquoted expansion of IFS (default space/tab/newline) is a field
// separator, so cat${IFS}/etc/shadow runs cat with the file argument. Works on
// bash and dash; NOT on zsh (no word splitting on unquoted expansion), so Linux
// only.
type nixIFSSubstitution struct{}

func (nixIFSSubstitution) Name() string      { return "sh-ifs-substitution" }
func (nixIFSSubstitution) Technique() string { return "T1027" }

// $IFS word-splitting works in every POSIX shell except zsh. It fires here only
// inside a -c payload, and on macOS that interpreter is bash (both /bin/sh and
// /bin/bash are bash 3.2), so it holds on Linux and macOS alike — but not when
// the payload interpreter is zsh, which the Apply method excludes.
func (nixIFSSubstitution) Platforms() []Platform { return []Platform{Linux, MacOS} }
func (nixIFSSubstitution) Describe() string {
	return "Replace a separator space in a shell -c payload with ${IFS} (cat /etc/shadow -> cat${IFS}/etc/shadow)"
}
func (nixIFSSubstitution) Remediation() string {
	return "Expand ${IFS}/$IFS to a space at ingest and match the resolved argv; replace the spaced literal with |contains|all on the separated tokens, and hunt the literal ${IFS}."
}
func (nixIFSSubstitution) Apply(value string) []Result {
	interp, start, end, ok := nixPayload(value)
	if !ok || interp == "zsh" {
		return nil // zsh does not word-split unquoted expansions
	}
	payload := value[start:end]
	spaces := unquotedSpaces(payload)
	if len(spaces) == 0 {
		return nil
	}
	i := spaces[0]
	newPayload := payload[:i] + "${IFS}" + payload[i+1:]
	return []Result{{Value: editPayload(value, start, end, newPayload), Note: "replaced a separator space with ${IFS}"}}
}

// nixBraceExpansion rewrites the payload's top-level word list as a brace list.
// Brace expansion is purely textual and first, producing the identical word list.
// bash only — not POSIX (dash), and zsh parses a leading brace as a block.
type nixBraceExpansion struct{}

func (nixBraceExpansion) Name() string      { return "sh-brace-expansion" }
func (nixBraceExpansion) Technique() string { return "T1027" }

// Command-position brace expansion works in bash but not dash (not POSIX) or zsh
// (parses a leading brace as a block). It fires only when the -c interpreter is
// literally bash, which is safe on both Linux and macOS.
func (nixBraceExpansion) Platforms() []Platform { return []Platform{Linux, MacOS} }
func (nixBraceExpansion) Describe() string {
	return "Rewrite a shell -c payload as a brace list (cat /etc/passwd -> {cat,/etc/passwd})"
}
func (nixBraceExpansion) Remediation() string {
	return "Brace expansion never reaches argv — match syscall-level argv instead of the shell string; where only the string exists, use |contains|all on the tokens plus |re for \\{[^ ]+,."
}
func (nixBraceExpansion) Apply(value string) []Result {
	interp, start, end, ok := nixPayload(value)
	if !ok || interp != "bash" {
		return nil // only bash performs command-position brace expansion
	}
	payload := value[start:end]
	// Only handle a simple, quote-free, top-level space-separated word list, so
	// the brace rewrite is provably equivalent.
	if strings.ContainsAny(payload, `'"{}`) {
		return nil
	}
	fields := strings.Fields(payload)
	if len(fields) < 2 {
		return nil
	}
	newPayload := "{" + strings.Join(fields, ",") + "}"
	return []Result{{Value: editPayload(value, start, end, newPayload), Note: "rewrote the -c payload as a brace list"}}
}

// nixZshForcedSplit is the zsh-native counterpart to sh-ifs-substitution. zsh
// does not word-split unquoted expansions, but ${=spec} forces splitting for that
// expansion, so cat${=IFS}/etc/passwd runs cat with the file argument. It is a
// syntax error under bash/sh, so it fires only when the -c interpreter is zsh.
type nixZshForcedSplit struct{}

func (nixZshForcedSplit) Name() string          { return "zsh-forced-split" }
func (nixZshForcedSplit) Technique() string     { return "T1027" }
func (nixZshForcedSplit) Platforms() []Platform { return []Platform{Linux, MacOS} }
func (nixZshForcedSplit) Describe() string {
	return "Replace a separator space in a zsh -c payload with ${=IFS} (cat /etc/passwd -> cat${=IFS}/etc/passwd)"
}
func (nixZshForcedSplit) Remediation() string {
	return "Alert on ${= as a zsh-specific split marker; expand it at ingest and do not assume whitespace separates the binary from its arguments."
}
func (nixZshForcedSplit) Apply(value string) []Result {
	interp, start, end, ok := nixPayload(value)
	if !ok || interp != "zsh" {
		return nil
	}
	payload := value[start:end]
	spaces := unquotedSpaces(payload)
	if len(spaces) == 0 {
		return nil
	}
	i := spaces[0]
	newPayload := payload[:i] + "${=IFS}" + payload[i+1:]
	return []Result{{Value: editPayload(value, start, end, newPayload), Note: "replaced a separator space with the zsh ${=IFS} split"}}
}

func init() {
	register(
		nixQuoteInsertion{},
		nixBackslashEscape{},
		nixEmptyExpansion{},
		nixAnsiCQuote{},
		nixLineContinuation{},
		nixTrailingComment{},
		nixIFSSubstitution{},
		nixBraceExpansion{},
		nixZshForcedSplit{},
	)
}
