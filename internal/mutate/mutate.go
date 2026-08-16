// Package mutate generates semantics-preserving evasions of an event.
//
// This is Ordeal's reason to exist. A conventional detection test asks "does the
// rule fire on this event?" Ordeal asks the adversary's question: "what is the
// cheapest change to this event that keeps the behaviour identical but stops the
// rule from firing?"
//
// Each mutator encodes a real, documented obfuscation technique that an attacker
// can apply for free — argument abbreviation, caret and quote insertion, dash
// substitution, environment-variable indirection, and so on. The mutated command
// does the same thing on the host; only its surface form changes. If a rule stops
// matching after a mutation, the rule has an evasion gap — a real hole an operator
// would walk through.
//
// Two principles keep findings honest rather than noisy:
//
//   - Only attacker-controlled fields are mutated. A field such as CommandLine
//     reflects attacker input verbatim; a field such as Image is resolved by the
//     kernel and is not something an attacker can obfuscate at the surface, so
//     mutating it would model an evasion that cannot happen. See FieldClass.
//   - Opaque payload tokens are never corrupted. Inserting an escape character
//     into a base64 blob or flipping its case would change what executes, so
//     token- and case-level mutators skip payload-shaped tokens.
//
// Mutators only GENERATE variants. They never evaluate rules; the runner does
// that. This keeps the catalog pure, testable, and free of engine dependencies.
package mutate

import (
	"regexp"
	"sort"
	"strings"

	"github.com/principlebreach/ordeal/internal/engine"
)

// FieldClass describes how much control an attacker has over a field's value,
// which decides whether the field is a legitimate mutation target.
type FieldClass int

const (
	// ClassCommand is attacker-controlled command text (CommandLine,
	// ParentCommandLine, script blocks). These are mutated.
	ClassCommand FieldClass = iota
	// ClassPath is a system-resolved path or image (Image, ParentImage,
	// TargetFilename). The kernel logs the canonical form regardless of how the
	// attacker typed it, so surface mutation here is not a realistic evasion and
	// is skipped.
	ClassPath
	// ClassGeneric is anything else (hashes, ports, users). Not mutated.
	ClassGeneric
)

var (
	commandFieldHints = []string{"commandline", "command_line", "cmdline", "arguments", "args", "scriptblock", "script_block"}
	pathFieldHints    = []string{"image", "path", "targetfilename", "target_filename", "directory", "parentimage"}
)

// Classify maps a Sigma field name to a FieldClass using name heuristics.
func Classify(field string) FieldClass {
	f := strings.ToLower(field)
	for _, h := range commandFieldHints {
		if strings.Contains(f, h) {
			return ClassCommand
		}
	}
	for _, h := range pathFieldHints {
		if strings.Contains(f, h) {
			return ClassPath
		}
	}
	return ClassGeneric
}

// Variant is one mutated event plus the provenance of the change.
type Variant struct {
	Mutator     string       // mutator name, e.g. "flag-abbreviation"
	Field       string       // the field whose value was mutated
	Before      string       // original field value
	After       string       // mutated field value
	Note        string       // human explanation of the technique
	Remediation string       // how to harden a rule against this evasion
	Event       engine.Event // full event copy with the single field replaced
}

// Mutator transforms a single command-string value into zero or more evasions.
// Returning no results means the technique does not apply to this value.
type Mutator interface {
	// Name is the stable identifier used on the command line and in reports.
	Name() string
	// Technique is the MITRE ATT&CK id or Sigma modifier the mutator models.
	Technique() string
	// Describe is a one-line explanation of the transform.
	Describe() string
	// Remediation is the one-line blue-team fix: how to harden a Sigma rule so
	// it catches this evasion. Printed next to a finding.
	Remediation() string
	// Apply returns mutated forms of value, each with a short note.
	Apply(value string) []Result
}

// Result is a single mutated string and the note describing the technique used.
type Result struct {
	Value string
	Note  string
}

// registry holds every mutator, populated by register() in package init. New
// mutators self-register from their own file, so adding one never touches this
// file or Catalog.
var registry []Mutator

// register adds mutators to the catalog. Call it from an init() function.
func register(mutators ...Mutator) {
	registry = append(registry, mutators...)
}

func init() {
	register(
		flagAbbreviation{},
		windashSubstitution{},
		caretInsertion{},
		powershellTick{},
		quoteInsertion{},
		envIndirection{},
		forwardSlashPath{},
		trailingDot{},
		whitespacePadding{},
		caseFlip{},
	)
}

// Catalog returns every registered mutator, ordered by name for determinism.
func Catalog() []Mutator {
	out := make([]Mutator, len(registry))
	copy(out, registry)
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// Options selects a subset of the catalog by mutator name.
type Options struct {
	Only []string // if non-empty, restrict to these mutator names
	Skip []string // exclude these mutator names
}

// Select returns the catalog filtered by opts, preserving catalog order.
func Select(opts Options) []Mutator {
	only := set(opts.Only)
	skip := set(opts.Skip)
	var out []Mutator
	for _, m := range Catalog() {
		if len(only) > 0 && !only[m.Name()] {
			continue
		}
		if skip[m.Name()] {
			continue
		}
		out = append(out, m)
	}
	return out
}

func set(xs []string) map[string]bool {
	if len(xs) == 0 {
		return nil
	}
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// Generate applies the full catalog to each attacker-controlled string field of
// base and returns all resulting event variants. base is never modified.
func Generate(base engine.Event, fields []string) []Variant {
	return GenerateWith(Catalog(), base, fields)
}

// GenerateWith is Generate with an explicit mutator set.
func GenerateWith(mutators []Mutator, base engine.Event, fields []string) []Variant {
	var out []Variant
	for _, field := range fields {
		if Classify(field) != ClassCommand {
			continue // only attacker-controlled command text is a realistic target
		}
		value, ok := base[field].(string)
		if !ok || value == "" {
			continue
		}
		for _, m := range mutators {
			for _, r := range m.Apply(value) {
				if r.Value == value {
					continue // no-op mutation
				}
				out = append(out, Variant{
					Mutator:     m.Name(),
					Field:       field,
					Before:      value,
					After:       r.Value,
					Note:        r.Note,
					Remediation: m.Remediation(),
					Event:       withField(base, field, r.Value),
				})
			}
		}
	}
	return out
}

// StringFields returns the field names in event whose values are non-empty
// strings, sorted for deterministic output.
func StringFields(event engine.Event) []string {
	var fields []string
	for k, v := range event {
		if s, ok := v.(string); ok && s != "" {
			fields = append(fields, k)
		}
	}
	sort.Strings(fields)
	return fields
}

// MutableFields returns the subset of StringFields that are attacker-controlled
// command text and therefore eligible for mutation.
func MutableFields(event engine.Event) []string {
	var fields []string
	for _, f := range StringFields(event) {
		if Classify(f) == ClassCommand {
			fields = append(fields, f)
		}
	}
	return fields
}

// withField returns a shallow copy of base with one field replaced.
func withField(base engine.Event, field, value string) engine.Event {
	cp := make(engine.Event, len(base))
	for k, v := range base {
		cp[k] = v
	}
	cp[field] = value
	return cp
}

// --- shared token helpers ------------------------------------------------

// opaqueToken matches payload-shaped tokens (long base64/hex blobs) that must
// never be reshaped or case-flipped, because doing so changes what executes.
var opaqueToken = regexp.MustCompile(`^[A-Za-z0-9+/=_-]{12,}$`)

func isOpaque(tok string) bool {
	if !opaqueToken.MatchString(tok) {
		return false
	}
	// A token with both letters and digits, or containing base64 padding, is
	// almost certainly an encoded payload rather than a word like a long flag.
	hasDigit := strings.ContainsAny(tok, "0123456789")
	hasPad := strings.ContainsAny(tok, "+/=")
	return hasDigit || hasPad || len(tok) >= 20
}

// commandToken returns the first whitespace-delimited token of value (the
// executable or command word) and the remainder, so token-obfuscation mutators
// can reshape the command name without touching argument payloads.
func commandToken(value string) (head, rest string) {
	i := strings.IndexByte(value, ' ')
	if i < 0 {
		return value, ""
	}
	return value[:i], value[i:]
}

// letters matches a run of alphabetic characters, the unit token mutators split.
var letters = regexp.MustCompile(`[A-Za-z]{4,}`)

// insertInWord inserts sep into the middle of each letter-run of tok.
func insertInWord(tok, sep string) string {
	return letters.ReplaceAllStringFunc(tok, func(w string) string {
		mid := len(w) / 2
		return w[:mid] + sep + w[mid:]
	})
}

// --- Mutators ------------------------------------------------------------

// flagAbbreviation shortens well-known PowerShell / cmd flags to the shortest
// prefix the interpreter still accepts. PowerShell resolves any unambiguous
// prefix, so "-EncodedCommand" runs identically as "-enc". Rules that match the
// long flag literally miss the short form.
type flagAbbreviation struct{}

func (flagAbbreviation) Name() string      { return "flag-abbreviation" }
func (flagAbbreviation) Technique() string { return "T1059.001" }
func (flagAbbreviation) Describe() string {
	return "Shorten PowerShell/cmd flags to an accepted prefix (-EncodedCommand -> -enc)"
}
func (flagAbbreviation) Remediation() string {
	return "Match abbreviated forms too, e.g. a regex like -e(n(c(o...)?)?)? or key on a stable prefix."
}

var flagAbbrevMap = map[string]string{
	"-encodedcommand":  "-enc",
	"-executionpolicy": "-ep",
	"-noprofile":       "-nop",
	"-windowstyle":     "-w",
	"-noninteractive":  "-noni",
	"-command":         "-c",
	"-file":            "-f",
	"-version":         "-v",
	"-nologo":          "-nol",
}

func (flagAbbreviation) Apply(value string) []Result {
	var out []Result
	lower := strings.ToLower(value)
	// Deterministic order: iterate a sorted key list, not the map.
	keys := make([]string, 0, len(flagAbbrevMap))
	for k := range flagAbbrevMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, long := range keys {
		idx := strings.Index(lower, long)
		if idx < 0 {
			continue
		}
		short := flagAbbrevMap[long]
		mutated := value[:idx] + short + value[idx+len(long):]
		out = append(out, Result{Value: mutated, Note: "abbreviated " + long + " to " + short})
	}
	return out
}

// windashSubstitution swaps the ASCII hyphen flag prefix for an alternative dash
// the Windows argument parser accepts (/, en-dash, em-dash). Sigma models this as
// the |windash modifier; rules that omit it and match a literal "-flag" miss
// "/flag".
type windashSubstitution struct{}

func (windashSubstitution) Name() string      { return "windash" }
func (windashSubstitution) Technique() string { return "Sigma windash" }
func (windashSubstitution) Describe() string {
	return "Swap the - flag prefix for an accepted alternative (/, en-dash, em-dash)"
}
func (windashSubstitution) Remediation() string {
	return "Use the |windash modifier, or a regex character class such as [-/] on the flag prefix."
}

var flagToken = regexp.MustCompile(`(^|\s)-([A-Za-z])`)

func (windashSubstitution) Apply(value string) []Result {
	if !flagToken.MatchString(value) {
		return nil
	}
	var out []Result
	for _, alt := range []struct{ ch, name string }{
		{"/", "forward slash"},
		{"\u2013", "en-dash"},
		{"\u2014", "em-dash"},
	} {
		mutated := flagToken.ReplaceAllString(value, "${1}"+alt.ch+"${2}")
		out = append(out, Result{Value: mutated, Note: "replaced - flag prefix with " + alt.name})
	}
	return out
}

// caretInsertion inserts cmd.exe's escape character (^) into the command token.
// cmd strips carets before execution, so "who^ami" runs "whoami". Rules matching
// the command word in the command line miss the carated form.
type caretInsertion struct{}

func (caretInsertion) Name() string      { return "caret-insertion" }
func (caretInsertion) Technique() string { return "T1027" }
func (caretInsertion) Describe() string {
	return "Insert cmd.exe caret escapes into the command token (whoami -> who^ami)"
}
func (caretInsertion) Remediation() string {
	return "Carets survive in the logged command line; key on the Image field or strip ^ before matching."
}

func (caretInsertion) Apply(value string) []Result {
	head, rest := commandToken(value)
	if isOpaque(head) {
		return nil
	}
	mutated := insertInWord(head, "^") + rest
	if mutated == value {
		return nil
	}
	return []Result{{Value: mutated, Note: "inserted ^ escapes into the command token"}}
}

// powershellTick inserts PowerShell's backtick escape into the command token.
// The backtick is a no-op before ordinary characters, so `p“owershell` runs
// powershell. Distinct from the cmd caret.
type powershellTick struct{}

func (powershellTick) Name() string      { return "powershell-tick" }
func (powershellTick) Technique() string { return "T1059.001" }
func (powershellTick) Describe() string {
	return "Insert PowerShell backtick escapes into the command token (iex -> i`ex)"
}
func (powershellTick) Remediation() string {
	return "Backticks survive in the command line; key on Image/ParentImage or strip ` before matching."
}

func (powershellTick) Apply(value string) []Result {
	head, rest := commandToken(value)
	if isOpaque(head) {
		return nil
	}
	mutated := insertInWord(head, "`") + rest
	if mutated == value {
		return nil
	}
	return []Result{{Value: mutated, Note: "inserted backtick escapes into the command token"}}
}

// quoteInsertion inserts empty double-quote pairs into the command token. Both
// cmd and PowerShell strip quotes during parsing, so pow""ershell executes
// powershell. Rules matching the command word miss the split form.
type quoteInsertion struct{}

func (quoteInsertion) Name() string      { return "quote-insertion" }
func (quoteInsertion) Technique() string { return "T1027" }
func (quoteInsertion) Describe() string {
	return `Insert empty quote pairs into the command token (powershell -> pow""ershell)`
}
func (quoteInsertion) Remediation() string {
	return "Quotes survive in the command line; key on the Image field or strip quotes before matching."
}

func (quoteInsertion) Apply(value string) []Result {
	head, rest := commandToken(value)
	if isOpaque(head) {
		return nil
	}
	mutated := insertInWord(head, `""`) + rest
	if mutated == value {
		return nil
	}
	return []Result{{Value: mutated, Note: "inserted empty quote pairs into the command token"}}
}

// envIndirection replaces a well-known absolute path prefix in the command line
// with the equivalent environment variable. %SystemRoot%\System32\cmd.exe and
// C:\Windows\System32\cmd.exe resolve to the same file; rules matching the
// literal path miss the variable form.
type envIndirection struct{}

func (envIndirection) Name() string      { return "env-indirection" }
func (envIndirection) Technique() string { return "T1027" }
func (envIndirection) Describe() string {
	return "Replace an absolute path prefix with an environment variable (C:\\Windows -> %SystemRoot%)"
}
func (envIndirection) Remediation() string {
	return "Also match the %SystemRoot%/%ProgramFiles% forms, or key on the resolved Image field."
}

var envPrefixes = []struct{ literal, envvar string }{
	{`C:\Windows\System32`, `%SystemRoot%\System32`},
	{`C:\Windows`, `%SystemRoot%`},
	{`C:\Program Files`, `%ProgramFiles%`},
	{`C:\Users`, `%SystemDrive%\Users`},
}

func (envIndirection) Apply(value string) []Result {
	var out []Result
	lower := strings.ToLower(value)
	for _, p := range envPrefixes {
		idx := strings.Index(lower, strings.ToLower(p.literal))
		if idx < 0 {
			continue
		}
		mutated := value[:idx] + p.envvar + value[idx+len(p.literal):]
		out = append(out, Result{Value: mutated, Note: "replaced " + p.literal + " with " + p.envvar})
	}
	return out
}

// forwardSlashPath flips Windows backslashes to forward slashes. Many Windows
// APIs and interpreters accept C:/Windows/System32/cmd.exe. Rules that match a
// backslash path literally miss the forward-slash form.
type forwardSlashPath struct{}

func (forwardSlashPath) Name() string      { return "forward-slash-path" }
func (forwardSlashPath) Technique() string { return "T1027" }
func (forwardSlashPath) Describe() string {
	return "Flip \\ path separators to / (C:\\Windows -> C:/Windows)"
}
func (forwardSlashPath) Remediation() string {
	return "Match both separators with a regex like [\\\\/], or key on the normalized Image field."
}

func (forwardSlashPath) Apply(value string) []Result {
	if !strings.Contains(value, `\`) {
		return nil
	}
	mutated := strings.ReplaceAll(value, `\`, "/")
	return []Result{{Value: mutated, Note: "replaced backslash separators with forward slashes"}}
}

// trailingDot appends a trailing dot to an executable name in the command line.
// Windows strips trailing dots and spaces from paths, so "certutil.exe." resolves
// to "certutil.exe". Rules using |endswith on the exact name miss it.
type trailingDot struct{}

func (trailingDot) Name() string      { return "trailing-dot" }
func (trailingDot) Technique() string { return "T1036" }
func (trailingDot) Describe() string {
	return "Append a trailing dot to an executable name (certutil.exe -> certutil.exe.)"
}
func (trailingDot) Remediation() string {
	return "Match on the executable stem with |contains rather than an exact |endswith boundary, or use Image."
}

var exeName = regexp.MustCompile(`(?i)([A-Za-z0-9_]+\.exe)`)

func (trailingDot) Apply(value string) []Result {
	if !exeName.MatchString(value) {
		return nil
	}
	mutated := exeName.ReplaceAllString(value, "$1.")
	if mutated == value {
		return nil
	}
	return []Result{{Value: mutated, Note: "appended a trailing dot to the executable name"}}
}

// whitespacePadding expands single spaces between arguments into runs of spaces.
// Interpreters collapse repeated whitespace; rules matching a literal
// single-space substring miss the padded form.
type whitespacePadding struct{}

func (whitespacePadding) Name() string      { return "whitespace-padding" }
func (whitespacePadding) Technique() string { return "T1027" }
func (whitespacePadding) Describe() string {
	return "Expand single spaces into runs (arg1 arg2 -> arg1   arg2)"
}
func (whitespacePadding) Remediation() string {
	return "Match individual tokens with separate |contains terms rather than a fixed single-space sequence."
}

func (whitespacePadding) Apply(value string) []Result {
	if !strings.Contains(value, " ") {
		return nil
	}
	mutated := strings.ReplaceAll(value, " ", "   ")
	return []Result{{Value: mutated, Note: "padded single spaces into triple spaces"}}
}

// caseFlip inverts the case of non-opaque tokens. Sigma matching is
// case-insensitive by default, so this is a no-op against a correct native
// evaluator — but many compiled backends (Elastic ES|QL, some SQL) are
// case-sensitive, and this surfaces rules that will silently miss "PowerShell.exe"
// in production even though they pass locally. Opaque payload tokens are left
// untouched, since flipping a base64 blob would change what executes.
type caseFlip struct{}

func (caseFlip) Name() string      { return "case-flip" }
func (caseFlip) Technique() string { return "backend case-sensitivity" }
func (caseFlip) Describe() string {
	return "Invert letter case of non-payload tokens (powershell -> POWERSHELL)"
}
func (caseFlip) Remediation() string {
	return "Ensure the backend comparison is case-insensitive (Sigma's default) or lowercase the field first."
}

func (caseFlip) Apply(value string) []Result {
	toks := strings.Split(value, " ")
	changed := false
	for i, t := range toks {
		if isOpaque(t) {
			continue
		}
		flipped := flipCase(t)
		if flipped != t {
			changed = true
		}
		toks[i] = flipped
	}
	if !changed {
		return nil
	}
	return []Result{{Value: strings.Join(toks, " "), Note: "inverted case of non-payload tokens"}}
}

func flipCase(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r - 32
		case r >= 'A' && r <= 'Z':
			return r + 32
		default:
			return r
		}
	}, s)
}
