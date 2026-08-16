// Package mutate generates semantics-preserving evasions of an event.
//
// This is Ordeal's reason to exist. A conventional detection test asks "does the
// rule fire on this event?" Ordeal asks the adversary's question: "what is the
// cheapest change to this event that keeps the behaviour identical but stops the
// rule from firing?"
//
// Each mutator encodes a real, documented obfuscation technique that an attacker
// can apply for free on the command line (argument abbreviation, caret
// insertion, quote insertion, windash substitution, environment-variable
// indirection, and so on). The mutated command does the same thing on the host;
// only its surface form changes. If a rule stops matching after a mutation, the
// rule has an evasion gap — a real hole an operator would walk through.
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

// Variant is one mutated event plus the provenance of the change.
type Variant struct {
	Mutator string       // mutator name, e.g. "flag-abbreviation"
	Field   string       // the field whose value was mutated
	Before  string       // original field value
	After   string       // mutated field value
	Note    string       // human explanation of the technique
	Event   engine.Event // full event copy with the single field replaced
}

// Mutator transforms a single string field value into zero or more evasions.
// Returning no strings means the technique does not apply to this value.
type Mutator interface {
	Name() string
	// Describe is a one-line explanation shown in verbose output.
	Describe() string
	// Apply returns mutated forms of value, each paired with a short note.
	Apply(value string) []Result
}

// Result is a single mutated string and the note describing the technique used.
type Result struct {
	Value string
	Note  string
}

// Catalog is the default, ordered set of mutators.
func Catalog() []Mutator {
	return []Mutator{
		flagAbbreviation{},
		windashSubstitution{},
		caretInsertion{},
		quoteInsertion{},
		envIndirection{},
		forwardSlashPath{},
		trailingDot{},
		whitespacePadding{},
		caseFlip{},
	}
}

// Generate applies every mutator in the catalog to each named string field of
// base and returns all resulting event variants. base is never modified.
func Generate(base engine.Event, fields []string) []Variant {
	return GenerateWith(Catalog(), base, fields)
}

// GenerateWith is Generate with an explicit mutator set (used in tests).
func GenerateWith(mutators []Mutator, base engine.Event, fields []string) []Variant {
	var out []Variant
	for _, field := range fields {
		raw, ok := base[field]
		if !ok {
			continue
		}
		value, ok := raw.(string)
		if !ok || value == "" {
			continue
		}
		for _, m := range mutators {
			for _, r := range m.Apply(value) {
				if r.Value == value {
					continue // no-op mutation, skip
				}
				out = append(out, Variant{
					Mutator: m.Name(),
					Field:   field,
					Before:  value,
					After:   r.Value,
					Note:    r.Note,
					Event:   withField(base, field, r.Value),
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

// withField returns a shallow copy of base with one field replaced.
func withField(base engine.Event, field, value string) engine.Event {
	cp := make(engine.Event, len(base))
	for k, v := range base {
		cp[k] = v
	}
	cp[field] = value
	return cp
}

// --- Mutators ------------------------------------------------------------

// flagAbbreviation shortens well-known PowerShell / cmd flags to the shortest
// unambiguous prefix the interpreter still accepts. PowerShell resolves any
// unambiguous prefix, so "-EncodedCommand" runs identically as "-enc". Rules
// that match the long flag literally miss the short form.
type flagAbbreviation struct{}

func (flagAbbreviation) Name() string { return "flag-abbreviation" }
func (flagAbbreviation) Describe() string {
	return "Shorten PowerShell/cmd flags to an accepted prefix (-EncodedCommand -> -enc)"
}

// longFlag -> shortest commonly-accepted abbreviation.
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
	for long, short := range flagAbbrevMap {
		idx := strings.Index(lower, long)
		if idx < 0 {
			continue
		}
		mutated := value[:idx] + short + value[idx+len(long):]
		out = append(out, Result{
			Value: mutated,
			Note:  "abbreviated " + long + " to " + short,
		})
	}
	return out
}

// windashSubstitution swaps the ASCII hyphen flag prefix for one of the
// alternative dash characters the Windows argument parser accepts (/, en-dash,
// em-dash). Sigma models this as the |windash modifier; rules that omit it and
// match a literal "-flag" miss "/flag".
type windashSubstitution struct{}

func (windashSubstitution) Name() string { return "windash" }
func (windashSubstitution) Describe() string {
	return "Swap - flag prefix for an accepted alternative (/, en-dash, em-dash)"
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
		out = append(out, Result{
			Value: mutated,
			Note:  "replaced - flag prefix with " + alt.name,
		})
	}
	return out
}

// caretInsertion inserts cmd.exe's escape character (^) between characters of
// alphabetic tokens. cmd strips carets before execution, so "who^ami" runs
// "whoami". Rules matching the literal token miss the carated form.
type caretInsertion struct{}

func (caretInsertion) Name() string { return "caret-insertion" }
func (caretInsertion) Describe() string {
	return "Insert cmd.exe caret escapes inside tokens (whoami -> who^ami)"
}

var wordToken = regexp.MustCompile(`[A-Za-z]{4,}`)

func (caretInsertion) Apply(value string) []Result {
	mutated := wordToken.ReplaceAllStringFunc(value, func(tok string) string {
		mid := len(tok) / 2
		return tok[:mid] + "^" + tok[mid:]
	})
	if mutated == value {
		return nil
	}
	return []Result{{Value: mutated, Note: "inserted ^ escape characters inside tokens"}}
}

// quoteInsertion inserts empty double-quote pairs inside alphabetic tokens. Both
// cmd and PowerShell strip quotes during parsing, so pow""ershell executes
// powershell. Rules matching the literal token miss the split form.
type quoteInsertion struct{}

func (quoteInsertion) Name() string { return "quote-insertion" }
func (quoteInsertion) Describe() string {
	return `Insert empty quote pairs inside tokens (powershell -> pow""ershell)`
}

func (quoteInsertion) Apply(value string) []Result {
	mutated := wordToken.ReplaceAllStringFunc(value, func(tok string) string {
		mid := len(tok) / 2
		return tok[:mid] + `""` + tok[mid:]
	})
	if mutated == value {
		return nil
	}
	return []Result{{Value: mutated, Note: "inserted empty quote pairs inside tokens"}}
}

// envIndirection replaces well-known absolute path prefixes with the equivalent
// environment variable. %SystemRoot%\System32\cmd.exe and
// C:\Windows\System32\cmd.exe are the same file; rules matching the literal path
// miss the variable form.
type envIndirection struct{}

func (envIndirection) Name() string { return "env-indirection" }
func (envIndirection) Describe() string {
	return "Replace absolute path prefixes with environment variables (C:\\Windows -> %SystemRoot%)"
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
		out = append(out, Result{
			Value: mutated,
			Note:  "replaced " + p.literal + " with " + p.envvar,
		})
	}
	return out
}

// forwardSlashPath flips Windows backslashes to forward slashes. Many Windows
// APIs and interpreters accept C:/Windows/System32/cmd.exe. Rules that match a
// backslash path literally miss the forward-slash form.
type forwardSlashPath struct{}

func (forwardSlashPath) Name() string { return "forward-slash-path" }
func (forwardSlashPath) Describe() string {
	return "Flip \\ path separators to / (C:\\Windows -> C:/Windows)"
}

func (forwardSlashPath) Apply(value string) []Result {
	if !strings.Contains(value, `\`) {
		return nil
	}
	mutated := strings.ReplaceAll(value, `\`, "/")
	return []Result{{Value: mutated, Note: "replaced backslash separators with forward slashes"}}
}

// trailingDot appends a trailing dot to executable file names. Windows strips
// trailing dots and spaces from paths, so "certutil.exe." resolves to
// "certutil.exe". Rules using |endswith on the exact name miss it.
type trailingDot struct{}

func (trailingDot) Name() string { return "trailing-dot" }
func (trailingDot) Describe() string {
	return "Append a trailing dot to executable names (certutil.exe -> certutil.exe.)"
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
	return []Result{{Value: mutated, Note: "appended trailing dot to executable name"}}
}

// whitespacePadding replaces single spaces between arguments with runs of
// spaces. Interpreters collapse repeated whitespace; rules matching a literal
// single-space substring miss the padded form.
type whitespacePadding struct{}

func (whitespacePadding) Name() string { return "whitespace-padding" }
func (whitespacePadding) Describe() string {
	return "Expand single spaces to multiple (arg1 arg2 -> arg1   arg2)"
}

func (whitespacePadding) Apply(value string) []Result {
	if !strings.Contains(value, " ") {
		return nil
	}
	mutated := strings.ReplaceAll(value, " ", "   ")
	return []Result{{Value: mutated, Note: "padded single spaces to triple spaces"}}
}

// caseFlip inverts the case of every letter. Sigma matching is case-insensitive
// by default, so this is a no-op against a correct native evaluator — but many
// compiled backends (Elastic ES|QL, some SQL) are case-sensitive, and this
// mutation surfaces rules that will silently miss "PowerShell.exe" in
// production even though they pass locally.
type caseFlip struct{}

func (caseFlip) Name() string { return "case-flip" }
func (caseFlip) Describe() string {
	return "Invert letter case (powershell -> POWERSHELL); catches case-sensitive backends"
}

func (caseFlip) Apply(value string) []Result {
	mutated := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r - 32
		case r >= 'A' && r <= 'Z':
			return r + 32
		default:
			return r
		}
	}, value)
	if mutated == value {
		return nil
	}
	return []Result{{Value: mutated, Note: "inverted letter case"}}
}
