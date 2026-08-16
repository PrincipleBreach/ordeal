package mutate

import (
	"regexp"
	"sort"
	"strings"
)

// This file holds mutators that exploit PowerShell's *resolvers* rather than its
// escaping rules. The engine resolves three things by name before it ever runs
// code — commands, .NET types, and members — and each resolver accepts more than
// one spelling of the same name. A rule that matches the canonical spelling in
// CommandLine or in a 4104 script block misses every other spelling, because
// neither log normalizes any of them: the logged text is what the attacker typed.
//
//   - the command resolver maps an alias to its cmdlet (case-insensitively),
//   - the type resolver retries a bare type name with "System." prepended, so
//     [Net.WebClient] and [System.Net.WebClient] are the same type,
//   - member access takes a quoted member name and resolves it identically to
//     the bare-word form.
//
// All three transforms are compile-time-identical, not runtime tricks: the
// parsed AST binds to the same command, type, and method.

// --- shared PowerShell surface helpers -----------------------------------

// psrQuoteMask marks every byte of value that lies inside a quoted string,
// including the quote characters themselves. Substituting inside a string
// literal would rewrite data rather than code, which is not semantics
// preserving, so every mutator in this file consults the mask first.
//
// The scan follows PowerShell's own rules closely enough to stay conservative:
// a backtick escapes the next character outside a string and inside a
// double-quoted string, and a doubled quote inside a string re-opens it
// immediately, which leaves the whole span marked either way.
func psrQuoteMask(value string) []bool {
	mask := make([]bool, len(value))
	var quote byte // 0 when outside a string
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case quote == 0:
			if c == '`' && i+1 < len(value) {
				i++ // escaped character, never a string delimiter
				continue
			}
			if c == '\'' || c == '"' {
				quote = c
				mask[i] = true
			}
		case quote == '"' && c == '`' && i+1 < len(value):
			mask[i] = true
			i++
			mask[i] = true
		case c == quote:
			mask[i] = true
			quote = 0
		default:
			mask[i] = true
		}
	}
	return mask
}

// psrAtCommandPosition reports whether a token starting at idx sits in command
// position: the first token of the value, or the first token after an unquoted
// pipeline or statement separator. Only there does PowerShell resolve a bare
// word through the command resolver, which is what makes an alias equivalent.
//
// afterPipe additionally reports that the separator was a pipe. That matters for
// aliases whose spelling collides with a language keyword — after a pipe the
// word is unambiguously a command, at statement start it would parse as the
// keyword instead.
func psrAtCommandPosition(value string, quoted []bool, idx int) (ok, afterPipe bool) {
	for i := idx - 1; i >= 0; i-- {
		if quoted[i] {
			return false, false
		}
		switch value[i] {
		case ' ', '\t':
			continue
		case '|':
			return true, true
		case ';', '&', '(', '{', '\n', '\r':
			return true, false
		default:
			return false, false
		}
	}
	return true, false // start of the value
}

// psrSplice replaces each span [start,end) of value with repl. Spans must be
// sorted ascending and must not overlap.
func psrSplice(value string, spans [][2]int, repl string) string {
	var b strings.Builder
	prev := 0
	for _, sp := range spans {
		b.WriteString(value[prev:sp[0]])
		b.WriteString(repl)
		prev = sp[1]
	}
	b.WriteString(value[prev:])
	return b.String()
}

func init() {
	register(
		cmdletAlias{},
		namespaceShorten{},
		memberNameExpression{},
	)
}

// --- cmdlet-alias ---------------------------------------------------------

// cmdletAlias replaces a cmdlet's Verb-Noun name with a built-in alias. The
// command resolver looks up aliases and cmdlets in the same pass, so "iex" and
// "Invoke-Expression" bind to the identical command with identical parameter
// binding — but 4104 script-block logs record the alias verbatim, so a rule
// listing only the long name never fires.
type cmdletAlias struct{}

func (cmdletAlias) Name() string      { return "cmdlet-alias" }
func (cmdletAlias) Technique() string { return "T1027.010" }
func (cmdletAlias) Describe() string {
	return "Replace a cmdlet Verb-Noun with a built-in alias (Invoke-Expression -> iex)"
}
func (cmdletAlias) Remediation() string {
	return "Enumerate every alias in CommandLine|contains lists (or a |re alternation); aliases are not normalized in 4104 script-block logs, so this is a rule-content fix."
}

// psrAlias is one cmdlet/alias pair. Only aliases that ship with BOTH Windows
// PowerShell 5.1 and PowerShell 7 are listed: aliases that differ across
// versions (curl, wget, sc) would change behaviour on one of them and are not
// semantics preserving.
type psrAlias struct {
	cmdlet string // canonical spelling, used in the note
	alias  string
	// pipeOnly restricts the substitution to command position after a pipe,
	// because the alias spelling is also a language keyword. "foreach" at the
	// start of a statement parses as the foreach loop, not as ForEach-Object.
	pipeOnly bool
}

var psrAliasTable = []psrAlias{
	{cmdlet: "Invoke-Expression", alias: "iex"},
	{cmdlet: "Invoke-WebRequest", alias: "iwr"},
	{cmdlet: "Invoke-RestMethod", alias: "irm"},
	{cmdlet: "Invoke-Command", alias: "icm"},
	{cmdlet: "Invoke-Item", alias: "ii"},
	{cmdlet: "Get-Content", alias: "gc"},
	{cmdlet: "Get-ChildItem", alias: "gci"},
	{cmdlet: "Get-Process", alias: "gps"},
	{cmdlet: "Start-Process", alias: "saps"},
	{cmdlet: "Get-Command", alias: "gcm"},
	{cmdlet: "Get-Member", alias: "gm"},
	{cmdlet: "Where-Object", alias: "where"},
	{cmdlet: "ForEach-Object", alias: "foreach", pipeOnly: true},
	{cmdlet: "Select-Object", alias: "select"},
	{cmdlet: "New-PSSession", alias: "nsn"},
	{cmdlet: "Start-Sleep", alias: "sleep"},
}

var (
	psrAliasByName = psrBuildAliasIndex()
	psrAliasRe     = psrBuildAliasRe()
)

func psrBuildAliasIndex() map[string]psrAlias {
	idx := make(map[string]psrAlias, len(psrAliasTable))
	for _, a := range psrAliasTable {
		idx[strings.ToLower(a.cmdlet)] = a
	}
	return idx
}

// psrBuildAliasRe compiles one case-insensitive alternation over every cmdlet
// name. Alternatives are ordered longest-first so Go's leftmost-first matching
// can never settle for a shorter name that prefixes a longer one.
func psrBuildAliasRe() *regexp.Regexp {
	names := make([]string, 0, len(psrAliasTable))
	for _, a := range psrAliasTable {
		names = append(names, regexp.QuoteMeta(a.cmdlet))
	}
	sort.Slice(names, func(i, j int) bool {
		if len(names[i]) != len(names[j]) {
			return len(names[i]) > len(names[j])
		}
		return names[i] < names[j]
	})
	return regexp.MustCompile(`(?i)\b(?:` + strings.Join(names, "|") + `)\b`)
}

// psrNameTail lists characters that, immediately after a matched cmdlet name,
// mean the match was part of a longer name or a path rather than a command.
const psrNameTail = `.:\/`

func (cmdletAlias) Apply(value string) []Result {
	quoted := psrQuoteMask(value)

	// Group the command-position occurrences by cmdlet, keeping first-appearance
	// order so the result slice is deterministic.
	var order []string
	spans := map[string][][2]int{}
	for _, loc := range psrAliasRe.FindAllStringIndex(value, -1) {
		start, end := loc[0], loc[1]
		if quoted[start] {
			continue // a cmdlet name inside a string literal is data, not a call
		}
		ok, afterPipe := psrAtCommandPosition(value, quoted, start)
		if !ok {
			continue
		}
		if end < len(value) && strings.IndexByte(psrNameTail, value[end]) >= 0 {
			continue
		}
		key := strings.ToLower(value[start:end])
		entry := psrAliasByName[key]
		if entry.pipeOnly && !afterPipe {
			continue
		}
		if _, seen := spans[key]; !seen {
			order = append(order, key)
		}
		spans[key] = append(spans[key], [2]int{start, end})
	}
	if len(order) == 0 {
		return nil
	}

	out := make([]Result, 0, len(order))
	for _, key := range order {
		entry := psrAliasByName[key]
		mutated := psrSplice(value, spans[key], entry.alias)
		if mutated == value {
			continue
		}
		out = append(out, Result{
			Value: mutated,
			Note:  "replaced " + entry.cmdlet + " with its built-in alias " + entry.alias,
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// --- namespace-shorten ----------------------------------------------------

// namespaceShorten drops a leading "System." from a .NET type reference. The
// type resolver retries any bare name with "System." prepended, so
// [Net.WebClient] and [System.Net.WebClient] resolve to the same type. A rule
// keyed on the fully qualified path misses the short form.
type namespaceShorten struct{}

func (namespaceShorten) Name() string      { return "namespace-shorten" }
func (namespaceShorten) Technique() string { return "T1027.010" }
func (namespaceShorten) Describe() string {
	return "Drop a leading System. from a .NET type reference ([System.Net.WebClient] -> [Net.WebClient])"
}
func (namespaceShorten) Remediation() string {
	return "List the System.-less twin, or better match the distinctive leaf (WebClient, FromBase64String) instead of the qualified path."
}

// psrSystemRoots are the only namespaces whose System. prefix is dropped. The
// resolver's retry is unconditional, so a bare name that also exists under some
// other loaded namespace could bind to a different type; restricting the list to
// roots with no known colliding twin keeps the transform exact.
var psrSystemRoots = []string{
	"Management.Automation",
	"Reflection",
	"Diagnostics",
	"Convert",
	"Text",
	"Net",
	"IO",
}

var (
	// Group 1 is the "System." span to delete, group 2 the allowlisted root.
	psrTypeLiteralRe = regexp.MustCompile(`(?i)\[(system\.)(` + psrRootAlternation() + `)\b`)
	psrNewObjectRe   = regexp.MustCompile(`(?i)new-object\s+(?:-typename\s+)?(system\.)(` + psrRootAlternation() + `)\b`)
)

// psrRootAlternation renders the allowlist longest-first so a root that
// prefixes another can never win the alternation.
func psrRootAlternation() string {
	roots := make([]string, 0, len(psrSystemRoots))
	for _, r := range psrSystemRoots {
		roots = append(roots, regexp.QuoteMeta(r))
	}
	sort.Slice(roots, func(i, j int) bool {
		if len(roots[i]) != len(roots[j]) {
			return len(roots[i]) > len(roots[j])
		}
		return roots[i] < roots[j]
	})
	return strings.Join(roots, "|")
}

func (namespaceShorten) Apply(value string) []Result {
	quoted := psrQuoteMask(value)

	var spans [][2]int
	var roots []string
	seenSpan := map[int]bool{}
	seenRoot := map[string]bool{}
	for _, re := range []*regexp.Regexp{psrTypeLiteralRe, psrNewObjectRe} {
		for _, m := range re.FindAllStringSubmatchIndex(value, -1) {
			start, end := m[2], m[3]
			if start < 0 || quoted[start] || seenSpan[start] {
				continue
			}
			seenSpan[start] = true
			spans = append(spans, [2]int{start, end})
			if root := value[m[4]:m[5]]; !seenRoot[root] {
				seenRoot[root] = true
				roots = append(roots, root)
			}
		}
	}
	if len(spans) == 0 {
		return nil
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i][0] < spans[j][0] })
	sort.Strings(roots)

	mutated := psrSplice(value, spans, "")
	if mutated == value {
		return nil
	}
	return []Result{{
		Value: mutated,
		Note:  "dropped the leading System. from " + strings.Join(roots, ", ") + " (the type resolver re-adds it)",
	}}
}

// --- member-name-expression -----------------------------------------------

// memberNameExpression quotes a member name so it is parsed as a string
// expression rather than a bare word. The parser stores both forms as the same
// constant member name, so .DownloadString() and .'DownloadString'() invoke the
// identical method — but a rule matching the literal ".DownloadString" misses
// the quoted spelling, which 4104 logging does not normalize away.
type memberNameExpression struct{}

func (memberNameExpression) Name() string      { return "member-name-expression" }
func (memberNameExpression) Technique() string { return "T1027.010" }
func (memberNameExpression) Describe() string {
	return "Quote a member name after . so it resolves as an expression (.DownloadString( -> .'DownloadString'()"
}
func (memberNameExpression) Remediation() string {
	return "Match .'Name, .\"Name and .( before a quote; script-block logging (4104) does not normalize this member-access form."
}

// psrMemberCallRe matches a bare-word member name that is immediately invoked.
// Requiring the "(" keeps this to method calls, where the quoted form is
// unambiguously equivalent. An already-quoted member cannot match, because the
// name has to start with an identifier character.
var psrMemberCallRe = regexp.MustCompile(`\.([A-Za-z_][A-Za-z0-9_]*)\(`)

func (memberNameExpression) Apply(value string) []Result {
	quoted := psrQuoteMask(value)
	for _, m := range psrMemberCallRe.FindAllStringSubmatchIndex(value, -1) {
		if quoted[m[0]] {
			continue // inside a string literal this is text, not member access
		}
		name := value[m[2]:m[3]]
		quotedName := "'" + name + "'"
		return []Result{{
			Value: value[:m[2]] + quotedName + value[m[3]:],
			Note:  "quoted the member name ." + name + " as ." + quotedName,
		}}
	}
	return nil
}
