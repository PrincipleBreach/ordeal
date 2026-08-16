package mutate

import (
	"regexp"
	"strings"
)

func init() {
	register(
		argSeparatorSubstitution{},
		envVarSubstringIdentity{},
		shortPath8dot3{},
	)
}

// --- cmd.exe token helpers -----------------------------------------------

// cmdToken is one whitespace-delimited token of a command line plus its byte
// offsets, so a mutator can rewrite a single separator and copy everything else
// through verbatim.
type cmdToken struct {
	text  string
	start int
	end   int
}

// cmdTokenize splits value on unquoted spaces and tabs. Quotes stay part of the
// token text: a quoted region is one token, which is what keeps mutators from
// touching the spaces inside it.
func cmdTokenize(value string) []cmdToken {
	var toks []cmdToken
	inQuote := false
	start := -1
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == '"' {
			inQuote = !inQuote
		}
		if !inQuote && (c == ' ' || c == '\t') {
			if start >= 0 {
				toks = append(toks, cmdToken{value[start:i], start, i})
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		toks = append(toks, cmdToken{value[start:], start, len(value)})
	}
	return toks
}

// cmdIsCmdContext reports whether the command line invokes cmd.exe, which is the
// only interpreter whose delimiter set this file models. The first token may be
// quoted and path-qualified; only the base name decides.
func cmdIsCmdContext(toks []cmdToken) bool {
	if len(toks) == 0 {
		return false
	}
	head := strings.Trim(toks[0].text, `"`)
	if i := strings.LastIndexAny(head, `\/`); i >= 0 {
		head = head[i+1:]
	}
	switch strings.ToLower(head) {
	case "cmd", "cmd.exe":
		return true
	}
	return false
}

// cmdPayloadSwitch returns the index of the /c or /k token, after which cmd
// treats the rest of the line as a command to run. -1 if there is none.
func cmdPayloadSwitch(toks []cmdToken) int {
	for i := 1; i < len(toks); i++ {
		switch strings.ToLower(toks[i].text) {
		case "/c", "/k":
			return i
		}
	}
	return -1
}

// cmdSeparable reports whether a comma may stand in for the space next to tok
// without changing what runs.
//
// Excluded, deliberately:
//   - tokens containing '=', because '=' is itself a cmd delimiter and a
//     "set X=Y" or "/p:Prop=Val" token depends on its exact shape;
//   - tokens carrying a shell metacharacter (& | < > ^ ( )), where the comma
//     would land next to a redirection or command-chaining operator and cmd's
//     parse order stops being obvious;
//   - quoted tokens, where the delimiter interacts with quote stripping.
func cmdSeparable(tok string) bool {
	return tok != "" && !strings.ContainsAny(tok, `="&|<>^()`)
}

// --- Mutators ------------------------------------------------------------

// argSeparatorSubstitution replaces the delimiter between a cmd.exe payload's
// command word and its arguments with a comma. cmd.exe treats space, tab, comma,
// semicolon and equals as one interchangeable delimiter set when it splits the
// command word off the rest of the line, so "cmd /c ping,127.0.0.1" runs exactly
// what "cmd /c ping 127.0.0.1" runs. A rule matching a literal that spans that
// boundary ("/c ping ") stops firing.
//
// Only that one delimiter is substituted, and only in a cmd.exe context. The
// delimiters further along the payload are NOT interchangeable in general: cmd
// hands the remainder of the line to the target program, whose own parser
// (CommandLineToArgvW, or a bespoke one) splits on whitespace only. Replacing
// them would turn "ping 127.0.0.1 -n 5" into a single argument "127.0.0.1,-n,5"
// and change what executes, so this mutator leaves them alone.
type argSeparatorSubstitution struct{}

func (argSeparatorSubstitution) Name() string      { return "arg-separator-substitution" }
func (argSeparatorSubstitution) Technique() string { return "T1027.010" }
func (argSeparatorSubstitution) Describe() string {
	return "Replace spaces between cmd.exe tokens with commas (cmd treats space , ; = as one delimiter)"
}
func (argSeparatorSubstitution) Remediation() string {
	return "Never match a literal spanning a token boundary; split multi-token matches into CommandLine|contains|all so any delimiter works."
}

func (argSeparatorSubstitution) Apply(value string) []Result {
	toks := cmdTokenize(value)
	if !cmdIsCmdContext(toks) {
		return nil
	}
	sw := cmdPayloadSwitch(toks)
	if sw < 0 || sw+2 >= len(toks) {
		return nil // no /c or /k, or no argument to separate from the command word
	}
	word, arg := toks[sw+1], toks[sw+2]
	if !cmdSeparable(word.text) || !cmdSeparable(arg.text) {
		return nil
	}
	mutated := value[:word.end] + "," + value[arg.start:]
	if mutated == value {
		return nil
	}
	return []Result{{Value: mutated, Note: "replaced the delimiter after the payload command word with a comma"}}
}

// envVarSubstringIdentity rewrites %VAR% as %VAR:~0%. cmd's substring syntax is
// %VAR:~offset,length%; with the length omitted it runs to the end of the value,
// so %VAR:~0% expands to the whole of VAR for every possible value, including the
// empty one. The expansion is identical, the literal is not, so a rule matching
// %SystemRoot% stops firing.
//
// The rewrite only means something where %VAR% is expanded at run time — a cmd or
// batch context, or a delayed-expansion payload. A literal %VAR% surviving into a
// logged command line is the signal that expansion has not happened yet.
type envVarSubstringIdentity struct{}

func (envVarSubstringIdentity) Name() string      { return "env-var-substring-identity" }
func (envVarSubstringIdentity) Technique() string { return "T1027.010" }
func (envVarSubstringIdentity) Describe() string {
	return "Rewrite %VAR% as the identity substring %VAR:~0% (expands to the full value unconditionally)"
}
func (envVarSubstringIdentity) Remediation() string {
	return "Don't match %VAR% literally (expansion happens pre-execution); deploy a rule for the substring/replacement syntax %VAR:[~=]."
}

var cmdEnvVar = regexp.MustCompile(`%([A-Za-z_][A-Za-z0-9_]*)%`)

func (envVarSubstringIdentity) Apply(value string) []Result {
	loc := cmdEnvVar.FindStringSubmatchIndex(value)
	if loc == nil {
		return nil
	}
	name := value[loc[2]:loc[3]]
	mutated := value[:loc[0]] + "%" + name + ":~0%" + value[loc[1]:]
	return []Result{{Value: mutated, Note: "rewrote %" + name + "% as the identity substring %" + name + ":~0%"}}
}

// shortPath8dot3 swaps a well-known long directory for its 8.3 short name.
// C:\PROGRA~1\Foo\bar.exe opens the same file as C:\Program Files\Foo\bar.exe,
// but a rule matching the long path misses it.
//
// The substitutions come from a fixed table and nothing else. 8.3 names are
// allocated per volume in creation order, so a short name for an arbitrary
// directory cannot be derived from its long name — inventing one would produce a
// path that does not resolve, i.e. a fabricated evasion. The four entries here
// are the allocation a default Windows install produces on the system volume.
type shortPath8dot3 struct{}

func (shortPath8dot3) Name() string      { return "short-path-8dot3" }
func (shortPath8dot3) Technique() string { return "T1036.005" }
func (shortPath8dot3) Describe() string {
	return "Replace a well-known long directory with its 8.3 short name (Program Files -> PROGRA~1)"
}
func (shortPath8dot3) Remediation() string {
	return "Pin location on Image (the kernel logs the canonical long path); hunt ~1/~2 in CommandLine — modern software rarely emits short paths."
}

// cmdShortPaths is ordered longest-first so "Program Files (x86)" is tried
// before the "Program Files" prefix it contains.
var cmdShortPaths = []struct{ long, short string }{
	{"Documents and Settings", "DOCUME~1"},
	{"Program Files (x86)", "PROGRA~2"},
	{"Program Files", "PROGRA~1"},
	{"ProgramData", "PROGRA~3"},
}

func (shortPath8dot3) Apply(value string) []Result {
	lower := strings.ToLower(value)
	for _, p := range cmdShortPaths {
		idx := cmdFindComponent(lower, strings.ToLower(p.long))
		if idx < 0 {
			continue
		}
		mutated := value[:idx] + p.short + value[idx+len(p.long):]
		return []Result{{Value: mutated, Note: "replaced " + p.long + " with its 8.3 short name " + p.short}}
	}
	return nil
}

// cmdFindComponent returns the index of the first occurrence of want in lower
// that stands alone as a path component, or -1. The boundary check is what keeps
// %ProgramData% (a variable reference, already handled by env-indirection) and
// "Program Files (x86)" from being rewritten by the "Program Files" entry.
func cmdFindComponent(lower, want string) int {
	for from := 0; from+len(want) <= len(lower); {
		i := strings.Index(lower[from:], want)
		if i < 0 {
			return -1
		}
		i += from
		if cmdComponentBounded(lower, i, i+len(want)) {
			return i
		}
		from = i + 1
	}
	return -1
}

func cmdComponentBounded(s string, start, end int) bool {
	if start > 0 && s[start-1] != '\\' && s[start-1] != '/' {
		return false
	}
	if end < len(s) {
		switch s[end] {
		case '\\', '/', '"':
		default:
			return false
		}
	}
	return true
}
