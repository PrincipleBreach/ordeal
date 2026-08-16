package mutate

import (
	"regexp"
	"strings"
)

// This file holds the macOS-specific mutators.
//
// They differ from the nix family in two ways. First, they are not confined to a
// shell -c payload: each rewrites an argument the interpreter itself resolves
// (a symlinked path prefix, a redundant default flag, an alternate short flag,
// an attached option argument), so the mutated form survives argv-level logging
// and appears verbatim in EDR telemetry. Second, they encode behaviour that is
// specific to Apple's userland — the /private symlink farm, osascript's default
// language component, and the BSD base64 flag set — so a rule authored against
// Linux tooling misses them even when the technique is identical.
//
// Verified on macOS 26.5.2 with zsh 5.9 on a case-insensitive APFS volume.

// macBasename returns the lowercased file name of a command token, so
// /usr/bin/osascript, "osascript" and OSASCRIPT are all recognized alike. macOS
// volumes are case-insensitive by default, so case carries no meaning here.
func macBasename(tok string) string {
	tok = strings.Trim(tok, `'"`)
	if i := strings.LastIndexByte(tok, '/'); i >= 0 {
		tok = tok[i+1:]
	}
	return strings.ToLower(tok)
}

// macHead splits value into its command token, that token's basename, and the
// remaining argument text. Flag rewrites search only rest, so a flag-shaped
// substring of the program path is never touched.
func macHead(value string) (head, base, rest string) {
	head, rest = commandToken(value)
	return head, macBasename(head), rest
}

var (
	// macPathSegment matches a /tmp, /var or /etc prefix that is a whole path
	// segment: it must start an argument token (string start, whitespace, an
	// opening quote, or a --flag= separator) and end on a path separator or a
	// token boundary. That leaves /tmpfoo, /etcd and an already-rewritten
	// /private/tmp untouched — in the last case the prefix is preceded by the
	// "e" of private, so it never starts a token.
	macPathSegment = regexp.MustCompile(`(^|[\s'"=])(/tmp|/var|/etc)(/|[\s'";,)]|$)`)

	// macDashE, macDashL and macDashD match a short flag standing alone as its
	// own argument, so --decode and --language are not mistaken for -d and -l.
	macDashE = regexp.MustCompile(`(^|\s)-e(\s|$)`)
	macDashL = regexp.MustCompile(`(^|\s)-l(\s|$)`)
	macDashD = regexp.MustCompile(`(^|\s)-d(\s|$)`)

	// macDashCQuoted matches python's -c flag separated from its quoted program
	// text by exactly one space — the space this mutator deletes.
	macDashCQuoted = regexp.MustCompile(`(^|\s)-c (['"])`)

	// macPythonName matches the CPython interpreter names whose option parser is
	// the getopt-style _PyOS_GetOpt, which attaches a short option's argument.
	macPythonName = regexp.MustCompile(`^python[23]?$`)
)

// --- Mutators ------------------------------------------------------------

// macPrivatePathPrefix rewrites /tmp, /var and /etc to the /private/... targets
// they are symlinked to. The kernel resolves both spellings to the same vnode,
// so the command reads or writes the identical file. The gap this opens is that
// EDR telemetry frequently reports the resolved /private/tmp form while rules
// are written against the /tmp form an operator types.
type macPrivatePathPrefix struct{}

func (macPrivatePathPrefix) Name() string          { return "macos-private-path-prefix" }
func (macPrivatePathPrefix) Technique() string     { return "T1036.005" }
func (macPrivatePathPrefix) Platforms() []Platform { return []Platform{MacOS} }
func (macPrivatePathPrefix) Describe() string {
	return "Rewrite /tmp, /var, /etc to their real /private/... targets (cat /tmp/x -> cat /private/tmp/x)"
}
func (macPrivatePathPrefix) Remediation() string {
	return "Normalize /private/ prefixes before matching and cover both forms in path selectors; EDR reports the resolved /private/tmp form while many rules key on /tmp."
}
func (macPrivatePathPrefix) Apply(value string) []Result {
	loc := macPathSegment.FindStringSubmatchIndex(value)
	if loc == nil {
		return nil
	}
	start, end := loc[4], loc[5] // group 2: the /tmp, /var or /etc prefix
	prefix := value[start:end]
	return []Result{{
		Value: value[:start] + "/private" + value[start:],
		Note:  "rewrote " + prefix + " to /private" + prefix,
	}}
}

// macOsascriptLang inserts the -l AppleScript flag, naming the component
// osascript already defaults to. The invocation is unchanged, but osascript and
// -e are no longer adjacent, which defeats a rule matching them as one literal
// substring.
type macOsascriptLang struct{}

func (macOsascriptLang) Name() string          { return "osascript-lang-explicit" }
func (macOsascriptLang) Technique() string     { return "T1059.002" }
func (macOsascriptLang) Platforms() []Platform { return []Platform{MacOS} }
func (macOsascriptLang) Describe() string {
	return "Insert the redundant default -l AppleScript, breaking osascript<->-e adjacency (osascript -e '...' -> osascript -l AppleScript -e '...')"
}
func (macOsascriptLang) Remediation() string {
	return "Do not require -e to immediately follow osascript; match them as independent |contains|all items, and cover -l JavaScript."
}
func (macOsascriptLang) Apply(value string) []Result {
	head, base, rest := macHead(value)
	if base != "osascript" {
		return nil
	}
	// -e supplies the statement; -l already names a component, and re-specifying
	// it could contradict the caller, so decline that case.
	if !macDashE.MatchString(rest) || macDashL.MatchString(rest) {
		return nil
	}
	return []Result{{
		Value: head + " -l AppleScript" + rest,
		Note:  "named osascript's default AppleScript component explicitly",
	}}
}

// macBase64FlagCase swaps base64's -d decode flag for -D. macOS ships the
// bintrans implementation, whose decode flag is spelled -D, -d and --decode
// interchangeably. This is macOS-only: GNU coreutils base64 has no -D, so the
// same rewrite would break the command on Linux.
type macBase64FlagCase struct{}

func (macBase64FlagCase) Name() string          { return "base64-flagcase" }
func (macBase64FlagCase) Technique() string     { return "T1140" }
func (macBase64FlagCase) Platforms() []Platform { return []Platform{MacOS} }
func (macBase64FlagCase) Describe() string {
	return "Swap the macOS base64 decode flag -d for the equivalent -D (base64 -d -> base64 -D)"
}
func (macBase64FlagCase) Remediation() string {
	return "Match base64 with any of -d/-D/--decode as a set; a Linux-authored rule matching only -d/--decode misses macOS -D."
}
func (macBase64FlagCase) Apply(value string) []Result {
	head, base, rest := macHead(value)
	if base != "base64" {
		return nil
	}
	loc := macDashD.FindStringSubmatchIndex(rest)
	if loc == nil {
		return nil
	}
	flag := loc[3] // just past group 1: the position of the "-" in "-d"
	return []Result{{
		Value: head + rest[:flag] + "-D" + rest[flag+2:],
		Note:  "swapped the base64 decode flag -d for the equivalent -D",
	}}
}

// macPythonCSpacing deletes the space between python's -c flag and its program
// text. CPython parses its options with a getopt-style scanner, which takes the
// remainder of the argument as the option's value, so -c'...' passes the same
// program string as -c '...'.
type macPythonCSpacing struct{}

func (macPythonCSpacing) Name() string          { return "python-c-spacing" }
func (macPythonCSpacing) Technique() string     { return "T1059.006" }
func (macPythonCSpacing) Platforms() []Platform { return []Platform{Linux, MacOS} }
func (macPythonCSpacing) Describe() string {
	return "Remove the space after python's -c flag (python3 -c 'x' -> python3 -c'x')"
}
func (macPythonCSpacing) Remediation() string {
	return `Match python* + -c without requiring the following space; use a regex like -\w*c.`
}
func (macPythonCSpacing) Apply(value string) []Result {
	head, base, rest := macHead(value)
	if !macPythonName.MatchString(base) {
		return nil
	}
	loc := macDashCQuoted.FindStringSubmatchIndex(rest)
	if loc == nil {
		return nil
	}
	space := loc[4] - 1 // group 3 is the opening quote; the space precedes it
	return []Result{{
		Value: head + rest[:space] + rest[space+1:],
		Note:  "attached python's -c argument to the flag",
	}}
}

func init() {
	register(
		macPrivatePathPrefix{},
		macOsascriptLang{},
		macBase64FlagCase{},
		macPythonCSpacing{},
	)
}
