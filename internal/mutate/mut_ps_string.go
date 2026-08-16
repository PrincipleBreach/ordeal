package mutate

import "strings"

// This file holds the PowerShell string-level obfuscations: transforms that
// rewrite a single-quoted string literal, or a parameter name, inside a command
// line without changing what the interpreter ends up executing.
//
// Everything here is deliberately conservative. A string literal is the one
// place in a command line where an attacker's payload lives verbatim, so a
// transform that is "usually" reversible is not good enough — a mutation that
// silently changes the string would report an evasion gap that does not exist.
// Each mutator therefore refuses the input (returns nil) whenever it cannot
// prove the rewrite is a no-op for the interpreter:
//
//   - Only single-quoted literals are touched. PowerShell does no expansion
//     inside them, so their contents are exactly their bytes, and the emitted
//     fragments are single-quoted too — which also means they nest cleanly
//     inside an outer double-quoted -Command "..." wrapper.
//   - Literals whose body is non-ASCII, contains a quote, or looks like an
//     encoded payload (isOpaque) are skipped entirely.
//   - The backtick mutator refuses any position where the backtick would form a
//     PowerShell escape sequence (`n, `t, `0, ...) and thus change the bytes.

func init() {
	register(
		stringConcat{},
		formatOperator{},
		argBacktick{},
	)
}

// --- single-quoted literal helpers ---------------------------------------

// pssLiteral is one single-quoted string literal located inside a value: the
// byte offsets of its opening and closing quotes, plus the body between them.
type pssLiteral struct {
	open  int    // index of the opening ' byte
	close int    // index of the closing ' byte
	body  string // contents, exclusive of both quotes
}

// pssFirstLiteral returns the first single-quoted literal in value whose body is
// safe to rewrite: printable ASCII, at least minLen bytes, and not an opaque
// payload blob. Scanning is left to right, so the choice is deterministic.
//
// PowerShell escapes a quote inside a literal by doubling it. That makes literal
// boundaries ambiguous to a scanner this simple, so the whole value is refused as
// soon as a doubled quote appears rather than risk splitting a string in the
// wrong place.
func pssFirstLiteral(value string, minLen int) (pssLiteral, bool) {
	for i := 0; i < len(value); i++ {
		if value[i] != '\'' {
			continue
		}
		j := strings.IndexByte(value[i+1:], '\'')
		if j < 0 {
			return pssLiteral{}, false // unterminated literal
		}
		j += i + 1
		if j+1 < len(value) && value[j+1] == '\'' {
			return pssLiteral{}, false // doubled quote: boundaries are ambiguous
		}
		body := value[i+1 : j]
		if pssEligibleBody(body, minLen) {
			return pssLiteral{open: i, close: j, body: body}, true
		}
		i = j // this literal is unusable; resume after it
	}
	return pssLiteral{}, false
}

// pssEligibleBody reports whether a literal body can be safely reshaped.
func pssEligibleBody(body string, minLen int) bool {
	if len(body) < minLen {
		return false
	}
	if isOpaque(body) {
		return false // an encoded payload; splitting it is not provably a no-op
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		if c < 0x20 || c > 0x7e {
			return false // non-ASCII or control byte
		}
		if c == '\'' {
			return false // unreachable via pssFirstLiteral, but cheap to assert
		}
	}
	return true
}

// pssSplit cuts s at floor(len/2) into two non-empty halves.
func pssSplit(s string) (a, b string) {
	mid := len(s) / 2
	return s[:mid], s[mid:]
}

// pssReplace swaps the literal at lit for expr, leaving the rest of value alone.
func pssReplace(value string, lit pssLiteral, expr string) string {
	return value[:lit.open] + expr + value[lit.close+1:]
}

// --- string-concat --------------------------------------------------------

// stringConcat splits a string literal in two and rejoins the halves with the +
// operator. PowerShell concatenates the fragments back to the identical string
// before anything sees it, so 'http://x' and ('htt'+'p://x') are the same value —
// but a rule matching the contiguous literal only sees the first fragment.
type stringConcat struct{}

func (stringConcat) Name() string      { return "string-concat" }
func (stringConcat) Technique() string { return "T1027.010" }
func (stringConcat) Describe() string {
	return "Split a string literal and rejoin with + ('http://x' -> ('htt'+'p://x'))"
}
func (stringConcat) Remediation() string {
	return "Stop matching contiguous literals; add a regex for '+'-joined quoted fragments as an obfuscation signal (Elastic 'String Concatenation')."
}

func (stringConcat) Apply(value string) []Result {
	lit, ok := pssFirstLiteral(value, 4)
	if !ok {
		return nil
	}
	a, b := pssSplit(lit.body)
	// The parentheses matter: without them the + would bind to whatever precedes
	// the literal instead of forming a self-contained expression.
	mutated := pssReplace(value, lit, "('"+a+"'+'"+b+"')")
	if mutated == value {
		return nil
	}
	return []Result{{Value: mutated, Note: "split the literal '" + lit.body + "' into a parenthesised '+' concatenation"}}
}

// --- format-operator ------------------------------------------------------

// formatOperator rebuilds a string literal through the -f format operator with
// its fragments listed out of order. ('{1}{0}' -f 'B','A') evaluates to "AB", so
// the runtime string is unchanged while the original substring never appears in
// the command line in reading order.
type formatOperator struct{}

func (formatOperator) Name() string      { return "format-operator" }
func (formatOperator) Technique() string { return "T1027.010" }
func (formatOperator) Describe() string {
	return "Rebuild a string via the -f format operator with reordered fragments"
}
func (formatOperator) Remediation() string {
	return "Regex for ({\\d}){2,} together with -f or ::Format (Elastic 'String Reordering'); keep per-keyword leaf matches."
}

func (formatOperator) Apply(value string) []Result {
	lit, ok := pssFirstLiteral(value, 4)
	if !ok {
		return nil
	}
	// A brace in the body would be parsed as a format item by -f and could change
	// or break the result, so such literals are refused outright rather than
	// escaped: doubling braces is easy to get subtly wrong.
	if strings.ContainsAny(lit.body, "{}") {
		return nil
	}
	a, b := pssSplit(lit.body)
	// Arg 0 is the second half and arg 1 the first, so '{1}{0}' reassembles a+b.
	mutated := pssReplace(value, lit, "('{1}{0}' -f '"+b+"','"+a+"')")
	if mutated == value {
		return nil
	}
	return []Result{{Value: mutated, Note: "rebuilt the literal '" + lit.body + "' with the -f operator and reordered fragments"}}
}

// --- arg-backtick ---------------------------------------------------------

// argBacktick inserts a PowerShell backtick into a parameter name. The backtick
// escapes the following character, and for an ordinary letter that escape is the
// letter itself, so -Win`dowStyle binds to the same parameter as -WindowStyle.
// This complements powershell-tick, which only reshapes the command token and so
// misses rules that key on an argument.
type argBacktick struct{}

func (argBacktick) Name() string      { return "arg-backtick" }
func (argBacktick) Technique() string { return "T1027.010" }
func (argBacktick) Describe() string {
	return "Insert a PowerShell backtick into a parameter name (-WindowStyle -> -Win`dowStyle)"
}
func (argBacktick) Remediation() string {
	return "Strip backticks before matching, or use |re with an optional backtick between characters of high-value keywords."
}

// pssEscapeLetters are the characters PowerShell turns into something other than
// themselves when preceded by a backtick (`n newline, `t tab, `0 null, and so
// on). A backtick placed before any of these is not a no-op. Both cases are
// listed because being conservative here costs one candidate position and buys
// certainty.
const pssEscapeLetters = "ntr0abfveNTRABFVE"

// pssSafeAfterTick reports whether inserting a backtick immediately before c
// leaves the token's meaning unchanged.
func pssSafeAfterTick(c byte) bool {
	if !pssIsLetter(c) {
		return false // covers ` " ' $ and every other special character
	}
	return strings.IndexByte(pssEscapeLetters, c) < 0
}

func pssIsLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// pssParam is a parameter token found in a command line: the offset of the first
// letter after the dash, and the letter run itself.
type pssParam struct {
	start int
	name  string
}

// pssParams returns every `-Name` parameter token in value that sits outside a
// single-quoted string, in left-to-right order.
//
// The single-quote exclusion is the whole safety argument for this mutator:
// outside a literal (and inside a double-quoted string) the backtick is an escape
// character and vanishes, but inside a single-quoted literal it is data and would
// change the string.
func pssParams(value string) []pssParam {
	var out []pssParam
	inLiteral := false
	for i := 0; i < len(value); {
		c := value[i]
		switch {
		case c == '\'':
			inLiteral = !inLiteral
			i++
		case inLiteral:
			i++
		case c == '-' && (i == 0 || value[i-1] == ' ' || value[i-1] == '\t'):
			j := i + 1
			for j < len(value) && pssIsLetter(value[j]) {
				j++
			}
			if name := value[i+1 : j]; len(name) >= 4 {
				out = append(out, pssParam{start: i + 1, name: name})
			}
			i = j
		default:
			i++
		}
	}
	return out
}

// pssTickOffset picks where inside name to insert the backtick: after the third
// letter when that is safe, otherwise the first other safe position. It returns
// -1 when no position in name is safe, in which case the parameter is skipped.
func pssTickOffset(name string) int {
	if len(name) > 3 && pssSafeAfterTick(name[3]) {
		return 3
	}
	for k := 1; k < len(name); k++ {
		if k != 3 && pssSafeAfterTick(name[k]) {
			return k
		}
	}
	return -1
}

func (argBacktick) Apply(value string) []Result {
	for _, p := range pssParams(value) {
		if isOpaque(p.name) {
			continue // payload-shaped; not a parameter worth reshaping
		}
		k := pssTickOffset(p.name)
		if k < 0 {
			continue // every position would form an escape sequence
		}
		at := p.start + k
		mutated := value[:at] + "`" + value[at:]
		if mutated == value {
			return nil
		}
		return []Result{{Value: mutated, Note: "inserted a backtick into the parameter -" + p.name}}
	}
	return nil
}
