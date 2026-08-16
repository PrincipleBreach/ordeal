package mutate

import (
	"strings"
	"testing"
)

// applyOne runs m and returns the single mutated value, or "" when the technique
// does not apply. It fails the test if a mutator returns more than one variant,
// since all three cmd mutators are single-variant by construction.
func applyOne(t *testing.T, m Mutator, in string) string {
	t.Helper()
	got := m.Apply(in)
	if len(got) == 0 {
		return ""
	}
	if len(got) != 1 {
		t.Fatalf("%s(%q) returned %d variants, want at most 1: %+v", m.Name(), in, len(got), got)
	}
	if got[0].Value == in {
		t.Fatalf("%s(%q) returned a no-op variant", m.Name(), in)
	}
	if got[0].Note == "" {
		t.Errorf("%s(%q) returned a variant with no note", m.Name(), in)
	}
	return got[0].Value
}

func TestArgSeparatorSubstitution(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string // "" means the mutator must not apply
	}{
		{
			name: "cmd payload gets a comma delimiter",
			in:   `cmd.exe /c ping 127.0.0.1 -n 5`,
			want: `cmd.exe /c ping,127.0.0.1 -n 5`,
		},
		{
			name: "uppercase switch and bare cmd",
			in:   `cmd /K whoami /priv`,
			want: `cmd /K whoami,/priv`,
		},
		{
			name: "path-qualified and quoted cmd still counts as a cmd context",
			in:   `"C:\Windows\System32\cmd.exe" /c net user`,
			want: `"C:\Windows\System32\cmd.exe" /c net,user`,
		},
		{
			name: "non-cmd interpreter is out of scope",
			in:   `powershell.exe -NoProfile -Command Get-Process`,
			want: "",
		},
		{
			name: "cmd without /c or /k runs no payload",
			in:   `cmd.exe /v:on`,
			want: "",
		},
		{
			name: "payload with no argument has no delimiter to swap",
			in:   `cmd.exe /c whoami`,
			want: "",
		},
		{
			name: "token containing = is left alone",
			in:   `cmd.exe /c set X=Y`,
			want: "",
		},
		{
			name: "spaces inside a quoted region are preserved",
			in:   `cmd.exe /c ping 127.0.0.1 "a b"`,
			want: `cmd.exe /c ping,127.0.0.1 "a b"`,
		},
		{
			name: "quoted payload is a single token",
			in:   `cmd.exe /c "ping 127.0.0.1"`,
			want: "",
		},
		{
			name: "redirection operator is left alone",
			in:   `cmd.exe /c dir > C:\out.txt`,
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := applyOne(t, argSeparatorSubstitution{}, tc.in); got != tc.want {
				t.Errorf("Apply(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestArgSeparatorKeepsAssignmentIntact(t *testing.T) {
	// Whatever the mutator decides, an "=" assignment must survive byte-identical:
	// "=" is itself a cmd delimiter, so collapsing it would change what runs.
	for _, in := range []string{`cmd.exe /c set X=Y`, `cmd.exe /c msbuild /p:Prop=Val proj.xml`} {
		for _, r := range (argSeparatorSubstitution{}).Apply(in) {
			if !strings.Contains(r.Value, "=") {
				t.Errorf("Apply(%q) collapsed an assignment: %q", in, r.Value)
			}
		}
	}
}

func TestEnvVarSubstringIdentity(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "system root becomes an identity substring",
			in:   `%SystemRoot%\System32\x`,
			want: `%SystemRoot:~0%\System32\x`,
		},
		{
			name: "only the first occurrence is rewritten",
			in:   `copy %TEMP%\a %TEMP%\b`,
			want: `copy %TEMP:~0%\a %TEMP%\b`,
		},
		{
			name: "underscore-prefixed name",
			in:   `echo %_x1%`,
			want: `echo %_x1:~0%`,
		},
		{
			name: "no variable reference",
			in:   `cmd.exe /c whoami`,
			want: "",
		},
		{
			name: "bare percent signs are not a reference",
			in:   `echo 50% off`,
			want: "",
		},
		{
			name: "already a substring expression",
			in:   `echo %SystemRoot:~0%`,
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := applyOne(t, envVarSubstringIdentity{}, tc.in); got != tc.want {
				t.Errorf("Apply(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestShortPath8dot3(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "program files",
			in:   `"C:\Program Files\Foo\bar.exe"`,
			want: `"C:\PROGRA~1\Foo\bar.exe"`,
		},
		{
			name: "x86 wins over the prefix it contains",
			in:   `C:\Program Files (x86)\Foo\bar.exe`,
			want: `C:\PROGRA~2\Foo\bar.exe`,
		},
		{
			name: "programdata",
			in:   `C:\ProgramData\Foo\bar.exe`,
			want: `C:\PROGRA~3\Foo\bar.exe`,
		},
		{
			name: "documents and settings",
			in:   `C:\Documents and Settings\All Users\x.bat`,
			want: `C:\DOCUME~1\All Users\x.bat`,
		},
		{
			name: "case insensitive match preserves the rest verbatim",
			in:   `c:\program files\Foo\BAR.exe -Flag`,
			want: `c:\PROGRA~1\Foo\BAR.exe -Flag`,
		},
		{
			name: "arbitrary directory has no derivable short name",
			in:   `C:\Users\victim\AppData\Local\Temp\x.exe`,
			want: "",
		},
		{
			name: "variable reference is not a path component",
			in:   `%ProgramData%\Foo\bar.exe`,
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := applyOne(t, shortPath8dot3{}, tc.in); got != tc.want {
				t.Errorf("Apply(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestCmdMutatorsAreRegisteredAndDeterministic(t *testing.T) {
	want := map[string]bool{
		"arg-separator-substitution": false,
		"env-var-substring-identity": false,
		"short-path-8dot3":           false,
	}
	for _, m := range Catalog() {
		if _, ok := want[m.Name()]; ok {
			want[m.Name()] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("mutator %q is not in the catalog", name)
		}
	}

	inputs := []string{
		`cmd.exe /c ping 127.0.0.1 -n 5`,
		`%SystemRoot%\System32\cmd.exe /c "C:\Program Files\Foo\bar.exe"`,
		`powershell.exe -enc SQBFAFgAKAB0AGUAcwB0ACkA`,
	}
	for _, m := range []Mutator{argSeparatorSubstitution{}, envVarSubstringIdentity{}, shortPath8dot3{}} {
		for _, in := range inputs {
			first := m.Apply(in)
			for i := 0; i < 5; i++ {
				again := m.Apply(in)
				if len(again) != len(first) {
					t.Fatalf("%s(%q) output length varies between runs", m.Name(), in)
				}
				for j := range again {
					if again[j] != first[j] {
						t.Fatalf("%s(%q) output varies between runs: %+v vs %+v", m.Name(), in, first, again)
					}
				}
			}
		}
	}
}
