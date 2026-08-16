package lint

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const certutilRule = `title: Certutil Download From URL
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\certutil.exe'
  condition: selection
level: high
`

const suitePositiveAndNegative = `rule: rule.yml
cases:
  - name: fires
    event:
      Image: 'C:\Windows\System32\certutil.exe'
    match: true
  - name: benign
    event:
      Image: 'C:\Windows\System32\where.exe'
    match: false
`

const suitePositiveOnly = `rule: rule.yml
cases:
  - name: fires
    event:
      Image: 'C:\Windows\System32\certutil.exe'
    match: true
`

const suiteNegativeOnly = `rule: rule.yml
cases:
  - name: benign
    event:
      Image: 'C:\Windows\System32\where.exe'
    match: false
`

// writeTree materializes files (relative path -> contents) under a fresh temp
// directory and returns its root.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	return root
}

// relative rewrites finding paths to slash-separated paths under root, so
// expectations can be written literally.
func relative(t *testing.T, root string, findings []Finding) []Finding {
	t.Helper()
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		rel, err := filepath.Rel(root, f.Path)
		if err != nil {
			t.Fatalf("rel %s: %v", f.Path, err)
		}
		f.Path = filepath.ToSlash(rel)
		out = append(out, f)
	}
	return out
}

func TestRun(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  []Finding
	}{
		{
			name: "tested rule is clean",
			files: map[string]string{
				"rule.yml":      certutilRule,
				"rule.test.yml": suitePositiveAndNegative,
			},
			want: nil,
		},
		{
			name: "untested rule",
			files: map[string]string{
				"rule.yml": certutilRule,
			},
			want: []Finding{{
				Severity: Warn,
				Path:     "rule.yml",
				Rule:     "Certutil Download From URL",
				Message:  "rule has no test suite; expected rule.test.yml",
			}},
		},
		{
			name: "dangling rule reference",
			files: map[string]string{
				"rule.test.yml": suitePositiveAndNegative,
			},
			want: []Finding{{
				Severity: Error,
				Path:     "rule.test.yml",
				Rule:     "rule.yml",
				Message:  `rule reference "rule.yml" does not exist`,
			}},
		},
		{
			name: "suite fails to load",
			files: map[string]string{
				"rule.yml":      certutilRule,
				"rule.test.yml": "cases:\n  - name: fires\n    event:\n      Image: certutil.exe\n",
			},
			want: []Finding{{
				Severity: Error,
				Path:     "rule.test.yml",
				Message:  "missing required field 'rule'",
			}},
		},
		{
			name: "suite has no negative cases",
			files: map[string]string{
				"rule.yml":      certutilRule,
				"rule.test.yml": suitePositiveOnly,
			},
			want: []Finding{{
				Severity: Warn,
				Path:     "rule.test.yml",
				Rule:     "Certutil Download From URL",
				Message:  "no case expects a non-match; the rule has no false-positive guard",
			}},
		},
		{
			name: "suite has no positive cases",
			files: map[string]string{
				"rule.yml":      certutilRule,
				"rule.test.yml": suiteNegativeOnly,
			},
			want: []Finding{{
				Severity: Warn,
				Path:     "rule.test.yml",
				Rule:     "Certutil Download From URL",
				Message:  "no case expects a match; mutation testing has nothing to attack",
			}},
		},
		{
			name: "configs and unrelated yaml are ignored",
			files: map[string]string{
				"rule.yml":      certutilRule,
				"rule.test.yml": suitePositiveAndNegative,
				"config.yml":    "title: Windows Mapping\norder: 1\nfieldmappings:\n  Image: process.executable\n",
				"notes.yaml":    "owner: detection-eng\n",
				"README.md":     "# rules\n",
			},
			want: nil,
		},
		{
			name: "findings are sorted by path then severity",
			files: map[string]string{
				"b/rule.yml":      certutilRule,
				"a/rule.test.yml": suitePositiveOnly,
			},
			want: []Finding{
				{
					Severity: Error,
					Path:     "a/rule.test.yml",
					Rule:     "rule.yml",
					Message:  `rule reference "rule.yml" does not exist`,
				},
				{
					Severity: Warn,
					Path:     "a/rule.test.yml",
					Rule:     "rule.yml",
					Message:  "no case expects a non-match; the rule has no false-positive guard",
				},
				{
					Severity: Warn,
					Path:     "b/rule.yml",
					Rule:     "Certutil Download From URL",
					Message:  "rule has no test suite; expected rule.test.yml",
				},
			},
		},
		{
			name: "rule referenced from another directory counts as tested",
			files: map[string]string{
				"rules/certutil.yml": certutilRule,
				"suites/certutil.test.yml": "rule: ../rules/certutil.yml\n" +
					strings.TrimPrefix(suitePositiveAndNegative, "rule: rule.yml\n"),
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := writeTree(t, tt.files)
			rep, err := Run([]string{root})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			got := relative(t, root, rep.Findings)
			if len(got) == 0 && len(tt.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("findings mismatch\n got: %+v\nwant: %+v", got, tt.want)
			}
		})
	}
}

func TestRunAcceptsFileArguments(t *testing.T) {
	root := writeTree(t, map[string]string{"rule.yml": certutilRule})
	rep, err := Run([]string{filepath.Join(root, "rule.yml")})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].Severity != Warn {
		t.Fatalf("want one warning for the untested rule, got %+v", rep.Findings)
	}
}

func TestRunMissingPath(t *testing.T) {
	if _, err := Run([]string{filepath.Join(t.TempDir(), "absent")}); err == nil {
		t.Fatal("want an error for a path that does not exist")
	}
}

func TestReportCounts(t *testing.T) {
	empty := Report{}
	if !empty.OK() || empty.Errors() != 0 || empty.Warnings() != 0 {
		t.Errorf("empty report should be clean, got %+v", empty)
	}

	r := Report{Findings: []Finding{
		{Severity: Error, Path: "a.test.yml", Message: "boom"},
		{Severity: Warn, Path: "b.yml", Message: "meh"},
		{Severity: Warn, Path: "c.yml", Message: "meh"},
	}}
	if got := r.Errors(); got != 1 {
		t.Errorf("Errors() = %d, want 1", got)
	}
	if got := r.Warnings(); got != 2 {
		t.Errorf("Warnings() = %d, want 2", got)
	}
	if r.OK() {
		t.Error("OK() = true, want false with an error present")
	}
}

func TestWriteHuman(t *testing.T) {
	tests := []struct {
		name   string
		report Report
		want   string
	}{
		{
			name:   "clean",
			report: Report{},
			want:   "0 errors, 0 warnings\n",
		},
		{
			name: "findings",
			report: Report{Findings: []Finding{
				{Severity: Error, Path: "rules/a.test.yml", Rule: "a.yml", Message: `rule reference "a.yml" does not exist`},
				{Severity: Warn, Path: "rules/b.yml", Rule: "B", Message: "rule has no test suite; expected b.test.yml"},
			}},
			want: "ERROR  rules/a.test.yml  rule reference \"a.yml\" does not exist\n" +
				"WARN   rules/b.yml  rule has no test suite; expected b.test.yml\n" +
				"\n1 errors, 1 warnings\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tt.report.WriteHuman(&buf); err != nil {
				t.Fatalf("WriteHuman: %v", err)
			}
			if got := buf.String(); got != tt.want {
				t.Errorf("WriteHuman()\n got: %q\nwant: %q", got, tt.want)
			}
		})
	}
}

func TestWriteJSON(t *testing.T) {
	r := Report{Findings: []Finding{
		{Severity: Warn, Path: "rules/b.yml", Rule: "B", Message: "rule has no test suite; expected b.test.yml"},
	}}
	var buf bytes.Buffer
	if err := r.WriteJSON(&buf); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	want := `{
  "findings": [
    {
      "severity": "warn",
      "path": "rules/b.yml",
      "rule": "B",
      "message": "rule has no test suite; expected b.test.yml"
    }
  ],
  "errors": 0,
  "warnings": 1
}
`
	if got := buf.String(); got != want {
		t.Errorf("WriteJSON()\n got: %s\nwant: %s", got, want)
	}
}

func TestWriteJSONEmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := (Report{}).WriteJSON(&buf); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if !strings.Contains(buf.String(), `"findings": []`) {
		t.Errorf("empty report should encode findings as [], got %s", buf.String())
	}
}

func TestSeverityString(t *testing.T) {
	tests := []struct {
		severity Severity
		want     string
	}{
		{Error, "error"},
		{Warn, "warn"},
		{Severity(42), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.severity.String(); got != tt.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tt.severity, got, tt.want)
		}
	}
}
