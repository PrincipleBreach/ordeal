package testcase

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzLoad feeds arbitrary bytes to the suite loader. Ordeal ingests
// third-party rule repositories, so the YAML path is an untrusted-input surface:
// the loader must return an error, never panic, on malformed input.
func FuzzLoad(f *testing.F) {
	f.Add([]byte("rule: r.yml\ncases:\n  - name: a\n    event: {A: b}\n"))
	f.Add([]byte("rule: r.yml\ncases: []\n"))
	f.Add([]byte("not: valid: yaml: ["))
	f.Add([]byte(""))
	f.Add([]byte("cases:\n  - name: a\n    event: {A: b}\n    match: notabool\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "case.test.yml")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Skip()
		}
		// The only contract under fuzzing is: do not panic. A returned error is a
		// perfectly good outcome, and a valid parse must yield a usable suite.
		s, err := Load(path)
		if err == nil && s == nil {
			t.Fatal("Load returned nil suite and nil error")
		}
	})
}
