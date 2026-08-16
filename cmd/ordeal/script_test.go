package main

import (
	"os"
	"testing"

	"github.com/principlebreach/ordeal/internal/cli"
	"github.com/rogpeppe/go-internal/testscript"
)

// TestMain exposes the ordeal binary to testscript so end-to-end scripts can run
// the real command tree and assert on output and exit codes.
func TestMain(m *testing.M) {
	os.Exit(testscript.RunMain(m, map[string]func() int{
		"ordeal": cli.Execute,
	}))
}

// TestScripts runs the golden CLI scripts in testdata/script.
func TestScripts(t *testing.T) {
	testscript.Run(t, testscript.Params{Dir: "testdata/script"})
}
