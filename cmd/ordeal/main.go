// Command ordeal is the Principle Breach adversarial test harness for Sigma
// detection rules.
package main

import (
	"os"

	"github.com/principlebreach/ordeal/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
