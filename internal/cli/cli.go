// Package cli wires the Ordeal command tree.
package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/principlebreach/ordeal/internal/engine"
	"github.com/principlebreach/ordeal/internal/report"
	"github.com/principlebreach/ordeal/internal/runner"
	"github.com/principlebreach/ordeal/internal/testcase"
	"github.com/spf13/cobra"
)

// version is overridden at build time via -ldflags.
var version = "dev"

// Exit codes, chosen so CI can tell "your rule is wrong" from "the tool broke".
const (
	exitOK       = 0
	exitFindings = 1 // test failed, or a detection was evaded
	exitUsage    = 2 // bad flags/paths/config
)

// Execute runs the root command and returns a process exit code.
func Execute() int {
	root := newRoot()
	if err := root.Execute(); err != nil {
		var ce codedError
		if asCoded(err, &ce) {
			if ce.msg != "" {
				fmt.Fprintln(os.Stderr, "ordeal: "+ce.msg)
			}
			return ce.code
		}
		fmt.Fprintln(os.Stderr, "ordeal: "+err.Error())
		return exitUsage
	}
	return exitOK
}

func newRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   "ordeal",
		Short: "Adversarial test harness for Sigma detection rules",
		Long: "Ordeal puts detection rules through trial by fire. It asserts that a\n" +
			"rule fires on the events it should — then attacks the rule with known\n" +
			"evasions and reports what slips past.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version,
	}
	root.AddCommand(newRunCmd(), newMutateCmd())
	return root
}

func newRunCmd() *cobra.Command {
	var format string
	var mutateToo bool
	cmd := &cobra.Command{
		Use:   "run [paths...]",
		Short: "Assert that rules fire on their declared test cases",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			suites, err := testcase.Discover(args)
			if err != nil {
				return usageErr(err)
			}
			if len(suites) == 0 {
				return usageErr(fmt.Errorf("no %s files found in %v", testcase.Suffix, args))
			}
			rn := runner.New(engine.NewNative())
			rep, err := rn.RunTests(context.Background(), suites)
			if err != nil {
				return usageErr(err)
			}
			if err := report.Tests(cmd.OutOrStdout(), rep, report.Format(format)); err != nil {
				return usageErr(err)
			}
			if mutateToo {
				mrep, err := rn.RunMutations(context.Background(), suites)
				if err != nil {
					return usageErr(err)
				}
				fmt.Fprintln(cmd.OutOrStdout())
				_ = report.Mutations(cmd.OutOrStdout(), mrep, report.Format(format))
				if !mrep.OK() && rep.OK() {
					return codedError{code: exitFindings}
				}
			}
			if !rep.OK() {
				return codedError{code: exitFindings}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&format, "format", "f", "human", "output format: human, json, junit")
	cmd.Flags().BoolVar(&mutateToo, "mutate", false, "also run adversarial mutation after the unit tests")
	return cmd
}

func newMutateCmd() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "mutate [paths...]",
		Short: "Attack rules with known evasions and report what slips past",
		Long: "For every positive test case that fires, Ordeal applies its catalog of\n" +
			"semantics-preserving command-line evasions (flag abbreviation, caret and\n" +
			"quote insertion, windash, environment indirection, and more) and reports\n" +
			"each mutation that stops the rule from firing.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			suites, err := testcase.Discover(args)
			if err != nil {
				return usageErr(err)
			}
			if len(suites) == 0 {
				return usageErr(fmt.Errorf("no %s files found in %v", testcase.Suffix, args))
			}
			rn := runner.New(engine.NewNative())
			rep, err := rn.RunMutations(context.Background(), suites)
			if err != nil {
				return usageErr(err)
			}
			if err := report.Mutations(cmd.OutOrStdout(), rep, report.Format(format)); err != nil {
				return usageErr(err)
			}
			if !rep.OK() {
				return codedError{code: exitFindings}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&format, "format", "f", "human", "output format: human, json")
	return cmd
}

// --- typed exit codes ----------------------------------------------------

type codedError struct {
	code int
	msg  string
}

func (e codedError) Error() string {
	if e.msg != "" {
		return e.msg
	}
	return fmt.Sprintf("exit %d", e.code)
}

func usageErr(err error) error { return codedError{code: exitUsage, msg: err.Error()} }

func asCoded(err error, out *codedError) bool {
	if ce, ok := err.(codedError); ok {
		*out = ce
		return true
	}
	return false
}
