// Package cli wires the Ordeal command tree.
package cli

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/principlebreach/ordeal/internal/engine"
	"github.com/principlebreach/ordeal/internal/lint"
	"github.com/principlebreach/ordeal/internal/mutate"
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
	exitFindings = 1 // test failed, a detection was evaded, or lint found an error
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
	root.AddCommand(newRunCmd(), newMutateCmd(), newLintCmd(), newListCmd())
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
			suites, err := discover(args)
			if err != nil {
				return err
			}
			rn := runner.New(engine.NewNative())
			rep, err := rn.RunTests(context.Background(), suites)
			if err != nil {
				return usageErr(err)
			}
			if err := report.Tests(cmd.OutOrStdout(), rep, report.Format(format)); err != nil {
				return usageErr(err)
			}
			mutationFailed := false
			if mutateToo {
				mrep, err := rn.RunMutations(context.Background(), suites)
				if err != nil {
					return usageErr(err)
				}
				fmt.Fprintln(cmd.OutOrStdout())
				_ = report.Mutations(cmd.OutOrStdout(), mrep, report.Format(format))
				mutationFailed = !mrep.OK()
			}
			if !rep.OK() || mutationFailed {
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
	var only, skip []string
	cmd := &cobra.Command{
		Use:   "mutate [paths...]",
		Short: "Attack rules with known evasions and report what slips past",
		Long: "For every positive test case that fires, Ordeal applies its catalog of\n" +
			"semantics-preserving command-line evasions (flag abbreviation, caret and\n" +
			"quote insertion, windash, environment indirection, and more) and reports\n" +
			"each mutation that stops the rule from firing.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			suites, err := discover(args)
			if err != nil {
				return err
			}
			mutators := mutate.Select(mutate.Options{Only: only, Skip: skip})
			if len(mutators) == 0 {
				return usageErr(fmt.Errorf("no mutators selected"))
			}
			rn := runner.New(engine.NewNative())
			rep, err := rn.RunMutationsWith(context.Background(), suites, mutators)
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
	cmd.Flags().StringSliceVar(&only, "only", nil, "restrict to these mutators (comma-separated names)")
	cmd.Flags().StringSliceVar(&skip, "skip", nil, "exclude these mutators (comma-separated names)")
	return cmd
}

func newLintCmd() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "lint [paths...]",
		Short: "Report untested rules and broken or thin test suites",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rep, err := lint.Run(args)
			if err != nil {
				return usageErr(err)
			}
			w := cmd.OutOrStdout()
			var werr error
			if format == "json" {
				werr = rep.WriteJSON(w)
			} else {
				werr = rep.WriteHuman(w)
			}
			if werr != nil {
				return usageErr(werr)
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

func newListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the built-in evasion catalog",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "mutators",
		Short: "List every mutator, its ATT&CK anchor, and what it does",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tTECHNIQUE\tDESCRIPTION")
			for _, m := range mutate.Catalog() {
				fmt.Fprintf(tw, "%s\t%s\t%s\n", m.Name(), m.Technique(), m.Describe())
			}
			return tw.Flush()
		},
	})
	return cmd
}

// discover loads suites from paths and turns an empty result into a usage error.
func discover(paths []string) ([]*testcase.Suite, error) {
	suites, err := testcase.Discover(paths)
	if err != nil {
		return nil, usageErr(err)
	}
	if len(suites) == 0 {
		return nil, usageErr(fmt.Errorf("no %s files found in %v", testcase.Suffix, paths))
	}
	return suites, nil
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

func usageErr(err error) error {
	if ce, ok := err.(codedError); ok {
		return ce
	}
	return codedError{code: exitUsage, msg: err.Error()}
}

func asCoded(err error, out *codedError) bool {
	if ce, ok := err.(codedError); ok {
		*out = ce
		return true
	}
	return false
}
