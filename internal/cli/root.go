package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

const (
	formatText = "text"
	formatJSON = "json"
)

// errInvalidReport means a validation report found errors. The report itself
// explains them, so Execute writes nothing more.
var errInvalidReport = errors.New("validation report is invalid")

// NewCommand constructs the k8s-authz command tree. Commands read the command's
// input stream and write to its output stream.
func NewCommand() *cobra.Command {
	command := &cobra.Command{
		Use:           "k8s-authz",
		Short:         "Validate, explain, and configure k8s-authz authorization",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	command.AddCommand(newValidateCommand())
	command.AddCommand(newRenderCallerConfigCommand())
	command.AddCommand(newExplainCommand())
	return command
}

// Execute runs command and returns its process exit code: 1 when a validation
// report found errors, and 2 when the command couldn't run. It writes any
// other error to the command's error stream.
func Execute(ctx context.Context, command *cobra.Command) int {
	err := command.ExecuteContext(ctx)
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errInvalidReport):
		return 1
	}
	_, _ = fmt.Fprintln(command.ErrOrStderr(), err)
	return 2
}

// registerOutputFlag adds -o/--output and its completion to command.
func registerOutputFlag(command *cobra.Command, output *string) {
	command.Flags().StringVarP(output, "output", "o", formatText, "output format: text or json")
	_ = command.RegisterFlagCompletionFunc("output", cobra.FixedCompletions([]string{formatText, formatJSON}, cobra.ShellCompDirectiveNoFileComp))
}

func checkOutput(output string) error {
	if output != formatText && output != formatJSON {
		return fmt.Errorf("unsupported output format %q", output)
	}
	return nil
}
