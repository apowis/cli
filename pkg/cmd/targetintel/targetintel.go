// Package targetintel implements `vulncheck target-intel`: querying VulnCheck
// Target Intelligence scan data in BigQuery with a cost gate on every query.
package targetintel

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/vulncheck-oss/cli/internal/errs"
	"github.com/vulncheck-oss/cli/pkg/i18n"
	"github.com/vulncheck-oss/cli/pkg/session"
	"github.com/vulncheck-oss/cli/pkg/targetintel"
)

// Command returns the target-intel command tree.
func Command() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "target-intel <command>",
		Aliases: []string{"ti"},
		Short:   i18n.C.TargetIntelShort,
		Long:    i18n.C.TargetIntelLong,
		GroupID: "core",
		Args:    validArgs(cobra.NoArgs),
		RunE:    groupRunE,
		Example: i18n.C.TargetIntelExample,
	}

	// Target Intelligence authenticates with Google, not a VulnCheck API
	// token, so the root token check does not apply.
	session.DisableAuthCheck(cmd)

	// A flag that fails to parse is bad input like any other, so it exits 2
	// (validation) rather than 1. Subcommands inherit this.
	cmd.SetFlagErrorFunc(func(c *cobra.Command, err error) error {
		return errs.Wrap(errs.KindValidation, err, "%s", err.Error()).WithHint("run `%s --help` for usage", c.CommandPath())
	})

	cmd.PersistentFlags().String("project", "", "GCP billing project (env: "+targetintel.EnvProject+")")
	cmd.PersistentFlags().String("location", "", "BigQuery location (env: "+targetintel.EnvLocation+", default "+targetintel.DefaultLocation+")")
	cmd.PersistentFlags().String("views-dataset", "", "Dataset holding the observations_by_* routines (env: "+targetintel.EnvViewsDataset+", default "+targetintel.DefaultViewsDataset+")")
	cmd.PersistentFlags().String("dataset", "", "Dataset holding the warehouse tables read by host and cves --counts (env: "+targetintel.EnvDataset+", default "+targetintel.DefaultDataset+")")

	cmd.AddCommand(authCommand())
	cmd.AddCommand(datasetsCommand())
	cmd.AddCommand(tablesCommand())
	cmd.AddCommand(queryCommand())
	cmd.AddCommand(estimateCommand())
	cmd.AddCommand(cvesCommand())
	cmd.AddCommand(productCommand())
	cmd.AddCommand(hostCommand())
	cmd.AddCommand(serviceCommand())
	cmd.AddCommand(usageCommand())

	return cmd
}

// newClient resolves credentials, opens the BigQuery client and attaches the
// usage log. It is a variable so tests can point the commands at a fake
// BigQuery server.
var newClient = openClient

// settingsFromCmd resolves Settings from the persistent flags plus any
// per-command overrides.
func settingsFromCmd(cmd *cobra.Command, o targetintel.Overrides) (targetintel.Settings, error) {
	if v, _ := cmd.Flags().GetString("project"); v != "" {
		o.Project = v
	}
	if v, _ := cmd.Flags().GetString("location"); v != "" {
		o.Location = v
	}
	if v, _ := cmd.Flags().GetString("views-dataset"); v != "" {
		o.ViewsDataset = v
	}
	if v, _ := cmd.Flags().GetString("dataset"); v != "" {
		o.Dataset = v
	}

	s := targetintel.ResolveSettings(o)

	return s, s.Validate()
}

// validArgs wraps a positional-argument check so a wrong argument count
// exits 2 (validation) like every other input error, not 1.
func validArgs(check cobra.PositionalArgs) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if err := check(cmd, args); err != nil {
			return errs.Wrap(errs.KindValidation, err, "%s", err.Error()).WithHint("run `%s --help` for usage", cmd.CommandPath())
		}

		return nil
	}
}

// groupRunE makes a command group runnable so cobra validates its
// arguments: without it a mistyped subcommand prints help and exits 0.
// With no arguments it still prints help.
func groupRunE(cmd *cobra.Command, _ []string) error {
	return cmd.Help()
}

// countNoun renders "1 table" or "3 tables".
func countNoun(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}

	return fmt.Sprintf("%d %ss", n, noun)
}
