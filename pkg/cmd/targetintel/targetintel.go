// Package targetintel implements `vulncheck target-intel`: querying VulnCheck
// Target Intelligence scan data in BigQuery with a cost gate on every query.
package targetintel

import (
	"github.com/MakeNowJust/heredoc/v2"
	"github.com/spf13/cobra"

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
		Example: heredoc.Doc(`
			$ vulncheck target-intel auth login
			$ vulncheck target-intel datasets list
			$ vulncheck target-intel tables describe anchorbreaker_views_prod.timeline
			$ vulncheck target-intel cves --cves CVE-2024-6387 --days 30
			$ vulncheck target-intel query --limit 10 --query "SELECT ip, port FROM anchorbreaker_views_prod.timeline WHERE ..."
		`),
	}

	// Target Intelligence authenticates with Google, not a VulnCheck API
	// token, so the root token check does not apply.
	session.DisableAuthCheck(cmd)

	cmd.PersistentFlags().String("project", "", "GCP billing project (env: "+targetintel.EnvProject+")")
	cmd.PersistentFlags().String("location", "", "BigQuery location (env: "+targetintel.EnvLocation+", default "+targetintel.DefaultLocation+")")
	cmd.PersistentFlags().String("views-dataset", "", "Dataset holding the observations_by_* routines (env: "+targetintel.EnvViewsDataset+", default "+targetintel.DefaultViewsDataset+")")

	cmd.AddCommand(authCommand())
	cmd.AddCommand(datasetsCommand())
	cmd.AddCommand(tablesCommand())
	cmd.AddCommand(queryCommand())
	cmd.AddCommand(estimateCommand())
	cmd.AddCommand(cvesCommand())

	return cmd
}

// settingsFromCmd resolves Settings from the persistent flags plus any
// per-command overrides.
func settingsFromCmd(cmd *cobra.Command, o targetintel.Overrides) targetintel.Settings {
	if v, _ := cmd.Flags().GetString("project"); v != "" {
		o.Project = v
	}
	if v, _ := cmd.Flags().GetString("location"); v != "" {
		o.Location = v
	}
	if v, _ := cmd.Flags().GetString("views-dataset"); v != "" {
		o.ViewsDataset = v
	}

	return targetintel.ResolveSettings(o)
}
