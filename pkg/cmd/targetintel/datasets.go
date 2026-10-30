package targetintel

import (
	"github.com/spf13/cobra"

	"github.com/vulncheck-oss/cli/internal/output"
	"github.com/vulncheck-oss/cli/pkg/i18n"
	"github.com/vulncheck-oss/cli/pkg/targetintel"
	"github.com/vulncheck-oss/cli/pkg/ui"
)

func datasetsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "datasets <command>",
		Short: i18n.C.TargetIntelDatasetsShort,
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: i18n.C.TargetIntelDatasetsListShort,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			r := output.FromCmd(cmd)
			c, err := targetintel.NewClient(cmd.Context(), settingsFromCmd(cmd, targetintel.Overrides{}))
			if err != nil {
				return err
			}
			defer func() { _ = c.Close() }()

			datasets, err := c.ListDatasets(cmd.Context())
			if err != nil {
				return err
			}
			if r.IsJSON() {
				return r.JSON(datasets)
			}
			r.Info("%d datasets in %s", len(datasets), c.Settings.Project)
			rows := make([][]string, 0, len(datasets))
			for _, d := range datasets {
				rows = append(rows, []string{d.Project + "." + d.Dataset})
			}
			r.Println(ui.Table([]string{"Dataset"}, rows))

			return nil
		},
	})

	return cmd
}
