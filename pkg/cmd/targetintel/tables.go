package targetintel

import (
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vulncheck-oss/cli/internal/output"
	"github.com/vulncheck-oss/cli/pkg/i18n"
	"github.com/vulncheck-oss/cli/pkg/targetintel"
	"github.com/vulncheck-oss/cli/pkg/ui"
)

func tablesCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tables <command>",
		Short: i18n.C.TargetIntelTablesShort,
	}
	cmd.AddCommand(tablesListCommand(), tablesDescribeCommand())

	return cmd
}

func tablesListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list <dataset>",
		Short: i18n.C.TargetIntelTablesListShort,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r := output.FromCmd(cmd)
			s := settingsFromCmd(cmd, targetintel.Overrides{})
			ref, err := targetintel.ParseRef(args[0], s.Project, false)
			if err != nil {
				return err
			}
			c, err := targetintel.NewClient(cmd.Context(), s)
			if err != nil {
				return err
			}
			defer func() { _ = c.Close() }()

			tables, err := c.ListTables(cmd.Context(), ref)
			if err != nil {
				return err
			}
			if r.IsJSON() {
				return r.JSON(tables)
			}
			r.Info("%d tables in %s.%s", len(tables), ref.Project, ref.Dataset)
			rows := make([][]string, 0, len(tables))
			for _, t := range tables {
				rows = append(rows, []string{t.Table})
			}
			r.Println(ui.Table([]string{"Table"}, rows))

			return nil
		},
	}
}

func tablesDescribeCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "describe <dataset>.<table>",
		Short: i18n.C.TargetIntelTablesDescribeShort,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r := output.FromCmd(cmd)
			s := settingsFromCmd(cmd, targetintel.Overrides{})
			ref, err := targetintel.ParseRef(args[0], s.Project, true)
			if err != nil {
				return err
			}
			c, err := targetintel.NewClient(cmd.Context(), s)
			if err != nil {
				return err
			}
			defer func() { _ = c.Close() }()

			info, err := c.DescribeTable(cmd.Context(), ref)
			if err != nil {
				return err
			}
			if r.IsJSON() {
				return r.JSON(info)
			}

			r.Stat("Table", info.Project+"."+info.Dataset+"."+info.Table)
			r.Stat("Type", info.Type)
			if info.Description != "" {
				r.Stat("Description", info.Description)
			}
			r.Stat("Rows", strconv.FormatUint(info.NumRows, 10))
			r.Stat("Size", targetintel.FormatBytes(info.NumBytes)+" (full scan "+targetintel.FormatCost(info.FullScanCostUSD)+")")
			if info.PartitionField != "" {
				r.Stat("Partitioned on", info.PartitionField+" ("+info.PartitionType+")")
			}
			if len(info.ClusteringFields) > 0 {
				r.Stat("Clustered on", strings.Join(info.ClusteringFields, ", "))
			}
			rows := make([][]string, 0, len(info.Schema))
			for _, col := range info.Schema {
				rows = append(rows, []string{col.Name, col.Type, col.Mode})
			}
			r.Println(ui.Table([]string{"Column", "Type", "Mode"}, rows))

			return nil
		},
	}
}
