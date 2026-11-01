package targetintel

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/vulncheck-oss/cli/internal/output"
	"github.com/vulncheck-oss/cli/pkg/i18n"
	"github.com/vulncheck-oss/cli/pkg/targetintel"
	"github.com/vulncheck-oss/cli/pkg/ui"
)

func routinesCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "routines <command>",
		Short: i18n.C.TargetIntelRoutinesShort,
		Args:  validArgs(cobra.NoArgs),
		RunE:  groupRunE,
	}
	cmd.AddCommand(routinesListCommand(), routinesDescribeCommand())

	return cmd
}

func routinesListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list [dataset]",
		Short: i18n.C.TargetIntelRoutinesListShort,
		Args:  validArgs(cobra.MaximumNArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			r := output.FromCmd(cmd)
			s, err := settingsFromCmd(cmd, targetintel.Overrides{})
			if err != nil {
				return err
			}
			dataset := s.ViewsDataset
			if len(args) == 1 {
				dataset = args[0]
			}
			ref, err := targetintel.ParseRef(dataset, s.Project, false)
			if err != nil {
				return err
			}
			c, err := newClient(cmd.Context(), s)
			if err != nil {
				return err
			}
			defer func() { _ = c.Close() }()

			routines, err := c.ListRoutines(cmd.Context(), ref)
			if err != nil {
				return err
			}
			if r.IsJSON() {
				return r.JSON(routines)
			}
			r.Info("%s in %s.%s", countNoun(len(routines), "routine"), ref.Project, ref.Dataset)
			rows := make([][]string, 0, len(routines))
			for _, rt := range routines {
				rows = append(rows, []string{rt.Name, targetintel.RoutineKind(rt.Type), rt.Language, rt.LastModified.Format(time.DateOnly), rt.Command})
			}
			r.Println(ui.Table([]string{"Routine", "Type", "Language", "Modified", "Command"}, rows))

			return nil
		},
	}
}

func routinesDescribeCommand() *cobra.Command {
	var showSQL bool
	cmd := &cobra.Command{
		Use:   "describe [<project>.][<dataset>.]<routine>",
		Short: i18n.C.TargetIntelRoutinesDescribeShort,
		Long:  i18n.C.TargetIntelRoutinesDescribeLong,
		Args:  validArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			r := output.FromCmd(cmd)
			s, err := settingsFromCmd(cmd, targetintel.Overrides{})
			if err != nil {
				return err
			}
			ref, err := targetintel.ParseRoutineRef(args[0], s)
			if err != nil {
				return err
			}
			c, err := newClient(cmd.Context(), s)
			if err != nil {
				return err
			}
			defer func() { _ = c.Close() }()

			info, err := c.DescribeRoutine(cmd.Context(), ref, showSQL)
			if err != nil {
				return err
			}
			if r.IsJSON() {
				return r.JSON(info)
			}

			r.Stat("Routine", info.Project+"."+info.Dataset+"."+info.Name)
			r.Stat("Type", targetintel.RoutineKind(info.Type))
			if info.Language != "" {
				r.Stat("Language", info.Language)
			}
			if info.Description != "" {
				r.Stat("Description", info.Description)
			}
			if info.Command != "" {
				r.Stat("Called by", "vulncheck target-intel "+info.Command)
			}
			r.Stat("Modified", info.LastModified.Format(time.DateOnly))
			if info.ReturnType != "" {
				r.Stat("Returns", info.ReturnType)
			}
			if len(info.Arguments) > 0 {
				rows := make([][]string, 0, len(info.Arguments))
				for _, a := range info.Arguments {
					rows = append(rows, []string{a.Name, a.Type, a.Mode})
				}
				r.Println(ui.Table([]string{"Argument", "Type", "Mode"}, rows))
			}
			if len(info.ReturnColumns) > 0 {
				rows := make([][]string, 0, len(info.ReturnColumns))
				for _, col := range info.ReturnColumns {
					rows = append(rows, []string{col.Name, col.Type})
				}
				r.Println(ui.Table([]string{"Returned column", "Type"}, rows))
			}
			if info.Body != "" {
				r.Println(info.Body)
			}

			return nil
		},
	}
	cmd.Flags().BoolVar(&showSQL, "show-sql", false, "Include the routine's SQL body")

	return cmd
}
