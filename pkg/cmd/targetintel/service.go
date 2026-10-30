package targetintel

import (
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vulncheck-oss/cli/internal/output"
	"github.com/vulncheck-oss/cli/pkg/i18n"
	"github.com/vulncheck-oss/cli/pkg/targetintel"
)

// protocolHelp is the help text of one protocol's command.
type protocolHelp struct {
	short, long, example string
}

func protocolHelps() map[string]protocolHelp {
	return map[string]protocolHelp{
		"http": {i18n.C.TargetIntelServiceHTTPShort, i18n.C.TargetIntelServiceHTTPLong, i18n.C.TargetIntelServiceHTTPExample},
	}
}

func serviceCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "service <protocol>",
		Short: i18n.C.TargetIntelServiceShort,
		Long:  i18n.C.TargetIntelServiceLong,
		Args:  validArgs(cobra.NoArgs),
		RunE:  groupRunE,
	}
	helps := protocolHelps()
	for _, name := range targetintel.ProtocolNames() {
		cmd.AddCommand(protocolCommand(targetintel.Protocols[name], helps[name]))
	}

	return cmd
}

// protocolCommand builds the configuration list for one protocol, with one
// flag per registry filter.
func protocolCommand(p targetintel.Protocol, help protocolHelp) *cobra.Command {
	var f queryFlags
	filters := make(map[string]*string, len(p.Filters))
	var days, limit int
	var all, dryRun bool

	use := []string{p.Name}
	for _, flt := range p.Filters {
		use = append(use, "[--"+flt.Flag+" "+flt.Arg+"]")
	}
	use = append(use, "[--days <n>]")

	cmd := &cobra.Command{
		Use:     strings.Join(use, " "),
		Short:   help.short,
		Long:    help.long,
		Example: help.example,
		Args:    validArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			q := targetintel.ServiceQuery{Protocol: p.Name, Filters: map[string]string{}, LookbackDays: days}
			for flag, v := range filters {
				q.Filters[flag] = *v
			}
			s, opts, err := f.options(cmd, "")
			if err != nil {
				return err
			}
			if q.Limit, err = rowLimit(limit, all); err != nil {
				return err
			}
			sql, params, err := s.ServiceConfigurations(q)
			if err != nil {
				return err
			}
			// The row cap is the SQL's LIMIT, so read every row it returns.
			opts.SQL, opts.Params, opts.Limit = sql, params, 0

			c, err := newClient(cmd.Context(), s)
			if err != nil {
				return err
			}
			defer func() { _ = c.Close() }()

			if dryRun {
				return renderEstimate(cmd, c, opts)
			}

			return runConfigurations(cmd, c, opts, s, p, q)
		},
	}
	f.bindCommon(cmd)
	for _, flt := range p.Filters {
		filters[flt.Flag] = cmd.Flags().String(flt.Flag, "", flt.Usage)
	}
	cmd.Flags().IntVar(&days, "days", 30, "Lookback window in days on last_seen (1 to "+strconv.Itoa(targetintel.MaxServiceLookbackDays)+"); also bounds the partitions scanned")
	cmd.Flags().IntVar(&limit, "limit", 100, "Max configurations to return, applied in SQL")
	cmd.Flags().BoolVar(&all, "all", false, "Return every matching configuration (no LIMIT; a broad filter can then run out of resources)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print the estimate and exit without running the query")

	return cmd
}

// runConfigurations renders the configuration list. The LIMIT is in the
// SQL, so total_rows is the rows returned rather than the rows matched;
// the text summary says how many came back and whether the cap was hit.
func runConfigurations(cmd *cobra.Command, c *targetintel.Client, opts targetintel.QueryOptions, s targetintel.Settings, p targetintel.Protocol, q targetintel.ServiceQuery) error {
	r := output.FromCmd(cmd)
	res, err := c.Run(cmd.Context(), opts)
	if err != nil {
		return err
	}
	if r.IsJSON() {
		extra := map[string]any{
			"table": s.Project + "." + s.Dataset + "." + p.SnapshotTable,
			"query": serviceEcho(p, opts, q),
		}

		return r.JSON(resultPayload{SchemaVersion: output.SchemaVersion, Extra: extra, Result: res})
	}
	note := ""
	if q.Limit > 0 && res.ReturnedRows >= q.Limit {
		note = " (limit reached; narrow the filters or raise --limit for more)"
	}
	r.Info("Billed %s (%s%s), %s%s",
		targetintel.FormatCost(res.CostUSD), targetintel.FormatBytes(res.BytesBilled), capNote(opts), countNoun(res.ReturnedRows, "configuration"), note)
	if res.ReturnedRows == 0 {
		r.Warn("No %s configuration matched in the last %s.", p.Name, countNoun(q.LookbackDays, "day"))

		return nil
	}

	return renderRows(cmd, res, p.TextColumns)
}

// serviceEcho is the JSON query block: the protocol, the lookback and each
// filter set, as the value bound to BigQuery (a substring as its LIKE
// pattern, a hash lower-cased, a status as a number).
func serviceEcho(p targetintel.Protocol, opts targetintel.QueryOptions, q targetintel.ServiceQuery) map[string]any {
	echo := map[string]any{"protocol": p.Name, "lookback_days": q.LookbackDays}
	for _, param := range opts.Params {
		if param.Name != "limit" && param.Name != "lookback_days" {
			echo[param.Name] = param.Value
		}
	}

	return echo
}
