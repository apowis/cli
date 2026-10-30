package targetintel

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/vulncheck-oss/cli/internal/errs"
	"github.com/vulncheck-oss/cli/internal/output"
	"github.com/vulncheck-oss/cli/pkg/i18n"
	"github.com/vulncheck-oss/cli/pkg/targetintel"
	"github.com/vulncheck-oss/cli/pkg/ui"
)

// queryFlags are the flags shared by query and estimate.
type queryFlags struct {
	sql      string
	fromFile string
	maxCost  float64
	noCache  bool
	timeout  time.Duration
}

func (f *queryFlags) bind(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&f.sql, "query", "q", "", "SQL to run")
	cmd.Flags().StringVar(&f.fromFile, "from-file", "", `Read SQL from a file ("-" for stdin)`)
	f.bindCommon(cmd)
}

// bindCommon binds the flags every query-running command shares.
func (f *queryFlags) bindCommon(cmd *cobra.Command) {
	cmd.Flags().Float64Var(&f.maxCost, "max-cost", targetintel.DefaultMaxCostUSD,
		"Max estimated cost in USD before the query is refused (env: "+targetintel.EnvMaxCost+"; 0 disables the limit)")
	cmd.Flags().BoolVar(&f.noCache, "no-cache", false, "Disable the BigQuery result cache")
	cmd.Flags().DurationVar(&f.timeout, "timeout", 5*time.Minute, "Job timeout")
}

// readSQL resolves the statement from --query, --from-file or piped stdin.
func (f *queryFlags) readSQL(cmd *cobra.Command, stdin io.Reader) (string, error) {
	switch {
	case f.sql != "" && f.fromFile != "":
		return "", errs.Validation("--query and --from-file are mutually exclusive")
	case f.sql != "":
		return f.sql, nil
	case f.fromFile == "-":
		b, err := io.ReadAll(stdin)
		if err != nil {
			return "", err
		}

		return string(b), nil
	case f.fromFile != "":
		b, err := os.ReadFile(f.fromFile)
		if err != nil {
			return "", errs.Validation("read %s: %s", f.fromFile, err.Error())
		}

		return string(b), nil
	}

	// No flag: accept piped stdin, but never block on a terminal.
	if !output.FromCmd(cmd).Interactive() && stdin != nil {
		if fi, ok := stdin.(*os.File); !ok || !isTerminal(fi) {
			b, err := io.ReadAll(stdin)
			if err == nil && strings.TrimSpace(string(b)) != "" {
				return string(b), nil
			}
		}
	}

	return "", errs.Validation("no SQL given; pass --query, --from-file, or pipe SQL on stdin")
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}

	return fi.Mode()&os.ModeCharDevice != 0
}

func (f *queryFlags) options(cmd *cobra.Command, sql string) (targetintel.Settings, targetintel.QueryOptions) {
	o := targetintel.Overrides{}
	if cmd.Flags().Changed("max-cost") {
		v := f.maxCost
		o.MaxCostUSD = &v
	}
	s := settingsFromCmd(cmd, o)

	return s, targetintel.QueryOptions{
		SQL:         strings.TrimSpace(sql),
		MaxCostUSD:  s.MaxCostUSD,
		PricePerTiB: s.PricePerTiB,
		NoCache:     f.noCache,
		Timeout:     f.timeout,
	}
}

// estimatePayload is the JSON emitted by estimate and query --dry-run.
type estimatePayload struct {
	SchemaVersion int                  `json:"schema_version"`
	Estimate      targetintel.Estimate `json:"estimate"`
	MaxCostUSD    float64              `json:"max_cost_usd"`
	WithinLimit   bool                 `json:"within_limit"`
}

// resultPayload is the JSON emitted by a successful query.
type resultPayload struct {
	SchemaVersion int `json:"schema_version"`
	*targetintel.Result
	// Extra carries command-specific fields (the routine and its arguments)
	// alongside the generic result.
	Extra map[string]any `json:"-"`
}

// MarshalJSON flattens Extra into the top-level object.
func (p resultPayload) MarshalJSON() ([]byte, error) {
	type plain resultPayload
	b, err := json.Marshal(plain(p))
	if err != nil || len(p.Extra) == 0 {
		return b, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	for k, v := range p.Extra {
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		m[k] = raw
	}

	return json.Marshal(m)
}

func queryCommand() *cobra.Command {
	var f queryFlags
	var limit int
	var all, dryRun bool

	cmd := &cobra.Command{
		Use:     "query [--query <sql> | --from-file <path>]",
		Short:   i18n.C.TargetIntelQueryShort,
		Long:    i18n.C.TargetIntelQueryLong,
		Example: i18n.C.TargetIntelQueryExample,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			sql, err := f.readSQL(cmd, os.Stdin)
			if err != nil {
				return err
			}
			s, opts := f.options(cmd, sql)
			if !all {
				opts.Limit = limit
			}

			c, err := targetintel.NewClient(cmd.Context(), s)
			if err != nil {
				return err
			}
			defer func() { _ = c.Close() }()

			if dryRun {
				return renderEstimate(cmd, c, opts)
			}

			return runAndRender(cmd, c, opts, nil, nil)
		},
	}
	f.bind(cmd)
	cmd.Flags().IntVar(&limit, "limit", 100, "Max rows to return. Does not reduce bytes scanned; add LIMIT/WHERE in SQL to cut cost")
	cmd.Flags().BoolVar(&all, "all", false, "Return all rows (ignores --limit)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print the estimate and exit without running the query")

	return cmd
}

// runAndRender runs the query and renders the result. In JSON mode the
// payload is the full Result plus any extra top-level fields; in text mode
// the table shows textColumns when given, otherwise every column.
func runAndRender(cmd *cobra.Command, c *targetintel.Client, opts targetintel.QueryOptions, extra map[string]any, textColumns []string) error {
	r := output.FromCmd(cmd)
	res, err := c.Run(cmd.Context(), opts)
	if err != nil {
		return err
	}

	if r.IsJSON() {
		return r.JSON(resultPayload{SchemaVersion: output.SchemaVersion, Extra: extra, Result: res})
	}

	r.Info("Estimated %s (%s), billed %s, %d of %d rows%s",
		targetintel.FormatCost(res.Estimate.CostUSD), targetintel.FormatBytes(res.Estimate.BytesProcessed),
		targetintel.FormatCost(res.CostUSD), res.ReturnedRows, res.TotalRows, truncatedNote(res))

	return renderRows(cmd, res, textColumns)
}

// renderRows prints the result as a text table of textColumns, or of every
// column when nil.
func renderRows(cmd *cobra.Command, res *targetintel.Result, textColumns []string) error {
	r := output.FromCmd(cmd)
	headers := textColumns
	if headers == nil {
		headers = make([]string, 0, len(res.Schema))
		for _, col := range res.Schema {
			headers = append(headers, col.Name)
		}
	}
	r.Println(rowTable(headers, res.Rows))
	if textColumns != nil {
		r.Info("Showing %d of %d columns; use --json for every field", len(textColumns), len(res.Schema))
	}

	return nil
}

// rowTable renders the named columns of each row as a table.
func rowTable(headers []string, rows []map[string]any) string {
	cells := make([][]string, 0, len(rows))
	for _, row := range rows {
		line := make([]string, 0, len(headers))
		for _, h := range headers {
			line = append(line, targetintel.CellString(row[h]))
		}
		cells = append(cells, line)
	}

	return ui.Table(headers, cells)
}

func truncatedNote(res *targetintel.Result) string {
	if res.Truncated {
		return " (use --all or a larger --limit for more)"
	}

	return ""
}

func estimateCommand() *cobra.Command {
	var f queryFlags
	cmd := &cobra.Command{
		Use:   "estimate [--query <sql> | --from-file <path>]",
		Short: i18n.C.TargetIntelEstimateShort,
		Long:  i18n.C.TargetIntelEstimateLong,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			sql, err := f.readSQL(cmd, os.Stdin)
			if err != nil {
				return err
			}
			s, opts := f.options(cmd, sql)
			c, err := targetintel.NewClient(cmd.Context(), s)
			if err != nil {
				return err
			}
			defer func() { _ = c.Close() }()

			return renderEstimate(cmd, c, opts)
		},
	}
	f.bind(cmd)

	return cmd
}

func renderEstimate(cmd *cobra.Command, c *targetintel.Client, opts targetintel.QueryOptions) error {
	r := output.FromCmd(cmd)
	est, err := c.DryRun(cmd.Context(), opts)
	if err != nil {
		return err
	}
	within := opts.MaxCostUSD <= 0 || est.CostUSD <= opts.MaxCostUSD
	if r.IsJSON() {
		return r.JSON(estimatePayload{
			SchemaVersion: output.SchemaVersion,
			Estimate:      *est,
			MaxCostUSD:    opts.MaxCostUSD,
			WithinLimit:   within,
		})
	}
	r.Stat("Statement", est.StatementType)
	r.Stat("Bytes to be scanned", targetintel.FormatBytes(est.BytesProcessed))
	r.Stat("Estimated cost", targetintel.FormatCost(est.CostUSD)+" (on-demand, "+targetintel.FormatCost(opts.PricePerTiB)+"/TiB)")
	switch {
	case opts.MaxCostUSD <= 0:
		r.Stat("Max cost", "unlimited")
	case within:
		r.Stat("Max cost", targetintel.FormatCost(opts.MaxCostUSD)+" (within limit)")
	default:
		r.Warn("Estimated cost exceeds the max cost %s; `query` would refuse this statement.", targetintel.FormatCost(opts.MaxCostUSD))
	}

	return nil
}
