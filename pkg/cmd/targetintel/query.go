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
		"Max cost in USD billed per query, enforced by BigQuery as a bytes-billed cap: a job that would bill more fails before anything is charged (env: "+targetintel.EnvMaxCost+"; 0 disables the cap)")
	cmd.Flags().BoolVar(&f.noCache, "no-cache", false, "Disable the BigQuery result cache")
	cmd.Flags().DurationVar(&f.timeout, "timeout", 5*time.Minute, "Job timeout (0 for none)")
}

// readSQL resolves the statement from --query, --from-file or piped stdin
// and rejects one that is empty or only whitespace.
func (f *queryFlags) readSQL(cmd *cobra.Command, stdin io.Reader) (string, error) {
	sql, err := f.sqlSource(cmd, stdin)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(sql) == "" {
		return "", errs.Validation("the SQL statement is empty")
	}

	return sql, nil
}

func (f *queryFlags) sqlSource(cmd *cobra.Command, stdin io.Reader) (string, error) {
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

	// No flag: accept piped stdin, but never block on a terminal, and give
	// up on a pipe that sends nothing (a runner that leaves stdin open).
	if !output.FromCmd(cmd).Interactive() && stdin != nil {
		if fi, ok := stdin.(*os.File); !ok || !isTerminal(fi) {
			b, err := readPipedStdin(stdin, stdinWait)
			if err != nil {
				return "", errs.Validation("read stdin: %s", err.Error())
			}
			if strings.TrimSpace(string(b)) != "" {
				return string(b), nil
			}
		}
	}

	return "", errs.Validation("no SQL given; pass --query, --from-file, or pipe SQL on stdin").
		WithHint("use --from-file - to wait for SQL on stdin however long it takes")
}

// stdinWait is how long implicit stdin may stay silent before it is taken
// to carry no SQL.
var stdinWait = 3 * time.Second

// readPipedStdin reads r to the end once it yields a first byte, or returns
// nothing if it yields none within wait. On a timeout the reading goroutine
// is left blocked; the command fails straight after, so it dies with the
// process.
func readPipedStdin(r io.Reader, wait time.Duration) ([]byte, error) {
	type result struct {
		b   []byte
		err error
	}
	started := make(chan struct{})
	done := make(chan result, 1)
	go func() {
		b, err := io.ReadAll(&firstReadSignal{r: r, started: started})
		done <- result{b, err}
	}()
	select {
	case <-started:
	case res := <-done:
		return res.b, res.err
	case <-time.After(wait):
		return nil, nil
	}
	res := <-done

	return res.b, res.err
}

// firstReadSignal closes started the first time a read returns data.
type firstReadSignal struct {
	r       io.Reader
	started chan struct{}
	once    bool
}

func (s *firstReadSignal) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if n > 0 && !s.once {
		s.once = true
		close(s.started)
	}

	return n, err
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}

	return fi.Mode()&os.ModeCharDevice != 0
}

// options resolves the settings and the job options the shared flags
// describe, rejecting any that are out of range.
func (f *queryFlags) options(cmd *cobra.Command, sql string) (targetintel.Settings, targetintel.QueryOptions, error) {
	if f.timeout < 0 {
		return targetintel.Settings{}, targetintel.QueryOptions{}, errs.Validation("--timeout must be 0 (no job timeout) or more, got %s", f.timeout)
	}
	o := targetintel.Overrides{}
	if cmd.Flags().Changed("max-cost") {
		v := f.maxCost
		o.MaxCostUSD = &v
	}
	s, err := settingsFromCmd(cmd, o)
	if err != nil {
		return targetintel.Settings{}, targetintel.QueryOptions{}, err
	}

	return s, targetintel.QueryOptions{
		SQL:         strings.TrimSpace(sql),
		MaxCostUSD:  s.MaxCostUSD,
		PricePerTiB: s.PricePerTiB,
		NoCache:     f.noCache,
		Timeout:     f.timeout,
	}, nil
}

// rowLimit returns the row cap for --limit, or 0 (every row) with --all.
// Run reads a limit of 0 or less as "every row", so a non-positive --limit
// would silently mean --all; it is rejected instead.
func rowLimit(limit int, all bool) (int, error) {
	if all {
		return 0, nil
	}
	if limit < 1 {
		return 0, errs.Validation("--limit must be at least 1, got %d; use --all for every row", limit)
	}

	return limit, nil
}

// estimatePayload is the JSON emitted by estimate and query --dry-run.
type estimatePayload struct {
	SchemaVersion int `json:"schema_version"`
	estimateResult
}

// estimateResult is one dry run checked against the cost cap.
type estimateResult struct {
	Estimate    targetintel.Estimate `json:"estimate"`
	MaxCostUSD  float64              `json:"max_cost_usd"`
	WithinLimit bool                 `json:"within_limit"`
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
		Args:    validArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			sql, err := f.readSQL(cmd, os.Stdin)
			if err != nil {
				return err
			}
			s, opts, err := f.options(cmd, sql)
			if err != nil {
				return err
			}
			if opts.Limit, err = rowLimit(limit, all); err != nil {
				return err
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
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print a free dry-run estimate and exit without running the query")

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

	r.Info("Billed %s (%s%s), %d of %d rows%s",
		targetintel.FormatCost(res.CostUSD), targetintel.FormatBytes(res.BytesBilled), capNote(opts), res.ReturnedRows, res.TotalRows, truncatedNote(res))

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

// capNote names the bytes-billed cap when the job ran under one.
func capNote(opts targetintel.QueryOptions) string {
	if opts.MaxCostUSD <= 0 {
		return ""
	}

	return ", cap " + targetintel.FormatCost(opts.MaxCostUSD)
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
		Args:  validArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			sql, err := f.readSQL(cmd, os.Stdin)
			if err != nil {
				return err
			}
			s, opts, err := f.options(cmd, sql)
			if err != nil {
				return err
			}
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
	e, err := estimate(cmd, c, opts)
	if err != nil {
		return err
	}
	if r.IsJSON() {
		return r.JSON(estimatePayload{SchemaVersion: output.SchemaVersion, estimateResult: e})
	}
	printEstimate(r, e, opts)

	return nil
}

// estimate dry-runs opts and checks the estimate against its cost cap.
func estimate(cmd *cobra.Command, c *targetintel.Client, opts targetintel.QueryOptions) (estimateResult, error) {
	est, err := c.DryRun(cmd.Context(), opts)
	if err != nil {
		return estimateResult{}, err
	}

	return estimateResult{
		Estimate:    *est,
		MaxCostUSD:  opts.MaxCostUSD,
		WithinLimit: opts.MaxCostUSD <= 0 || est.CostUSD <= opts.MaxCostUSD,
	}, nil
}

func printEstimate(r *output.Renderer, e estimateResult, opts targetintel.QueryOptions) {
	est, within := e.Estimate, e.WithinLimit
	r.Stat("Statement", est.StatementType)
	r.Stat("Bytes to be scanned", targetintel.FormatBytes(est.BytesProcessed))
	r.Stat("Estimated cost", targetintel.FormatCost(est.CostUSD)+" (on-demand, "+targetintel.FormatCost(opts.PricePerTiB)+"/TiB)")
	switch {
	case opts.MaxCostUSD <= 0:
		r.Stat("Max cost", "unlimited")
	case within:
		r.Stat("Max cost", targetintel.FormatCost(opts.MaxCostUSD)+" (within limit)")
	default:
		r.Warn("The estimate exceeds the max cost %s. The query would still run under that cap and fail free if it really billed that much; the dry run cannot see cluster pruning, so a clustered lookup usually bills far less.", targetintel.FormatCost(opts.MaxCostUSD))
	}
}
