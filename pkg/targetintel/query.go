package targetintel

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"cloud.google.com/go/bigquery"
	"google.golang.org/api/iterator"
)

const tib = 1 << 40

// minMaxBytesBilled is the smallest maximumBytesBilled BigQuery accepts.
const minMaxBytesBilled = 10 << 20

// QueryOptions describes one query invocation.
type QueryOptions struct {
	SQL string
	// Params are named query parameters referenced as @name in SQL.
	Params []bigquery.QueryParameter
	// MaxCostUSD is sent to BigQuery as a bytes-billed cap: a job that would
	// bill more fails before anything is charged. Zero disables the cap.
	MaxCostUSD  float64
	PricePerTiB float64
	// Limit caps the rows returned to the caller; it does not change what
	// BigQuery scans. Zero returns every row.
	Limit   int
	NoCache bool
	Timeout time.Duration
}

// Estimate is the outcome of a free dry run.
type Estimate struct {
	BytesProcessed int64   `json:"bytes_processed"`
	CostUSD        float64 `json:"cost_usd"`
	StatementType  string  `json:"statement_type,omitempty"`
}

// Column is one output column.
type Column struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Mode string `json:"mode,omitempty"`
}

// Result is a completed query with up to Limit rows materialised.
type Result struct {
	JobID        string           `json:"job_id"`
	BytesBilled  int64            `json:"bytes_billed"`
	CostUSD      float64          `json:"cost_usd"`
	CacheHit     bool             `json:"cache_hit"`
	TotalRows    uint64           `json:"total_rows"`
	ReturnedRows int              `json:"returned_rows"`
	Truncated    bool             `json:"truncated"`
	Schema       []Column         `json:"schema"`
	Rows         []map[string]any `json:"rows"`
}

func (c *Client) newQuery(opts QueryOptions) *bigquery.Query {
	q := c.BQ.Query(opts.SQL)
	q.Location = c.Settings.Location
	q.Parameters = opts.Params
	q.DisableQueryCache = opts.NoCache
	q.JobTimeout = opts.Timeout
	q.Labels = map[string]string{"client": "vulncheck-cli"}

	return q
}

// DryRun estimates the query without running it. It uses the same job
// configuration as Run so the estimate matches what would be billed.
func (c *Client) DryRun(ctx context.Context, opts QueryOptions) (*Estimate, error) {
	q := c.newQuery(opts)
	q.DryRun = true
	job, err := q.Run(ctx)
	if err != nil {
		return nil, classify(err)
	}
	st := job.LastStatus()
	if st == nil {
		return nil, errors.New("dry run returned no status")
	}
	if err := st.Err(); err != nil {
		return nil, classify(err)
	}

	e := &Estimate{}
	if st.Statistics != nil {
		e.BytesProcessed = st.Statistics.TotalBytesProcessed
		if qs, ok := st.Statistics.Details.(*bigquery.QueryStatistics); ok && qs != nil {
			e.StatementType = qs.StatementType
		}
	}
	e.CostUSD = cost(e.BytesProcessed, opts.PricePerTiB)

	return e, nil
}

// Run runs the query under a bytes-billed cap and reads up to opts.Limit
// rows. There is no dry run: BigQuery's estimate cannot see cluster pruning
// and overstates a clustered lookup by orders of magnitude, while the cap is
// enforced against the bytes actually read and a job over it fails free.
// Only SELECT statements are accepted.
func (c *Client) Run(ctx context.Context, opts QueryOptions) (*Result, error) {
	if !IsSelect(opts.SQL) {
		return nil, ErrReadOnly
	}
	q := c.newQuery(opts)
	if opts.MaxCostUSD > 0 {
		q.MaxBytesBilled = maxBytesBilled(opts.MaxCostUSD, opts.PricePerTiB)
	}
	// The job ID is chosen here rather than by the server so a job whose
	// insert was interrupted can still be found and cancelled.
	jobID := "vulncheck_cli_" + rand.Text()
	q.JobIDConfig = bigquery.JobIDConfig{JobID: jobID}
	job, err := q.Run(ctx)
	if err != nil {
		if ctx.Err() != nil {
			c.cancelJob(nil, jobID)
		}

		return nil, classify(costLimitFromJob(err, opts))
	}

	status, err := job.Wait(ctx)
	if err != nil {
		if ctx.Err() != nil {
			c.cancelJob(job, jobID)
		}

		return nil, classify(costLimitFromJob(err, opts))
	}
	if err := status.Err(); err != nil {
		return nil, classify(costLimitFromJob(err, opts))
	}

	res := &Result{JobID: job.ID()}
	if status.Statistics != nil {
		if qs, ok := status.Statistics.Details.(*bigquery.QueryStatistics); ok && qs != nil {
			res.BytesBilled = qs.TotalBytesBilled
			res.CacheHit = qs.CacheHit
		}
	}
	res.CostUSD = cost(res.BytesBilled, opts.PricePerTiB)

	it, err := job.Read(ctx)
	if err != nil {
		return nil, classify(err)
	}
	for opts.Limit <= 0 || len(res.Rows) < opts.Limit {
		var row map[string]bigquery.Value
		err := it.Next(&row)
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, classify(err)
		}
		if res.Schema == nil {
			res.Schema = columns(it.Schema)
		}
		res.Rows = append(res.Rows, toJSONRow(row))
	}
	if res.Schema == nil {
		res.Schema = columns(it.Schema)
	}
	if res.Rows == nil {
		res.Rows = []map[string]any{}
	}
	res.TotalRows = it.TotalRows
	res.ReturnedRows = len(res.Rows)
	res.Truncated = uint64(res.ReturnedRows) < res.TotalRows

	return res, nil
}

// cancelJobTimeout bounds the cancel request sent after the caller's context
// is gone, so an unreachable API cannot hang the exit.
const cancelJobTimeout = 5 * time.Second

// cancelJob stops a job abandoned by a cancelled context, or it keeps running
// and billing. It blocks until the request completes: the CLI exits as soon
// as Run returns, which would kill a request left in a goroutine. A nil job
// means the insert was interrupted, so the job is looked up by ID; one that
// never reached the server is simply not found. Errors are dropped because
// the caller is already returning the cancellation.
func (c *Client) cancelJob(job *bigquery.Job, jobID string) {
	ctx, cancel := context.WithTimeout(context.Background(), cancelJobTimeout)
	defer cancel()
	if job == nil {
		var err error
		job, err = c.BQ.JobFromIDLocation(ctx, jobID, c.Settings.Location)
		if err != nil {
			return
		}
	}
	_ = job.Cancel(ctx)
}

func cost(bytes int64, pricePerTiB float64) float64 {
	return float64(bytes) / tib * pricePerTiB
}

func columns(schema bigquery.Schema) []Column {
	cols := make([]Column, 0, len(schema))
	for _, f := range schema {
		cols = append(cols, Column{Name: f.Name, Type: string(f.Type), Mode: mode(f)})
	}

	return cols
}

func mode(f *bigquery.FieldSchema) string {
	switch {
	case f.Repeated:
		return "REPEATED"
	case f.Required:
		return "REQUIRED"
	default:
		return "NULLABLE"
	}
}

// maxBytesBilled converts a cost cap to bytes, clamped to what BigQuery
// accepts. A cap too large for an int64 saturates rather than wrapping.
func maxBytesBilled(maxCostUSD, pricePerTiB float64) int64 {
	b := maxCostUSD / pricePerTiB * tib
	if b >= math.MaxInt64 {
		return math.MaxInt64
	}

	return max(int64(b), minMaxBytesBilled)
}

// FormatCost renders a dollar amount for humans.
func FormatCost(usd float64) string {
	switch {
	case usd == 0:
		return "$0.00"
	case usd < 0.01:
		return fmt.Sprintf("$%.4f", usd)
	default:
		return fmt.Sprintf("$%.2f", usd)
	}
}

// FormatBytes renders a byte count for humans.
func FormatBytes(b int64) string {
	return humanBytes(b)
}

var leadingWord = regexp.MustCompile(`^[\s(]*([A-Za-z]+)`)

// IsSelect reports whether the statement is a single SELECT (or WITH ...
// SELECT) once comments are stripped. It is a guard against handing DML, DDL
// or scripts to the warehouse, not a parser: a statement it accepts still
// runs under the credential's own permissions.
func IsSelect(sql string) bool {
	s, ok := stripLiterals(sql)
	if !ok {
		return false
	}
	m := leadingWord.FindStringSubmatch(s)
	if m == nil {
		return false
	}
	switch strings.ToUpper(m[1]) {
	case "SELECT", "WITH":
	default:
		return false
	}
	// A script is several statements; a trailing semicolon alone is fine.
	body := strings.TrimRight(strings.TrimSpace(s), ";")

	return !strings.Contains(body, ";")
}

// stripLiterals replaces every comment with a space and empties every
// quoted string and identifier, so a "--" or ";" inside a literal is not
// mistaken for a comment or a statement break. It reports false for an
// unterminated literal or block comment, which BigQuery would reject anyway.
func stripLiterals(sql string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(sql); {
		c := sql[i]
		switch {
		case c == '#' || strings.HasPrefix(sql[i:], "--"):
			end := strings.IndexByte(sql[i:], '\n')
			if end < 0 {
				return b.String(), true
			}
			b.WriteByte(' ')
			i += end
		case strings.HasPrefix(sql[i:], "/*"):
			end := strings.Index(sql[i+2:], "*/")
			if end < 0 {
				return "", false
			}
			b.WriteByte(' ')
			i += end + 4
		case c == '\'' || c == '"' || c == '`':
			quote := string(c)
			if c != '`' && strings.HasPrefix(sql[i:], strings.Repeat(quote, 3)) {
				quote = strings.Repeat(quote, 3)
			}
			raw := c != '`' && rawPrefix(sql[:i])
			j := i + len(quote)
			for ; j < len(sql) && !strings.HasPrefix(sql[j:], quote); j++ {
				if sql[j] == '\\' && !raw {
					j++
				}
			}
			if j >= len(sql) {
				return "", false
			}
			b.WriteString(quote + quote)
			i = j + len(quote)
		default:
			b.WriteByte(c)
			i++
		}
	}

	return b.String(), true
}

// rawPrefix reports whether the text before a quote ends in a string
// prefix (r, b, rb or br in any case) that makes the literal raw.
func rawPrefix(before string) bool {
	tail := before[max(0, len(before)-2):]
	k := len(tail)
	for k > 0 && strings.IndexByte("rRbB", tail[k-1]) >= 0 {
		k--
	}
	prefix := tail[k:]
	if prefix == "" {
		return false
	}
	if start := len(before) - len(prefix); start > 0 && isIdentByte(before[start-1]) {
		return false
	}

	return strings.ContainsAny(prefix, "rR")
}

func isIdentByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}
