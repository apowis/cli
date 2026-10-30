package targetintel

import (
	"context"
	"errors"
	"fmt"
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
	// MaxCostUSD refuses the query when the estimate is above it. Zero
	// disables the limit.
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
	Estimate     Estimate         `json:"estimate"`
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

// Run dry-runs the query, enforces the read-only and cost rules, then runs it
// and reads up to opts.Limit rows. The cost limit is also sent to BigQuery as
// maximumBytesBilled, so the job cannot bill past it even if the estimate is
// wrong.
func (c *Client) Run(ctx context.Context, opts QueryOptions) (*Result, error) {
	est, err := c.DryRun(ctx, opts)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(est.StatementType, "SELECT") {
		return nil, ErrReadOnly
	}
	if opts.MaxCostUSD > 0 && est.CostUSD > opts.MaxCostUSD {
		return nil, (&CostLimitError{Estimate: *est, MaxCostUSD: opts.MaxCostUSD}).Classified()
	}

	q := c.newQuery(opts)
	if opts.MaxCostUSD > 0 {
		q.MaxBytesBilled = max(int64(opts.MaxCostUSD/opts.PricePerTiB*tib), minMaxBytesBilled)
	}
	job, err := q.Run(ctx)
	if err != nil {
		return nil, classify(err)
	}

	// A cancelled context must also cancel the job, or an abandoned query
	// keeps running and billing.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			cancelCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = job.Cancel(cancelCtx)
		case <-done:
		}
	}()

	status, err := job.Wait(ctx)
	if err != nil {
		return nil, classify(err)
	}
	if err := status.Err(); err != nil {
		return nil, classify(err)
	}

	res := &Result{JobID: job.ID(), Estimate: *est}
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
