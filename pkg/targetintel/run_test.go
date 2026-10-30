package targetintel

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/bigquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulncheck-oss/cli/internal/bqfake"
	"github.com/vulncheck-oss/cli/internal/errs"
)

const testPrice = 6.25

// fakeClient returns a Client whose BigQuery calls go to s.
func fakeClient(t *testing.T, s *bqfake.Server) *Client {
	t.Helper()

	return &Client{BQ: s.NewClient("p"), Settings: Settings{Project: "p", Location: "US", PricePerTiB: testPrice}}
}

var observationSchema = []bqfake.Field{
	{Name: "ip", Type: "STRING", Mode: "REQUIRED"},
	{Name: "port", Type: "INTEGER"},
	{Name: "cves", Type: "STRING", Mode: "REPEATED"},
	{Name: "seen", Type: "TIMESTAMP"},
	{Name: "product", Type: "RECORD", Fields: []bqfake.Field{
		{Name: "vendor", Type: "STRING"},
		{Name: "score", Type: "FLOAT"},
	}},
}

func observationRows() []bqfake.Row {
	seen := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	rows := make([]bqfake.Row, 0, 3)
	for i, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		rows = append(rows, bqfake.Row{
			"ip":      ip,
			"port":    443 + i,
			"cves":    []string{"CVE-2024-0001", "CVE-2024-0002"},
			"seen":    seen,
			"product": map[string]any{"vendor": "acme", "score": 9.5},
		})
	}

	return rows
}

func TestRunHappyPath(t *testing.T) {
	t.Parallel()
	s := bqfake.New(t)
	s.SetQuery(bqfake.Query{
		Schema: observationSchema,
		Rows:   observationRows(),
		Stats:  bqfake.Stats{TotalBytesBilled: 2 << 40, CacheHit: true},
	})
	c := fakeClient(t, s)

	res, err := c.Run(t.Context(), QueryOptions{SQL: "SELECT * FROM t", PricePerTiB: testPrice})
	require.NoError(t, err)

	assert.True(t, strings.HasPrefix(res.JobID, "vulncheck_cli_"), res.JobID)
	assert.Equal(t, s.LastJob().JobReference.JobId, res.JobID)
	assert.Equal(t, int64(2<<40), res.BytesBilled)
	assert.True(t, res.CacheHit)
	assert.InDelta(t, 12.5, res.CostUSD, 1e-9)
	assert.Equal(t, uint64(3), res.TotalRows)
	assert.Equal(t, 3, res.ReturnedRows)
	assert.False(t, res.Truncated)
	assert.Equal(t, []Column{
		{Name: "ip", Type: "STRING", Mode: "REQUIRED"},
		{Name: "port", Type: "INTEGER", Mode: "NULLABLE"},
		{Name: "cves", Type: "STRING", Mode: "REPEATED"},
		{Name: "seen", Type: "TIMESTAMP", Mode: "NULLABLE"},
		{Name: "product", Type: "RECORD", Mode: "NULLABLE"},
	}, res.Schema)

	require.Len(t, res.Rows, 3)
	assert.Equal(t, map[string]any{
		"ip":      "192.0.2.1",
		"port":    int64(443),
		"cves":    []any{"CVE-2024-0001", "CVE-2024-0002"},
		"seen":    "2026-01-02T03:04:05Z",
		"product": map[string]any{"vendor": "acme", "score": 9.5},
	}, res.Rows[0])
	assert.Equal(t, "192.0.2.3", res.Rows[2]["ip"])
}

func TestRunLimitTruncates(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		limit     int
		totalRows uint64
		pageSize  int
		returned  int
		truncated bool
	}{
		{name: "limit below total", limit: 2, returned: 2, truncated: true},
		{name: "limit equals total", limit: 3, returned: 3},
		{name: "limit above total", limit: 10, returned: 3},
		{name: "no limit", returned: 3},
		{name: "limit across pages", limit: 3, pageSize: 2, returned: 3},
		{name: "server total above rows read", limit: 3, totalRows: 1000, returned: 3, truncated: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := bqfake.New(t)
			s.SetQuery(bqfake.Query{Schema: observationSchema, Rows: observationRows(), TotalRows: tt.totalRows, PageSize: tt.pageSize})
			c := fakeClient(t, s)

			res, err := c.Run(t.Context(), QueryOptions{SQL: "SELECT 1", Limit: tt.limit, PricePerTiB: testPrice})
			require.NoError(t, err)
			assert.Equal(t, tt.returned, res.ReturnedRows)
			assert.Len(t, res.Rows, tt.returned)
			assert.Equal(t, tt.truncated, res.Truncated)
			want := tt.totalRows
			if want == 0 {
				want = 3
			}
			assert.Equal(t, want, res.TotalRows)
		})
	}
}

func TestRunEmptyResult(t *testing.T) {
	t.Parallel()
	s := bqfake.New(t)
	s.SetQuery(bqfake.Query{Schema: []bqfake.Field{{Name: "ip", Type: "STRING"}}})
	c := fakeClient(t, s)

	res, err := c.Run(t.Context(), QueryOptions{SQL: "SELECT ip FROM t WHERE false", PricePerTiB: testPrice})
	require.NoError(t, err)
	require.NotNil(t, res.Rows, "an empty result encodes as [] rather than null")
	assert.Empty(t, res.Rows)
	assert.Equal(t, []Column{{Name: "ip", Type: "STRING", Mode: "NULLABLE"}}, res.Schema)
	assert.Equal(t, uint64(0), res.TotalRows)
	assert.Equal(t, 0, res.ReturnedRows)
	assert.False(t, res.Truncated)
	assert.Zero(t, res.CostUSD)
}

func TestRunJobConfiguration(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		maxCost float64
		want    int64
	}{
		{name: "no cap", maxCost: 0, want: 0},
		{name: "one dollar", maxCost: 1, want: 175921860444}, // 0.16 TiB,
		{name: "tiny cap clamps to the minimum", maxCost: 1e-9, want: minMaxBytesBilled},
		{name: "huge cap saturates", maxCost: 1e30, want: math.MaxInt64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := bqfake.New(t)
			c := fakeClient(t, s)

			_, err := c.Run(t.Context(), QueryOptions{
				SQL:         "SELECT @ip",
				Params:      []bigquery.QueryParameter{{Name: "ip", Value: "192.0.2.1"}},
				MaxCostUSD:  tt.maxCost,
				PricePerTiB: testPrice,
				NoCache:     true,
				Timeout:     30 * time.Second,
			})
			require.NoError(t, err)

			require.Len(t, s.Jobs(), 1)
			job := s.LastJob()
			q := job.Configuration.Query
			require.NotNil(t, q)
			assert.Equal(t, tt.want, q.MaximumBytesBilled)
			assert.Equal(t, "SELECT @ip", q.Query)
			assert.Equal(t, "US", job.JobReference.Location)
			assert.Equal(t, map[string]string{"client": "vulncheck-cli"}, job.Configuration.Labels)
			assert.False(t, job.Configuration.DryRun)
			require.NotNil(t, q.UseQueryCache)
			assert.False(t, *q.UseQueryCache)
			assert.Equal(t, int64(30000), job.Configuration.JobTimeoutMs)
			require.Len(t, q.QueryParameters, 1)
			assert.Equal(t, "ip", q.QueryParameters[0].Name)
			assert.Equal(t, "192.0.2.1", q.QueryParameters[0].ParameterValue.Value)
		})
	}
}

func TestRunRejectsNonSelect(t *testing.T) {
	t.Parallel()
	s := bqfake.New(t)
	c := fakeClient(t, s)

	for _, sql := range []string{"DELETE FROM t WHERE true", "SELECT 1; DROP TABLE t", "CREATE TABLE t (x INT64)"} {
		_, err := c.Run(t.Context(), QueryOptions{SQL: sql})
		require.ErrorIs(t, err, ErrReadOnly, sql)
	}
	assert.Empty(t, s.Requests(), "nothing reaches BigQuery")
}

func TestRunCostLimitExceeded(t *testing.T) {
	t.Parallel()
	msg := "Query exceeded limit for bytes billed: 10485760. 3221225472 or higher required."
	for _, statusOnly := range []bool{false, true} {
		name := "getQueryResults error"
		if statusOnly {
			name = "job status error"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := bqfake.New(t)
			s.SetQuery(bqfake.Query{Err: &bqfake.JobError{Reason: "bytesBilledLimitExceeded", Message: msg, StatusOnly: statusOnly}})
			c := fakeClient(t, s)

			_, err := c.Run(t.Context(), QueryOptions{SQL: "SELECT 1", MaxCostUSD: 0.01, PricePerTiB: testPrice})
			var e *errs.Error
			require.ErrorAs(t, err, &e)
			assert.Equal(t, errs.KindCostLimit, e.Kind)
			var cost *CostLimitError
			require.ErrorAs(t, err, &cost)
			assert.Equal(t, int64(3221225472), cost.RequiredBytes)
			assert.InDelta(t, 0.01, cost.MaxCostUSD, 1e-12)
		})
	}
}

func TestRunOtherJobError(t *testing.T) {
	t.Parallel()
	s := bqfake.New(t)
	s.SetQuery(bqfake.Query{Err: &bqfake.JobError{Reason: "invalidQuery", Message: "Unrecognized name: nope"}})
	c := fakeClient(t, s)

	_, err := c.Run(t.Context(), QueryOptions{SQL: "SELECT nope", PricePerTiB: testPrice})
	var e *errs.Error
	require.ErrorAs(t, err, &e)
	assert.Equal(t, errs.KindBadRequest, e.Kind)
	var cost *CostLimitError
	assert.False(t, errors.As(err, &cost))
}

func TestDryRun(t *testing.T) {
	t.Parallel()
	s := bqfake.New(t)
	s.SetQuery(bqfake.Query{Stats: bqfake.Stats{TotalBytesProcessed: 1 << 40, StatementType: "SELECT"}})
	c := fakeClient(t, s)

	e, err := c.DryRun(t.Context(), QueryOptions{SQL: "SELECT 1", PricePerTiB: testPrice})
	require.NoError(t, err)
	assert.Equal(t, int64(1<<40), e.BytesProcessed)
	assert.Equal(t, "SELECT", e.StatementType)
	assert.InDelta(t, testPrice, e.CostUSD, 1e-9)

	job := s.LastJob()
	assert.True(t, job.Configuration.DryRun)
	assert.Equal(t, "US", job.JobReference.Location)
	assert.Equal(t, map[string]string{"client": "vulncheck-cli"}, job.Configuration.Labels)
	for _, r := range s.Requests() {
		assert.Equal(t, "projects/p/jobs", r.Path, "a dry run is a single insert")
	}
}

func TestDryRunError(t *testing.T) {
	t.Parallel()
	s := bqfake.New(t)
	s.SetQuery(bqfake.Query{Err: &bqfake.JobError{Reason: "invalidQuery", Message: "Syntax error"}})
	c := fakeClient(t, s)

	_, err := c.DryRun(t.Context(), QueryOptions{SQL: "SELECT", PricePerTiB: testPrice})
	var e *errs.Error
	require.ErrorAs(t, err, &e)
	assert.Equal(t, errs.KindBadRequest, e.Kind)
}

func TestListDatasets(t *testing.T) {
	t.Parallel()
	s := bqfake.New(t)
	c := fakeClient(t, s)

	got, err := c.ListDatasets(t.Context())
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Empty(t, got)

	s.AddDataset("p", "alpha")
	s.AddDataset("p", "beta")
	s.AddDataset("other", "hidden")
	got, err = c.ListDatasets(t.Context())
	require.NoError(t, err)
	assert.Equal(t, []Dataset{{Project: "p", Dataset: "alpha"}, {Project: "p", Dataset: "beta"}}, got)
}

func TestListTables(t *testing.T) {
	t.Parallel()
	s := bqfake.New(t)
	s.AddTable("q", "ds", "one", bqfake.Table{})
	s.AddTable("q", "ds", "two", bqfake.Table{Type: "VIEW"})
	c := fakeClient(t, s)

	got, err := c.ListTables(t.Context(), TableRef{Project: "q", Dataset: "ds"})
	require.NoError(t, err)
	assert.Equal(t, []Table{{Project: "q", Dataset: "ds", Table: "one"}, {Project: "q", Dataset: "ds", Table: "two"}}, got)

	got, err = c.ListTables(t.Context(), TableRef{Project: "q", Dataset: "empty"})
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Empty(t, got)
}

func TestDescribeTable(t *testing.T) {
	t.Parallel()
	created := time.Date(2025, 5, 6, 7, 8, 9, 0, time.UTC)
	s := bqfake.New(t)
	s.AddTable("p", "ds", "obs", bqfake.Table{
		Description:           "observations",
		NumRows:               42,
		NumBytes:              1 << 40,
		Schema:                observationSchema,
		TimePartitioningType:  "DAY",
		TimePartitioningField: "seen",
		ClusteringFields:      []string{"ip", "port"},
		Created:               created,
		LastModified:          created.Add(time.Hour),
	})
	s.AddTable("p", "ds", "ingest", bqfake.Table{TimePartitioningType: "HOUR"})
	s.AddTable("p", "ds", "ranged", bqfake.Table{RangePartitioningField: "port"})
	c := fakeClient(t, s)

	info, err := c.DescribeTable(t.Context(), TableRef{Project: "p", Dataset: "ds", Table: "obs"})
	require.NoError(t, err)
	assert.Equal(t, "TABLE", info.Type)
	assert.Equal(t, "observations", info.Description)
	assert.Equal(t, uint64(42), info.NumRows)
	assert.Equal(t, int64(1<<40), info.NumBytes)
	assert.InDelta(t, testPrice, info.FullScanCostUSD, 1e-9)
	assert.Equal(t, "seen", info.PartitionField)
	assert.Equal(t, "DAY", info.PartitionType)
	assert.Equal(t, []string{"ip", "port"}, info.ClusteringFields)
	assert.True(t, created.Equal(info.Created))
	assert.True(t, created.Add(time.Hour).Equal(info.LastModified))
	modes := map[string]string{}
	for _, col := range info.Schema {
		modes[col.Name] = col.Mode
	}
	assert.Equal(t, map[string]string{
		"ip": "REQUIRED", "port": "NULLABLE", "cves": "REPEATED", "seen": "NULLABLE", "product": "NULLABLE",
	}, modes)

	info, err = c.DescribeTable(t.Context(), TableRef{Project: "p", Dataset: "ds", Table: "ingest"})
	require.NoError(t, err)
	assert.Equal(t, "_PARTITIONTIME", info.PartitionField)
	assert.Equal(t, "HOUR", info.PartitionType)

	info, err = c.DescribeTable(t.Context(), TableRef{Project: "p", Dataset: "ds", Table: "ranged"})
	require.NoError(t, err)
	assert.Equal(t, "port", info.PartitionField)
	assert.Equal(t, "RANGE", info.PartitionType)

	_, err = c.DescribeTable(t.Context(), TableRef{Project: "p", Dataset: "ds", Table: "missing"})
	var e *errs.Error
	require.ErrorAs(t, err, &e)
	assert.Equal(t, errs.KindNotFound, e.Kind)
}
