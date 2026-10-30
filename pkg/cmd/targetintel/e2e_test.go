package targetintel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bq "google.golang.org/api/bigquery/v2"

	"github.com/vulncheck-oss/cli/internal/bqfake"
	"github.com/vulncheck-oss/cli/internal/errs"
	"github.com/vulncheck-oss/cli/internal/output"
	"github.com/vulncheck-oss/cli/pkg/targetintel"
)

// These tests run the real command tree against bqfake. They swap the
// package-level newClient seam and set environment variables, so none of
// them may call t.Parallel (see the note in auth_test.go).

const e2eProject = targetintel.DefaultProject

// fakeBQ isolates the environment, starts a fake BigQuery server and points
// newClient at it for the rest of the test.
func fakeBQ(t *testing.T) *bqfake.Server {
	t.Helper()
	isolateEnv(t)
	s := bqfake.New(t)
	orig := newClient
	newClient = func(_ context.Context, settings targetintel.Settings) (*targetintel.Client, error) {
		c := s.NewClient(settings.Project)
		c.Location = settings.Location

		return &targetintel.Client{BQ: c, Settings: settings}, nil
	}
	t.Cleanup(func() { newClient = orig })

	return s
}

// runTI executes the target-intel command tree with args in the given mode
// and returns what it wrote to stdout and stderr.
func runTI(t *testing.T, mode output.Mode, args ...string) (string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	r := output.New(output.Options{Mode: mode, Stdout: &stdout, Stderr: &stderr})
	cmd := Command()
	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetIn(strings.NewReader(""))
	err := cmd.ExecuteContext(output.WithContext(t.Context(), r))

	return stdout.String(), stderr.String(), err
}

// decodeOne decodes stdout as exactly one JSON document.
func decodeOne(t *testing.T, stdout string) map[string]any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(stdout))
	var got map[string]any
	require.NoError(t, dec.Decode(&got), stdout)
	var extra any
	require.ErrorIs(t, dec.Decode(&extra), io.EOF, "stdout holds more than one JSON document: %s", stdout)

	return got
}

// billedLine is the summary line the query-running commands print in text
// mode.
func billedLine(bytesBilled int64, capUSD float64, returned, total int, truncated bool) string {
	capPart := ""
	if capUSD > 0 {
		capPart = ", cap " + targetintel.FormatCost(capUSD)
	}
	note := ""
	if truncated {
		note = " (use --all or a larger --limit for more)"
	}

	return fmt.Sprintf("Billed %s (%s%s), %d of %d rows%s",
		targetintel.FormatCost(float64(bytesBilled)/(1<<40)*targetintel.DefaultPricePerTiB),
		targetintel.FormatBytes(bytesBilled), capPart, returned, total, note)
}

func jobSQL(job *bq.Job) string {
	return job.Configuration.Query.Query
}

// jobParams returns the job's named parameters as name to value, with an
// array parameter as its element values.
func jobParams(job *bq.Job) map[string]any {
	out := map[string]any{}
	for _, p := range job.Configuration.Query.QueryParameters {
		if p.ParameterType != nil && p.ParameterType.Type == "ARRAY" {
			vals := []string{}
			for _, v := range p.ParameterValue.ArrayValues {
				vals = append(vals, v.Value)
			}
			out[p.Name] = vals

			continue
		}
		out[p.Name] = p.ParameterValue.Value
	}

	return out
}

var ipPortSchema = []bqfake.Field{{Name: "ip", Type: "STRING"}, {Name: "port", Type: "INTEGER"}}

func ipPortRows(n int) []bqfake.Row {
	rows := make([]bqfake.Row, 0, n)
	for i := range n {
		rows = append(rows, bqfake.Row{"ip": fmt.Sprintf("192.0.2.%d", i+1), "port": 443})
	}

	return rows
}

func TestE2EQueryJSON(t *testing.T) {
	s := fakeBQ(t)
	s.SetQuery(bqfake.Query{Schema: ipPortSchema, Rows: ipPortRows(3), Stats: bqfake.Stats{TotalBytesBilled: 1 << 30}})

	stdout, _, err := runTI(t, output.ModeJSON, "query", "-q", "SELECT ip, port FROM t", "--limit", "2")
	require.NoError(t, err)

	got := decodeOne(t, stdout)
	assert.InDelta(t, output.SchemaVersion, got["schema_version"], 0)
	assert.Equal(t, s.LastJob().JobReference.JobId, got["job_id"])
	assert.True(t, strings.HasPrefix(got["job_id"].(string), "vulncheck_cli_"), got["job_id"])
	assert.InDelta(t, 1<<30, got["bytes_billed"], 0)
	assert.InDelta(t, 3, got["total_rows"], 0)
	assert.InDelta(t, 2, got["returned_rows"], 0)
	assert.Equal(t, true, got["truncated"])
	assert.Equal(t, []any{
		map[string]any{"name": "ip", "type": "STRING", "mode": "NULLABLE"},
		map[string]any{"name": "port", "type": "INTEGER", "mode": "NULLABLE"},
	}, got["schema"])
	assert.Equal(t, []any{
		map[string]any{"ip": "192.0.2.1", "port": float64(443)},
		map[string]any{"ip": "192.0.2.2", "port": float64(443)},
	}, got["rows"])

	job := s.LastJob()
	assert.Equal(t, "SELECT ip, port FROM t", jobSQL(job))
	assert.False(t, job.Configuration.DryRun)
	maxCost, price := targetintel.DefaultMaxCostUSD, targetintel.DefaultPricePerTiB
	assert.Equal(t, int64(maxCost/price*(1<<40)), job.Configuration.Query.MaximumBytesBilled)
	assert.Equal(t, targetintel.DefaultLocation, job.JobReference.Location)
}

func TestE2EQueryText(t *testing.T) {
	s := fakeBQ(t)
	s.SetQuery(bqfake.Query{Schema: ipPortSchema, Rows: ipPortRows(3), Stats: bqfake.Stats{TotalBytesBilled: 1 << 30}})

	stdout, stderr, err := runTI(t, output.ModeText, "query", "-q", "SELECT ip, port FROM t", "--limit", "2")
	require.NoError(t, err)

	assert.Contains(t, stdout, billedLine(1<<30, 1, 2, 3, true))
	assert.Contains(t, stdout, "192.0.2.1")
	assert.Contains(t, stdout, "192.0.2.2")
	assert.NotContains(t, stdout, "192.0.2.3", "--limit 2 cuts the third row")
	assert.Contains(t, stdout, "port")
	assert.Empty(t, stderr)
}

func TestE2EQueryAllRows(t *testing.T) {
	s := fakeBQ(t)
	s.SetQuery(bqfake.Query{Schema: ipPortSchema, Rows: ipPortRows(3)})

	stdout, _, err := runTI(t, output.ModeText, "query", "-q", "SELECT ip, port FROM t", "--limit", "2", "--all")
	require.NoError(t, err)
	assert.Contains(t, stdout, billedLine(0, 1, 3, 3, false))
	assert.Contains(t, stdout, "192.0.2.3")
}

func TestE2EQueryNoCap(t *testing.T) {
	s := fakeBQ(t)
	s.SetQuery(bqfake.Query{Schema: ipPortSchema, Rows: ipPortRows(1)})

	stdout, _, err := runTI(t, output.ModeText, "query", "-q", "SELECT 1", "--max-cost", "0")
	require.NoError(t, err)

	assert.Zero(t, s.LastJob().Configuration.Query.MaximumBytesBilled, "--max-cost 0 sends no bytes-billed cap")
	assert.Contains(t, stdout, billedLine(0, 0, 1, 1, false))
	assert.NotContains(t, stdout, "cap ")
}

func TestE2EQueryRejectsNonSelect(t *testing.T) {
	s := fakeBQ(t)

	_, _, err := runTI(t, output.ModeJSON, "query", "-q", "DELETE FROM t WHERE true")
	require.Error(t, err)
	require.ErrorIs(t, err, targetintel.ErrReadOnly)
	assert.Equal(t, 2, errs.Classify(err).ExitCode(), "%v", err)
	assert.Empty(t, s.Jobs(), "a rejected statement never reaches BigQuery")
}

func TestE2EQueryCostLimitExceeded(t *testing.T) {
	s := fakeBQ(t)
	s.SetQuery(bqfake.Query{Schema: ipPortSchema, Err: &bqfake.JobError{Reason: "bytesBilledLimitExceeded", Message: "Query exceeded limit for bytes billed"}})

	_, _, err := runTI(t, output.ModeJSON, "query", "-q", "SELECT 1")
	require.Error(t, err)
	var cle *targetintel.CostLimitError
	assert.True(t, errors.As(err, &cle), "%T: %v", err, err)
	assert.Len(t, s.Jobs(), 1)
}

func TestE2EEstimate(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		bytes  int64
		within bool
	}{
		{name: "estimate within limit", args: []string{"estimate", "-q", "SELECT 1"}, bytes: 1 << 30, within: true},
		{name: "estimate over limit", args: []string{"estimate", "-q", "SELECT 1"}, bytes: 1 << 40, within: false},
		{name: "query dry run within limit", args: []string{"query", "-q", "SELECT 1", "--dry-run"}, bytes: 1 << 30, within: true},
		{name: "query dry run over limit", args: []string{"query", "-q", "SELECT 1", "--dry-run"}, bytes: 1 << 40, within: false},
	}
	for _, tt := range tests {
		t.Run(tt.name+" json", func(t *testing.T) {
			s := fakeBQ(t)
			s.SetQuery(bqfake.Query{Stats: bqfake.Stats{TotalBytesProcessed: tt.bytes}})

			stdout, _, err := runTI(t, output.ModeJSON, tt.args...)
			require.NoError(t, err)

			got := decodeOne(t, stdout)
			assert.InDelta(t, output.SchemaVersion, got["schema_version"], 0)
			assert.Equal(t, tt.within, got["within_limit"])
			assert.InDelta(t, targetintel.DefaultMaxCostUSD, got["max_cost_usd"], 0)
			est, ok := got["estimate"].(map[string]any)
			require.True(t, ok, got)
			assert.InDelta(t, tt.bytes, est["bytes_processed"], 0)
			assert.InDelta(t, float64(tt.bytes)/(1<<40)*targetintel.DefaultPricePerTiB, est["cost_usd"], 1e-9)
			assert.Equal(t, "SELECT", est["statement_type"])

			jobs := s.Jobs()
			require.Len(t, jobs, 1, "only the dry run is sent")
			assert.True(t, jobs[0].Configuration.DryRun)
		})
		t.Run(tt.name+" text", func(t *testing.T) {
			s := fakeBQ(t)
			s.SetQuery(bqfake.Query{Stats: bqfake.Stats{TotalBytesProcessed: tt.bytes}})

			stdout, stderr, err := runTI(t, output.ModeText, tt.args...)
			require.NoError(t, err)

			assert.Contains(t, stdout, "Statement: SELECT")
			assert.Contains(t, stdout, "Bytes to be scanned: "+targetintel.FormatBytes(tt.bytes))
			assert.Contains(t, stdout, "Estimated cost: "+targetintel.FormatCost(float64(tt.bytes)/(1<<40)*targetintel.DefaultPricePerTiB)+" (on-demand, $6.25/TiB)")
			if tt.within {
				assert.Contains(t, stdout, "Max cost: $1.00 (within limit)")
				assert.Empty(t, stderr)
			} else {
				assert.NotContains(t, stdout, "Max cost:")
				assert.Contains(t, stderr, "The estimate exceeds the max cost $1.00.")
			}
		})
	}

	t.Run("no cap", func(t *testing.T) {
		s := fakeBQ(t)
		s.SetQuery(bqfake.Query{Stats: bqfake.Stats{TotalBytesProcessed: 1 << 40}})

		stdout, _, err := runTI(t, output.ModeJSON, "estimate", "-q", "SELECT 1", "--max-cost", "0")
		require.NoError(t, err)
		got := decodeOne(t, stdout)
		assert.Equal(t, true, got["within_limit"], "with no cap every estimate is within it")
		assert.InDelta(t, 0, got["max_cost_usd"], 0)
	})
}

var countsSchema = []bqfake.Field{
	{Name: "cve_id", Type: "STRING"},
	{Name: "hosts", Type: "INTEGER"},
	{Name: "hosts_confirmed", Type: "INTEGER"},
	{Name: "kev_in_catalog", Type: "BOOLEAN"},
	{Name: "epss_score", Type: "FLOAT"},
	{Name: "top_countries", Type: "RECORD", Mode: "REPEATED", Fields: []bqfake.Field{
		{Name: "country_code", Type: "STRING"},
		{Name: "hosts", Type: "INTEGER"},
	}},
}

func countsRows() []bqfake.Row {
	return []bqfake.Row{
		{"cve_id": "CVE-2024-0001", "hosts": 15, "hosts_confirmed": 12, "kev_in_catalog": true, "epss_score": 0.9,
			"top_countries": []map[string]any{{"country_code": "US", "hosts": 10}, {"country_code": "IN", "hosts": 5}}},
		{"cve_id": "CVE-2024-0002", "hosts": 3, "hosts_confirmed": 1, "kev_in_catalog": false, "epss_score": 0.1,
			"top_countries": []map[string]any{{"country_code": "DE", "hosts": 3}}},
	}
}

const threeCVEs = "CVE-2024-0001,cve-2024-0002,CVE-2024-0003"

func TestE2ECVECountsJSON(t *testing.T) {
	s := fakeBQ(t)
	s.SetQuery(bqfake.Query{Schema: countsSchema, Rows: countsRows()})

	stdout, _, err := runTI(t, output.ModeJSON, "cves", "--cves", threeCVEs, "--counts")
	require.NoError(t, err)

	got := decodeOne(t, stdout)
	assert.Equal(t, []any{"CVE-2024-0003"}, got["missing"])
	assert.Equal(t, "cve_host_counts", got["table"])
	assert.Equal(t, map[string]any{"cves": []any{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"}}, got["query"])
	rows, ok := got["rows"].([]any)
	require.True(t, ok, got)
	require.Len(t, rows, 2)
	first := rows[0].(map[string]any)
	assert.Equal(t, []any{
		map[string]any{"country_code": "US", "hosts": float64(10)},
		map[string]any{"country_code": "IN", "hosts": float64(5)},
	}, first["top_countries"], "JSON keeps top_countries as records")

	job := s.LastJob()
	assert.Contains(t, jobSQL(job), "cve_host_counts")
	assert.Contains(t, jobSQL(job), "UNNEST(@cves)")
	assert.Equal(t, map[string]any{"cves": []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"}}, jobParams(job))
}

func TestE2ECVECountsText(t *testing.T) {
	s := fakeBQ(t)
	s.SetQuery(bqfake.Query{Schema: countsSchema, Rows: countsRows()})

	stdout, stderr, err := runTI(t, output.ModeText, "cves", "--cves", threeCVEs, "--counts")
	require.NoError(t, err)

	assert.Contains(t, stdout, billedLine(0, 1, 2, 2, false))
	assert.Contains(t, stdout, "US 10, IN 5")
	assert.Contains(t, stdout, "DE 3")
	assert.Contains(t, stdout, "CVE-2024-0001")
	assert.Contains(t, stdout, "hosts_confirmed is tiers 40 and 30")
	assert.Contains(t, stderr, "No row for CVE-2024-0003:")
	assert.NotContains(t, stderr, "CVE-2024-0001")
}

func TestE2ECVECountsNoneMissing(t *testing.T) {
	s := fakeBQ(t)
	s.SetQuery(bqfake.Query{Schema: countsSchema, Rows: countsRows()})

	stdout, _, err := runTI(t, output.ModeJSON, "cves", "--cves", "CVE-2024-0001,CVE-2024-0002", "--counts")
	require.NoError(t, err)
	got := decodeOne(t, stdout)
	assert.Equal(t, []any{}, got["missing"], "an empty list, never null")
}

func TestE2ECVETop(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantSQL    []string
		notSQL     []string
		wantParams map[string]any
		wantTop    map[string]any
	}{
		{
			name:       "no floor",
			args:       []string{"cves", "--top"},
			notSQL:     []string{"@min_epss", "kev_in_catalog ORDER"},
			wantParams: map[string]any{},
			wantTop:    map[string]any{"kev_only": false, "min_epss": float64(0)},
		},
		{
			name:       "epss floor and kev",
			args:       []string{"cves", "--top", "--min-epss", "0.5", "--kev"},
			wantSQL:    []string{"epss_score >= @min_epss", "AND kev_in_catalog"},
			wantParams: map[string]any{"min_epss": "0.5"},
			wantTop:    map[string]any{"kev_only": true, "min_epss": 0.5},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := fakeBQ(t)
			s.SetQuery(bqfake.Query{Schema: countsSchema, Rows: countsRows(), Stats: bqfake.Stats{TotalBytesBilled: 10 << 20}})

			stdout, _, err := runTI(t, output.ModeJSON, tt.args...)
			require.NoError(t, err)
			got := decodeOne(t, stdout)
			assert.Equal(t, map[string]any{"top": tt.wantTop}, got["query"])
			assert.Equal(t, "cve_host_counts", got["table"])
			assert.NotContains(t, got, "missing", "--top names no CVEs, so none can be missing")

			job := s.LastJob()
			assert.Contains(t, jobSQL(job), "WHERE hosts > 0")
			for _, sub := range tt.wantSQL {
				assert.Contains(t, jobSQL(job), sub)
			}
			for _, sub := range tt.notSQL {
				assert.NotContains(t, jobSQL(job), sub)
			}
			assert.Equal(t, tt.wantParams, jobParams(job))

			stdout, stderr, err := runTI(t, output.ModeText, tt.args...)
			require.NoError(t, err)
			assert.Contains(t, stdout, billedLine(10<<20, 1, 2, 2, false))
			assert.Contains(t, stdout, "US 10, IN 5")
			assert.NotContains(t, stderr, "No row for")
		})
	}
}

var observationSchema = []bqfake.Field{
	{Name: "matched_cve_id", Type: "STRING"},
	{Name: "ip", Type: "STRING"},
	{Name: "ip_int", Type: "INTEGER"},
	{Name: "port", Type: "INTEGER"},
	{Name: "vendor", Type: "STRING"},
	{Name: "product", Type: "STRING"},
	{Name: "version", Type: "STRING"},
	{Name: "timestamp", Type: "TIMESTAMP"},
}

func observationRows() []bqfake.Row {
	ts := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

	return []bqfake.Row{
		{"matched_cve_id": "CVE-2024-6387", "ip": "192.0.2.1", "ip_int": 3221225985, "port": 22, "vendor": "openbsd", "product": "openssh", "version": "9.6", "timestamp": ts},
	}
}

func TestE2ECVERoutine(t *testing.T) {
	s := fakeBQ(t)
	s.SetQuery(bqfake.Query{Schema: observationSchema, Rows: observationRows()})

	stdout, _, err := runTI(t, output.ModeJSON, "cves", "--cves", "CVE-2024-6387", "--days", "7", "--min-confidence", "30")
	require.NoError(t, err)

	got := decodeOne(t, stdout)
	assert.Equal(t, "observations_by_cves_scored", got["routine"])
	assert.Equal(t, map[string]any{"cves": []any{"CVE-2024-6387"}, "min_confidence": float64(30), "lookback_days": float64(7)}, got["query"])
	assert.NotContains(t, got, "group_by")
	rows := got["rows"].([]any)
	require.Len(t, rows, 1)
	assert.Equal(t, "2026-10-01T00:00:00Z", rows[0].(map[string]any)["timestamp"])

	job := s.LastJob()
	assert.Contains(t, jobSQL(job), "`"+e2eProject+".anchorbreaker_views_prod.observations_by_cves_scored`(@cves, @min_confidence, @lookback_days)")
	assert.Equal(t, map[string]any{"cves": []string{"CVE-2024-6387"}, "min_confidence": "30", "lookback_days": "7"}, jobParams(job))
}

func TestE2ECVERoutineText(t *testing.T) {
	s := fakeBQ(t)
	s.SetQuery(bqfake.Query{Schema: observationSchema, Rows: observationRows()})

	stdout, _, err := runTI(t, output.ModeText, "cves", "--cves", "CVE-2024-6387")
	require.NoError(t, err)
	assert.Contains(t, stdout, billedLine(0, 1, 1, 1, false))
	assert.Contains(t, stdout, "openssh")
	assert.Contains(t, stdout, "matched_cve_id")
	// The fake schema lacks some fixed text columns; only the ones present
	// are shown and counted.
	assert.Contains(t, stdout, "Showing 7 of 8 columns; use --json for every field")
	assert.NotContains(t, stdout, "kev_in_catalog")
}

func TestE2ECVEGroupBy(t *testing.T) {
	schema := []bqfake.Field{
		{Name: "matched_cve_id", Type: "STRING"},
		{Name: "country_code", Type: "STRING"},
		{Name: "country", Type: "STRING"},
		{Name: "hosts", Type: "INTEGER"},
		{Name: "observations", Type: "INTEGER"},
	}
	rows := []bqfake.Row{{"matched_cve_id": "CVE-2024-0001", "country_code": "US", "country": "United States", "hosts": 4, "observations": 9}}

	t.Run("json", func(t *testing.T) {
		s := fakeBQ(t)
		s.SetQuery(bqfake.Query{Schema: schema, Rows: rows})

		stdout, _, err := runTI(t, output.ModeJSON, "cves", "--cves", "CVE-2024-0001,CVE-2024-0002", "--group-by", "country")
		require.NoError(t, err)
		got := decodeOne(t, stdout)
		assert.Equal(t, "country", got["group_by"])
		assert.Equal(t, "observations_by_cves_scored", got["routine"])
		require.Len(t, got["rows"], 1)

		sql := jobSQL(s.LastJob())
		assert.True(t, strings.HasPrefix(sql, "SELECT matched_cve_id, country_code, country, COUNT(DISTINCT ip_int) AS hosts"), sql)
		assert.Contains(t, sql, "observations_by_cves_scored")
	})

	t.Run("single cve text", func(t *testing.T) {
		s := fakeBQ(t)
		s.SetQuery(bqfake.Query{Schema: schema[1:], Rows: rows})

		stdout, _, err := runTI(t, output.ModeText, "cves", "--cves", "CVE-2024-0001", "--group-by", "country")
		require.NoError(t, err)
		sql := jobSQL(s.LastJob())
		assert.True(t, strings.HasPrefix(sql, "SELECT country_code, country, COUNT(DISTINCT ip_int)"), "a single CVE is not grouped on matched_cve_id: %s", sql)
		assert.Contains(t, stdout, "United States")
		assert.Contains(t, stdout, "observations")
		assert.NotContains(t, stdout, "Showing", "a rollup shows every column")
	})
}

var hostProfileSchema = []bqfake.Field{
	{Name: "ip", Type: "STRING"},
	{Name: "last_seen", Type: "TIMESTAMP"},
	{Name: "port_count", Type: "INTEGER"},
	{Name: "identified", Type: "INTEGER"},
	{Name: "truncated", Type: "BOOLEAN"},
	{Name: "protocols", Type: "STRING", Mode: "REPEATED"},
	{Name: "services", Type: "RECORD", Mode: "REPEATED", Fields: []bqfake.Field{
		{Name: "port", Type: "INTEGER"},
		{Name: "service", Type: "STRING"},
		{Name: "transport", Type: "STRING"},
	}},
	{Name: "country", Type: "STRING"},
	{Name: "country_code", Type: "STRING"},
	{Name: "asn", Type: "INTEGER"},
	{Name: "as_name", Type: "STRING"},
	{Name: "as_domain", Type: "STRING"},
}

var hostFingerprintSchema = []bqfake.Field{
	{Name: "port", Type: "INTEGER"},
	{Name: "protocol", Type: "STRING"},
	{Name: "vendor", Type: "STRING"},
	{Name: "product", Type: "STRING"},
	{Name: "version", Type: "STRING"},
	{Name: "cpe", Type: "STRING"},
	{Name: "rule_id", Type: "STRING"},
	{Name: "cves", Type: "STRING", Mode: "REPEATED"},
	{Name: "probe_ok", Type: "BOOLEAN"},
}

var hostCPEMatchSchema = []bqfake.Field{
	{Name: "port", Type: "INTEGER"},
	{Name: "cpe", Type: "STRING"},
	{Name: "cve_id", Type: "STRING"},
	{Name: "confidence", Type: "INTEGER"},
	{Name: "match", Type: "STRING"},
}

func hostProfileRow() bqfake.Row {
	return bqfake.Row{
		"ip": "1.2.3.4", "last_seen": time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), "port_count": 2, "identified": 1, "truncated": false,
		"protocols": []string{"ssh", "dns"},
		"services": []map[string]any{
			{"port": 22, "service": "ssh", "transport": "tcp"},
			{"port": 53, "service": "dns", "transport": "udp"},
		},
		"country": "United States", "country_code": "US", "asn": 15169, "as_name": "GOOGLE", "as_domain": "google.com",
	}
}

// routeHost answers the host_profile and fingerprint_current lookups with
// the given rows, and cpe_cve_matches with none, routing on the SQL text.
func routeHost(s *bqfake.Server, profile, fingerprints []bqfake.Row) {
	routeHostCVEs(s, profile, fingerprints, nil)
}

// routeHostCVEs is routeHost with cpe_cve_matches answered by matches.
func routeHostCVEs(s *bqfake.Server, profile, fingerprints, matches []bqfake.Row) {
	s.HandleQuery(func(job *bq.Job) bqfake.Query {
		sql := jobSQL(job)
		switch {
		case strings.Contains(sql, ".cpe_cve_matches`"):
			return bqfake.Query{Schema: hostCPEMatchSchema, Rows: matches, Stats: bqfake.Stats{TotalBytesBilled: 5 << 20, TotalBytesProcessed: 1 << 20}}
		case strings.Contains(sql, ".fingerprint_current`"):
			return bqfake.Query{Schema: hostFingerprintSchema, Rows: fingerprints, Stats: bqfake.Stats{TotalBytesBilled: 20 << 20, TotalBytesProcessed: 1 << 30}}
		case strings.Contains(sql, ".host_profile`"):
			return bqfake.Query{Schema: hostProfileSchema, Rows: profile, Stats: bqfake.Stats{TotalBytesBilled: 10 << 20, TotalBytesProcessed: 1 << 40}}
		}

		return bqfake.Query{Err: &bqfake.JobError{Reason: "invalidQuery", Message: "unexpected SQL: " + sql}}
	})
}

func TestE2EHostJSON(t *testing.T) {
	fps := []bqfake.Row{{"port": 22, "protocol": "ssh", "vendor": "openbsd", "product": "openssh", "version": "9.6", "probe_ok": true, "cves": []string{"CVE-2024-6387"}}}
	matches := []bqfake.Row{
		{"port": 22, "cpe": "cpe:2.3:a:openbsd:openssh:9.6", "cve_id": "CVE-2024-6387", "confidence": 30, "match": "version"},
		{"port": 22, "cpe": "cpe:2.3:a:openbsd:openssh:9.6", "cve_id": "CVE-2023-51385", "confidence": 20, "match": "version"},
		{"port": 22, "cpe": "cpe:2.3:a:openbsd:openssh:-", "cve_id": "CVE-2008-3844", "confidence": 10, "match": "product"},
	}
	tests := []struct {
		name      string
		profile   []bqfake.Row
		fps       []bqfake.Row
		found     bool
		wantFPs   int
		wantCVEs  int
		noProfile bool
	}{
		{name: "found", profile: []bqfake.Row{hostProfileRow()}, fps: fps, found: true, wantFPs: 1, wantCVEs: 2},
		{name: "profile only", profile: []bqfake.Row{hostProfileRow()}, found: true},
		{name: "fingerprints only", fps: fps, found: true, wantFPs: 1, wantCVEs: 2, noProfile: true},
		{name: "not found", found: false, noProfile: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := fakeBQ(t)
			routeHostCVEs(s, tt.profile, tt.fps, matches)

			stdout, _, err := runTI(t, output.ModeJSON, "host", "1.2.3.4")
			require.NoError(t, err)

			got := decodeOne(t, stdout)
			assert.InDelta(t, output.SchemaVersion, got["schema_version"], 0)
			assert.Equal(t, tt.found, got["found"])
			assert.Equal(t, map[string]any{"ip": "1.2.3.4", "lookback_days": float64(30), "min_confidence": float64(20)}, got["query"])
			fpsGot, ok := got["fingerprints"].([]any)
			require.True(t, ok, "fingerprints is always an array, never null: %v", got["fingerprints"])
			assert.Len(t, fpsGot, tt.wantFPs)
			cvesGot, ok := got["cves"].([]any)
			require.True(t, ok, "cves is always an array, never null: %v", got["cves"])
			require.Len(t, cvesGot, tt.wantCVEs)
			if tt.wantCVEs > 0 {
				assert.Equal(t, map[string]any{
					"port": float64(22), "cve_id": "CVE-2024-6387", "confidence": float64(40), "match": "probe", "cpe": "",
				}, cvesGot[0], "the probe-confirmed rule annotation beats the tier-30 CPE match")
				assert.Equal(t, "CVE-2023-51385", cvesGot[1].(map[string]any)["cve_id"])
				assert.InDelta(t, 1, got["cves_below_min_confidence"], 0, "the tier-10 product match is hidden")
			} else {
				assert.InDelta(t, 0, got["cves_below_min_confidence"], 0, "CPE matches on ports not fingerprinted are ignored")
			}
			if tt.noProfile {
				assert.Nil(t, got["profile"])
			} else {
				profile := got["profile"].(map[string]any)
				assert.Equal(t, "1.2.3.4", profile["ip"])
				assert.Len(t, profile["services"], 2)
			}

			jobs := s.Jobs()
			require.Len(t, jobs, 3)
			assert.Contains(t, jobSQL(jobs[0]), "host_profile")
			assert.Contains(t, jobSQL(jobs[1]), "fingerprint_current")
			assert.Contains(t, jobSQL(jobs[2]), "cpe_cve_matches")
			assert.Equal(t, map[string]any{"ip": "1.2.3.4"}, jobParams(jobs[0]))
			assert.Equal(t, map[string]any{"ip": "1.2.3.4", "lookback_days": "30"}, jobParams(jobs[1]))
			assert.Equal(t, map[string]any{"ip": "1.2.3.4"}, jobParams(jobs[2]))

			gotJobs, ok := got["jobs"].([]any)
			require.True(t, ok, got)
			require.Len(t, gotJobs, 3)
			for i, name := range []string{"host_profile", "fingerprint_current", "cpe_cve_matches"} {
				j := gotJobs[i].(map[string]any)
				assert.Equal(t, name, j["name"])
				assert.Equal(t, jobs[i].JobReference.JobId, j["job_id"])
			}
			assert.InDelta(t, 10<<20, gotJobs[0].(map[string]any)["bytes_billed"], 0)
			assert.InDelta(t, 20<<20, gotJobs[1].(map[string]any)["bytes_billed"], 0)
			assert.InDelta(t, 5<<20, gotJobs[2].(map[string]any)["bytes_billed"], 0)
		})
	}
}

func TestE2EHostText(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		s := fakeBQ(t)
		routeHostCVEs(s, []bqfake.Row{hostProfileRow()},
			[]bqfake.Row{{"port": 22, "protocol": "ssh", "vendor": "openbsd", "product": "openssh", "version": "9.6"}},
			[]bqfake.Row{
				{"port": 22, "cpe": "cpe:2.3:a:openbsd:openssh:9.6", "cve_id": "CVE-2024-6387", "confidence": 30, "match": "version"},
				{"port": 22, "cpe": "cpe:2.3:a:openbsd:openssh:-", "cve_id": "CVE-2008-3844", "confidence": 10, "match": "product"},
			})

		stdout, stderr, err := runTI(t, output.ModeText, "host", "1.2.3.4")
		require.NoError(t, err)
		total := float64(35<<20) / (1 << 40) * targetintel.DefaultPricePerTiB
		assert.Contains(t, stdout, "Billed "+targetintel.FormatCost(total)+" across 3 lookups")
		assert.Contains(t, stdout, "Host: 1.2.3.4")
		assert.Contains(t, stdout, "Location: United States (US)")
		assert.Contains(t, stdout, "Network: 15169 GOOGLE (google.com)")
		assert.Contains(t, stdout, "Last seen: 2026-10-01T00:00:00Z")
		assert.Contains(t, stdout, "Ports listening: 2")
		assert.Contains(t, stdout, "transport")
		assert.Contains(t, stdout, "udp")
		assert.Contains(t, stdout, "openssh")
		assert.Contains(t, stdout, "CVE-2024-6387")
		assert.NotContains(t, stdout, "CVE-2008-3844", "tier 10 is below the default --min-confidence")
		assert.Contains(t, stdout, "1 CVEs at confidence 20 or above; 40 and 30 are confirmed. 1 more below it")
		assert.Empty(t, stderr)
	})

	t.Run("min confidence 10", func(t *testing.T) {
		s := fakeBQ(t)
		routeHostCVEs(s, nil,
			[]bqfake.Row{{"port": 22, "protocol": "ssh", "vendor": "openbsd", "product": "openssh"}},
			[]bqfake.Row{{"port": 22, "cpe": "cpe:2.3:a:openbsd:openssh:-", "cve_id": "CVE-2008-3844", "confidence": 10, "match": "product"}})

		stdout, _, err := runTI(t, output.ModeText, "host", "1.2.3.4", "--min-confidence", "10")
		require.NoError(t, err)
		assert.Contains(t, stdout, "CVE-2008-3844")
		assert.Contains(t, stdout, "product")
	})

	t.Run("not found", func(t *testing.T) {
		s := fakeBQ(t)
		routeHost(s, nil, nil)

		stdout, stderr, err := runTI(t, output.ModeText, "host", "1.2.3.4")
		require.NoError(t, err)
		assert.Contains(t, stdout, "across 3 lookups")
		assert.NotContains(t, stdout, "Host:")
		assert.Contains(t, stderr, "1.2.3.4 was not seen listening on any port in the current scan window.")
	})
}

func TestE2EHostDryRun(t *testing.T) {
	t.Run("json", func(t *testing.T) {
		s := fakeBQ(t)
		routeHost(s, nil, nil)

		stdout, _, err := runTI(t, output.ModeJSON, "host", "1.2.3.4", "--dry-run")
		require.NoError(t, err)

		got := decodeOne(t, stdout)
		assert.InDelta(t, output.SchemaVersion, got["schema_version"], 0)
		ests, ok := got["estimates"].([]any)
		require.True(t, ok, got)
		require.Len(t, ests, 3)
		profile, fps := ests[0].(map[string]any), ests[1].(map[string]any)
		assert.Equal(t, "host_profile", profile["name"])
		assert.Equal(t, "fingerprint_current", fps["name"])
		assert.Equal(t, "cpe_cve_matches", ests[2].(map[string]any)["name"])
		assert.Equal(t, false, profile["within_limit"], "1 TiB at $6.25 is over the $1 cap")
		assert.Equal(t, true, fps["within_limit"])
		assert.InDelta(t, 1<<40, profile["estimate"].(map[string]any)["bytes_processed"], 0)

		jobs := s.Jobs()
		require.Len(t, jobs, 3)
		for _, j := range jobs {
			assert.True(t, j.Configuration.DryRun)
		}
	})

	t.Run("text", func(t *testing.T) {
		s := fakeBQ(t)
		routeHost(s, nil, nil)

		stdout, stderr, err := runTI(t, output.ModeText, "host", "1.2.3.4", "--dry-run")
		require.NoError(t, err)
		assert.Contains(t, stdout, "Lookup: host_profile")
		assert.Contains(t, stdout, "Lookup: fingerprint_current")
		assert.Contains(t, stdout, "Lookup: cpe_cve_matches")
		assert.Contains(t, stdout, "Max cost: $1.00 (within limit)")
		assert.Contains(t, stderr, "The estimate exceeds the max cost $1.00.")
	})
}

var hostRangeSchema = []bqfake.Field{
	{Name: "ip", Type: "STRING"},
	{Name: "country_code", Type: "STRING"},
	{Name: "asn", Type: "INTEGER"},
	{Name: "as_name", Type: "STRING"},
	{Name: "last_seen", Type: "TIMESTAMP"},
	{Name: "port_count", Type: "INTEGER"},
	{Name: "services", Type: "STRING", Mode: "REPEATED"},
	{Name: "products", Type: "STRING", Mode: "REPEATED"},
}

func hostRangeRows() []bqfake.Row {
	ts := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

	return []bqfake.Row{
		{"ip": "10.0.0.1", "country_code": "US", "asn": 64500, "last_seen": ts, "port_count": 2,
			"services": []string{"22/tcp ssh", "80/tcp http"}, "products": []string{"openbsd openssh 9.6", "nginx 1.25"}},
		{"ip": "10.0.0.2", "country_code": "US", "asn": 64500, "last_seen": ts, "port_count": 1,
			"services": []string{"443/tcp https"}},
	}
}

func TestE2EHostRange(t *testing.T) {
	t.Run("json", func(t *testing.T) {
		s := fakeBQ(t)
		s.SetQuery(bqfake.Query{Schema: hostRangeSchema, Rows: hostRangeRows()})

		stdout, _, err := runTI(t, output.ModeJSON, "host", "10.0.0.0/30")
		require.NoError(t, err)

		got := decodeOne(t, stdout)
		assert.Equal(t, map[string]any{"cidr": "10.0.0.0/30", "lookback_days": float64(30)}, got["query"])
		rows := got["rows"].([]any)
		require.Len(t, rows, 2)
		first, second := rows[0].(map[string]any), rows[1].(map[string]any)
		assert.Equal(t, []any{"22/tcp ssh", "80/tcp http"}, first["services"])
		assert.Equal(t, []any{"openbsd openssh 9.6", "nginx 1.25"}, first["products"])
		assert.Equal(t, []any{}, second["products"])

		job := s.LastJob()
		require.Len(t, s.Jobs(), 1, "a range is one query")
		assert.Equal(t, map[string]any{"lo": "167772160", "hi": "167772163", "lookback_days": "30"}, jobParams(job))
	})

	t.Run("text", func(t *testing.T) {
		s := fakeBQ(t)
		s.SetQuery(bqfake.Query{Schema: hostRangeSchema, Rows: hostRangeRows(), Stats: bqfake.Stats{TotalBytesBilled: 10 << 20}})

		stdout, stderr, err := runTI(t, output.ModeText, "host", "10.0.0.0/30", "--limit", "1")
		require.NoError(t, err)
		want := strings.Replace(billedLine(10<<20, 1, 1, 2, true), " rows", " hosts", 1)
		assert.Contains(t, stdout, want)
		assert.Contains(t, stdout, "22/tcp ssh, 80/tcp http")
		assert.Contains(t, stdout, "openbsd openssh 9.6, nginx 1.25")
		assert.NotContains(t, stdout, "10.0.0.2")
		assert.Contains(t, stdout, "Showing 7 of 8 columns")
		assert.Empty(t, stderr)
	})

	t.Run("no hosts", func(t *testing.T) {
		s := fakeBQ(t)
		s.SetQuery(bqfake.Query{Schema: hostRangeSchema})

		stdout, stderr, err := runTI(t, output.ModeText, "host", "10.0.0.0/30")
		require.NoError(t, err)
		assert.Contains(t, stdout, "0 of 0 hosts")
		assert.Contains(t, stderr, "No host in 10.0.0.0/30 was seen listening on any port in the current scan window.")
		assert.NotContains(t, stdout, "port_count", "no table for an empty range")
	})
}

func TestE2EProduct(t *testing.T) {
	s := fakeBQ(t)
	s.SetQuery(bqfake.Query{Schema: observationSchema, Rows: observationRows()})

	stdout, _, err := runTI(t, output.ModeJSON, "product", "--vendor", "openbsd", "--days", "14")
	require.NoError(t, err)

	got := decodeOne(t, stdout)
	assert.Equal(t, "observations_by_product", got["routine"])
	assert.Equal(t, map[string]any{"vendor": "openbsd", "lookback_days": float64(14)}, got["query"])
	assert.Len(t, got["rows"], 1)

	job := s.LastJob()
	assert.Contains(t, jobSQL(job), "observations_by_product`(@vendor, @product, @lookback_days)")
	params := jobParams(job)
	assert.Equal(t, "%openbsd%", params["vendor"])
	assert.Equal(t, "14", params["lookback_days"])
}

func TestE2EDatasetsList(t *testing.T) {
	s := fakeBQ(t)
	s.AddDataset(e2eProject, "anchorbreaker_prod")
	s.AddDataset(e2eProject, "anchorbreaker_views_prod")

	stdout, _, err := runTI(t, output.ModeJSON, "datasets", "list")
	require.NoError(t, err)
	var got []map[string]any
	require.NoError(t, json.Unmarshal([]byte(stdout), &got), stdout)
	assert.Equal(t, []map[string]any{
		{"project": e2eProject, "dataset": "anchorbreaker_prod"},
		{"project": e2eProject, "dataset": "anchorbreaker_views_prod"},
	}, got)

	stdout, _, err = runTI(t, output.ModeText, "datasets", "list")
	require.NoError(t, err)
	assert.Contains(t, stdout, "2 datasets in "+e2eProject)
	assert.Contains(t, stdout, e2eProject+".anchorbreaker_views_prod")
}

func TestE2ETables(t *testing.T) {
	s := fakeBQ(t)
	ts := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	s.AddTable(e2eProject, "anchorbreaker_prod", "host_profile", bqfake.Table{
		Description:           "One row per host",
		NumRows:               1000,
		NumBytes:              1 << 40,
		TimePartitioningType:  "DAY",
		TimePartitioningField: "last_seen",
		ClusteringFields:      []string{"ip_int"},
		Schema:                []bqfake.Field{{Name: "ip_int", Type: "INTEGER", Mode: "REQUIRED"}, {Name: "services", Type: "STRING", Mode: "REPEATED"}},
		Created:               ts,
		LastModified:          ts,
	})
	s.AddTable(e2eProject, "anchorbreaker_prod", "fingerprint_current", bqfake.Table{Created: ts, LastModified: ts})

	t.Run("list json", func(t *testing.T) {
		stdout, _, err := runTI(t, output.ModeJSON, "tables", "list", "anchorbreaker_prod")
		require.NoError(t, err)
		var got []map[string]any
		require.NoError(t, json.Unmarshal([]byte(stdout), &got), stdout)
		assert.Equal(t, []map[string]any{
			{"project": e2eProject, "dataset": "anchorbreaker_prod", "table": "host_profile"},
			{"project": e2eProject, "dataset": "anchorbreaker_prod", "table": "fingerprint_current"},
		}, got)
	})

	t.Run("list text", func(t *testing.T) {
		stdout, _, err := runTI(t, output.ModeText, "tables", "list", e2eProject+".anchorbreaker_prod")
		require.NoError(t, err)
		assert.Contains(t, stdout, "2 tables in "+e2eProject+".anchorbreaker_prod")
		assert.Contains(t, stdout, "fingerprint_current")
	})

	t.Run("describe json", func(t *testing.T) {
		stdout, _, err := runTI(t, output.ModeJSON, "tables", "describe", "anchorbreaker_prod.host_profile")
		require.NoError(t, err)
		got := decodeOne(t, stdout)
		assert.Equal(t, "host_profile", got["table"])
		assert.Equal(t, "TABLE", got["type"])
		assert.Equal(t, "One row per host", got["description"])
		assert.InDelta(t, 1000, got["num_rows"], 0)
		assert.InDelta(t, targetintel.DefaultPricePerTiB, got["full_scan_cost_usd"], 1e-9)
		assert.Equal(t, "last_seen", got["partition_field"])
		assert.Equal(t, "DAY", got["partition_type"])
		assert.Equal(t, []any{"ip_int"}, got["clustering_fields"])
		assert.Equal(t, "2026-01-02T00:00:00Z", got["created"])
		assert.Equal(t, []any{
			map[string]any{"name": "ip_int", "type": "INTEGER", "mode": "REQUIRED"},
			map[string]any{"name": "services", "type": "STRING", "mode": "REPEATED"},
		}, got["schema"])
	})

	t.Run("describe text", func(t *testing.T) {
		stdout, _, err := runTI(t, output.ModeText, "tables", "describe", "anchorbreaker_prod.host_profile")
		require.NoError(t, err)
		assert.Contains(t, stdout, "Table: "+e2eProject+".anchorbreaker_prod.host_profile")
		assert.Contains(t, stdout, "Type: TABLE")
		assert.Contains(t, stdout, "Description: One row per host")
		assert.Contains(t, stdout, "Rows: 1000")
		assert.Contains(t, stdout, "Size: 1.00 TiB (full scan $6.25)")
		assert.Contains(t, stdout, "Partitioned on: last_seen (DAY)")
		assert.Contains(t, stdout, "Clustered on: ip_int")
		assert.Contains(t, stdout, "REPEATED")
	})

	t.Run("describe missing table", func(t *testing.T) {
		_, _, err := runTI(t, output.ModeJSON, "tables", "describe", "anchorbreaker_prod.nope")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nope")
	})
}
