package targetintel

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulncheck-oss/cli/internal/bqfake"
	"github.com/vulncheck-oss/cli/internal/errs"
	"github.com/vulncheck-oss/cli/internal/output"
	"github.com/vulncheck-oss/cli/pkg/targetintel"
)

// These tests swap package-level seams, so none may call t.Parallel.

// fixUsage points usage at a fresh log and pins the clock.
func fixUsage(t *testing.T, at time.Time, recs ...targetintel.UsageRecord) {
	t.Helper()
	isolateEnv(t)
	log := &targetintel.UsageLog{Dir: t.TempDir()}
	for _, r := range recs {
		require.NoError(t, log.Append(r))
	}
	origLog, origNow := usageLog, now
	usageLog = func() (*targetintel.UsageLog, error) { return log, nil }
	now = func() time.Time { return at }
	t.Cleanup(func() { usageLog, now = origLog, origNow })
}

func TestE2EUsageRecordsQueries(t *testing.T) {
	s := fakeBQ(t)
	s.SetQuery(bqfake.Query{Schema: ipPortSchema, Rows: ipPortRows(1), Stats: bqfake.Stats{TotalBytesBilled: 1 << 30}})

	_, stderr, err := runTI(t, output.ModeText, "query", "-q", "SELECT ip, port FROM t")
	require.NoError(t, err)
	assert.Empty(t, stderr, "recording is silent when it works")
	_, _, err = runTI(t, output.ModeText, "service", "http", "--title", "x")
	require.NoError(t, err)

	stdout, _, err := runTI(t, output.ModeJSON, "usage")
	require.NoError(t, err)
	got := decodeOne(t, stdout)
	assert.InDelta(t, 2, got["queries"], 0)
	assert.InDelta(t, 2<<30, got["bytes_billed"], 0)

	log, err := targetintel.DefaultUsageLog()
	require.NoError(t, err)
	recs, err := log.Records(time.Now().Add(-time.Minute), time.Now().Add(time.Minute))
	require.NoError(t, err)
	require.Len(t, recs, 2)
	assert.Equal(t, "query", recs[0].Command)
	assert.Equal(t, "service http", recs[1].Command)
	assert.Equal(t, e2eProject, recs[0].Project)
}

func TestE2EUsagePeriods(t *testing.T) {
	at := time.Date(2026, 11, 4, 15, 0, 0, 0, time.Local) // Wednesday
	rec := func(when time.Time, usd float64) targetintel.UsageRecord {
		return targetintel.UsageRecord{Time: when.Unix(), CostUSD: usd, BytesBilled: int64(usd * 100)}
	}
	fixUsage(t, at,
		rec(at.Add(-time.Hour), 1),                            // today
		rec(at.AddDate(0, 0, -2), 2),                          // Monday
		rec(at.AddDate(0, 0, -5), 4),                          // 30 Oct: last week and last month
		rec(time.Date(2026, 2, 1, 9, 0, 0, 0, time.Local), 8), // this year
	)

	cost := func(args ...string) float64 {
		t.Helper()
		stdout, _, err := runTI(t, output.ModeJSON, append([]string{"usage"}, args...)...)
		require.NoError(t, err, args)

		return decodeOne(t, stdout)["cost_usd"].(float64)
	}
	assert.InDelta(t, 1.0, cost(), 1e-9, "today by default")
	assert.InDelta(t, 1.0, cost("--today"), 1e-9)
	assert.InDelta(t, 3.0, cost("--week"), 1e-9)
	assert.InDelta(t, 3.0, cost("--month"), 1e-9)
	assert.InDelta(t, 15.0, cost("--year"), 1e-9)
	assert.InDelta(t, 7.0, cost("--since", "7d"), 1e-9)
	assert.InDelta(t, 8.0, cost("--since", "2026-02-01", "--until", "2026-02-01"), 1e-9)

	stdout, _, err := runTI(t, output.ModeJSON, "usage", "--week", "--by", "day")
	require.NoError(t, err)
	got := decodeOne(t, stdout)
	assert.Equal(t, "day", got["by"])
	buckets := got["buckets"].([]any)
	require.Len(t, buckets, 3, "Monday to Wednesday")
	assert.InDelta(t, 2.0, buckets[0].(map[string]any)["cost_usd"], 1e-9)
	assert.InDelta(t, 0.0, buckets[1].(map[string]any)["cost_usd"], 1e-9)
	assert.InDelta(t, 1.0, buckets[2].(map[string]any)["cost_usd"], 1e-9)
}

func TestE2EUsageText(t *testing.T) {
	at := time.Date(2026, 11, 4, 15, 0, 0, 0, time.Local)
	fixUsage(t, at,
		targetintel.UsageRecord{Time: at.Add(-time.Hour).Unix(), CostUSD: 0.5, BytesBilled: 3 << 30, CacheHit: true},
		targetintel.UsageRecord{Time: at.AddDate(0, 0, -1).Unix(), CostUSD: 0.25, BytesBilled: 1 << 30},
	)

	stdout, stderr, err := runTI(t, output.ModeText, "usage", "--week", "--by", "day")
	require.NoError(t, err)
	assert.Empty(t, stderr)
	assert.Contains(t, stdout, "This week (2026-11-02 to 2026-11-04)")
	assert.Contains(t, stdout, "2 (1 from cache)")
	assert.Contains(t, stdout, "4.00 GiB")
	assert.Contains(t, stdout, "$0.75")
	assert.Contains(t, stdout, "2026-11-03")
	assert.NotContains(t, stdout, "2026-11-05", "days still to come are not listed")

	stdout, _, err = runTI(t, output.ModeText, "spend")
	require.NoError(t, err, "spend is an alias")
	assert.Contains(t, stdout, "Today (2026-11-04)")
	assert.Contains(t, stdout, "$0.50")
}

func TestE2EUsageOldPeriodWarns(t *testing.T) {
	fixUsage(t, time.Date(2026, 11, 4, 15, 0, 0, 0, time.Local))

	_, stderr, err := runTI(t, output.ModeJSON, "usage", "--since", "2024-01-01")
	require.NoError(t, err)
	assert.Contains(t, stderr, "keeps 12 months")
}

func TestE2EUsageValidation(t *testing.T) {
	fixUsage(t, time.Date(2026, 11, 4, 15, 0, 0, 0, time.Local))

	for _, args := range [][]string{
		{"--today", "--week"},
		{"--month", "--since", "7d"},
		{"--until", "2026-11-01"},
		{"--since", "yesterday"},
		{"--since", "2026-11-03", "--until", "2026-11-01"},
		{"--by", "hour"},
		{"extra"},
	} {
		_, _, err := runTI(t, output.ModeText, append([]string{"usage"}, args...)...)
		require.Error(t, err, args)
		assert.Equal(t, errs.KindValidation, errs.Classify(err).Kind, "%v: %v", args, err)
	}
}
