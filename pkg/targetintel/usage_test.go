package targetintel

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulncheck-oss/cli/internal/bqfake"
)

func TestUsageLogAppendAndRecords(t *testing.T) {
	t.Parallel()
	l := &UsageLog{Dir: filepath.Join(t.TempDir(), "usage")}
	oct := time.Date(2026, 10, 31, 23, 0, 0, 0, time.UTC)
	nov := time.Date(2026, 11, 1, 1, 0, 0, 0, time.UTC)
	require.NoError(t, l.Append(UsageRecord{Time: nov.Unix(), CostUSD: 0.5, BytesBilled: 100, Command: "host"}))
	require.NoError(t, l.Append(UsageRecord{Time: oct.Unix(), CostUSD: 0.25, BytesBilled: 50, CacheHit: true}))

	for _, name := range []string{"2026-10.jsonl", "2026-11.jsonl"} {
		fi, err := os.Stat(filepath.Join(l.Dir, name))
		require.NoError(t, err, "one file per UTC month")
		assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	}

	recs, err := l.Records(oct.Add(-time.Hour), nov.Add(time.Hour))
	require.NoError(t, err)
	require.Len(t, recs, 2)
	assert.Equal(t, oct.Unix(), recs[0].Time, "oldest first across files")
	assert.Equal(t, "host", recs[1].Command)

	recs, err = l.Records(nov, nov.Add(time.Hour))
	require.NoError(t, err)
	assert.Len(t, recs, 1, "from is inclusive")
	recs, err = l.Records(oct.Add(-time.Hour), oct)
	require.NoError(t, err)
	assert.Empty(t, recs, "to is exclusive")

	assert.Equal(t, UsageTotals{Queries: 2, CacheHits: 1, BytesBilled: 150, CostUSD: 0.75}, SumUsage([]UsageRecord{
		{CostUSD: 0.5, BytesBilled: 100}, {CostUSD: 0.25, BytesBilled: 50, CacheHit: true},
	}))
}

func TestUsageLogMissingDirIsEmpty(t *testing.T) {
	t.Parallel()
	l := &UsageLog{Dir: filepath.Join(t.TempDir(), "nope")}
	recs, err := l.Records(time.Unix(0, 0), time.Now())
	require.NoError(t, err)
	assert.Empty(t, recs)
	assert.NoError(t, l.Prune(time.Now()))
}

func TestUsageLogSkipsBadLines(t *testing.T) {
	t.Parallel()
	l := &UsageLog{Dir: t.TempDir()}
	at := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	data := "not json\n{\"ts\":" + strconv.FormatInt(at.Unix(), 10) + ",\"cost_usd\":1}\n{\"cost_usd\":2}\n{\"ts\":" + strconv.FormatInt(at.Unix(), 10)
	require.NoError(t, os.WriteFile(filepath.Join(l.Dir, "2026-05.jsonl"), []byte(data), 0o600))

	recs, err := l.Records(at, at.Add(time.Hour))
	require.NoError(t, err)
	require.Len(t, recs, 1, "garbage, a record with no time and a torn final line are skipped")
	assert.InDelta(t, 1.0, recs[0].CostUSD, 0)
}

func TestUsageLogPrune(t *testing.T) {
	t.Parallel()
	l := &UsageLog{Dir: t.TempDir()}
	for _, name := range []string{"2025-10.jsonl", "2025-11.jsonl", "2026-11.jsonl", "notes.txt"} {
		require.NoError(t, os.WriteFile(filepath.Join(l.Dir, name), nil, 0o600))
	}
	require.NoError(t, l.Prune(time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)))

	entries, err := os.ReadDir(l.Dir)
	require.NoError(t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	assert.Equal(t, []string{"2025-11.jsonl", "2026-11.jsonl", "notes.txt"}, names,
		"the 12 months before the current one are kept, older ones and foreign files are not touched")
}

func TestPeriodStarts(t *testing.T) {
	t.Parallel()
	loc := time.FixedZone("X", -5*3600)
	sun := time.Date(2026, 11, 1, 15, 4, 5, 0, loc)
	mon := time.Date(2026, 10, 26, 0, 0, 0, 0, loc)
	assert.Equal(t, time.Date(2026, 11, 1, 0, 0, 0, 0, loc), StartOfDay(sun))
	assert.Equal(t, mon, StartOfWeek(sun), "a Sunday belongs to the week that began on Monday")
	assert.Equal(t, mon, StartOfWeek(mon.Add(time.Hour)))
	assert.Equal(t, time.Date(2026, 11, 1, 0, 0, 0, 0, loc), StartOfMonth(sun))
	assert.Equal(t, time.Date(2026, 1, 1, 0, 0, 0, 0, loc), StartOfYear(sun))
}

func TestParseSinceUntil(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 1, 15, 0, 0, 0, time.UTC)
	cases := map[string]time.Time{
		"1d":         time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC),
		"7d":         time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC),
		"2w":         time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC),
		"2026-03-04": time.Date(2026, 3, 4, 0, 0, 0, 0, time.UTC),
	}
	for in, want := range cases {
		got, err := ParseSince(in, now)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}
	for _, bad := range []string{"", "0d", "7", "7m", "-1d", "2026-13-01", "yesterday"} {
		_, err := ParseSince(bad, now)
		assert.Error(t, err, bad)
	}

	until, err := ParseUntil("2026-03-04", now)
	require.NoError(t, err)
	assert.Equal(t, time.Date(2026, 3, 5, 0, 0, 0, 0, time.UTC), until, "the --until day itself is included")
	_, err = ParseUntil("7d", now)
	assert.Error(t, err)
}

func TestBucketUsage(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC) // Wednesday
	from := StartOfWeek(now)
	to := from.AddDate(0, 0, 7)
	recs := []UsageRecord{
		{Time: from.Add(time.Hour).Unix(), CostUSD: 1},
		{Time: from.Add(2 * time.Hour).Unix(), CostUSD: 2},
		{Time: now.Unix(), CostUSD: 4, CacheHit: true},
	}

	days, err := BucketUsage(recs, from, to, now, ByDay)
	require.NoError(t, err)
	require.Len(t, days, 3, "Monday to today; days still to come are left out")
	assert.Equal(t, from, days[0].Start)
	assert.InDelta(t, 3.0, days[0].CostUSD, 1e-9)
	assert.Equal(t, 2, days[0].Queries)
	assert.Equal(t, 0, days[1].Queries, "an empty day is kept as zero")
	assert.InDelta(t, 4.0, days[2].CostUSD, 1e-9)
	assert.Equal(t, 1, days[2].CacheHits)

	months, err := BucketUsage(recs, StartOfYear(now), StartOfYear(now).AddDate(1, 0, 0), now, ByMonth)
	require.NoError(t, err)
	require.Len(t, months, 11)
	assert.Equal(t, 3, months[10].Queries)

	weeks, err := BucketUsage(nil, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), to, now, ByWeek)
	require.NoError(t, err)
	assert.Equal(t, time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC), weeks[0].Start, "weeks start on Monday")

	_, err = BucketUsage(nil, from, to, now, "hour")
	assert.Error(t, err)
}

func TestRunRecordsUsage(t *testing.T) {
	t.Parallel()
	s := bqfake.New(t)
	s.SetQuery(bqfake.Query{Schema: observationSchema, Rows: observationRows(), Stats: bqfake.Stats{TotalBytesBilled: 1 << 40}})
	c := fakeClient(t, s)
	c.Usage = &UsageLog{Dir: t.TempDir()}

	before := time.Now().Add(-time.Second)
	res, err := c.Run(t.Context(), QueryOptions{SQL: "SELECT 1", PricePerTiB: testPrice, Command: "service http"})
	require.NoError(t, err)

	recs, err := c.Usage.Records(before, time.Now().Add(time.Second))
	require.NoError(t, err)
	require.Len(t, recs, 1)
	assert.Equal(t, UsageRecord{
		Time: recs[0].Time, CostUSD: testPrice, BytesBilled: 1 << 40,
		Command: "service http", Project: "p", JobID: res.JobID,
	}, recs[0])
}

func TestRunUsageFailureDoesNotFailQuery(t *testing.T) {
	t.Parallel()
	s := bqfake.New(t)
	s.SetQuery(bqfake.Query{Schema: observationSchema, Rows: observationRows()})
	c := fakeClient(t, s)
	blocker := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))
	c.Usage = &UsageLog{Dir: filepath.Join(blocker, "usage")}
	var got error
	c.OnUsageError = func(err error) { got = err }

	_, err := c.Run(t.Context(), QueryOptions{SQL: "SELECT 1", PricePerTiB: testPrice})
	require.NoError(t, err)
	assert.Error(t, got, "the failure is reported, not returned")
}
