package targetintel

import (
	"errors"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulncheck-oss/cli/internal/bqfake"
	"github.com/vulncheck-oss/cli/internal/errs"
	"github.com/vulncheck-oss/cli/pkg/config"
)

// isolateBudget points the config file at an empty HOME and clears the
// budget variables. Tests using it must not call t.Parallel.
func isolateBudget(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv(EnvDailyBudget, "")
	t.Setenv(EnvMonthlyBudget, "")
}

func TestResolveBudget(t *testing.T) {
	isolateBudget(t)
	assert.False(t, ResolveBudget().IsSet(), "no budget by default")

	t.Setenv(EnvDailyBudget, "3")
	assert.Equal(t, Budget{DailyUSD: 3, DailySource: "env"}, ResolveBudget(), "env alone")

	require.NoError(t, config.SetTargetIntel(config.TargetIntelConfig{DailyBudgetUSD: 5, MonthlyBudgetUSD: 50}))
	b := ResolveBudget()
	assert.Equal(t, Budget{DailyUSD: 3, DailySource: "env", MonthlyUSD: 50, MonthlySource: "config"}, b, "the stricter limit wins")

	t.Setenv(EnvDailyBudget, "1000")
	assert.Equal(t, 5.0, ResolveBudget().DailyUSD, "env cannot raise a saved budget")
	t.Setenv(EnvDailyBudget, "0")
	assert.Equal(t, 5.0, ResolveBudget().DailyUSD, "env cannot switch a saved budget off")

	t.Setenv(EnvDailyBudget, "lots")
	b = ResolveBudget()
	assert.True(t, math.IsNaN(b.DailyUSD))
	err := b.Validate()
	require.Error(t, err, "an unparsable budget fails rather than disappearing")
	assert.Contains(t, err.Error(), EnvDailyBudget)

	t.Setenv(EnvDailyBudget, "-1")
	assert.Error(t, ResolveBudget().Validate())
	t.Setenv(EnvDailyBudget, "")
	assert.NoError(t, ResolveBudget().Validate())
}

func TestBudgetStatus(t *testing.T) {
	t.Parallel()
	loc := time.FixedZone("X", 3600)
	now := time.Date(2026, 11, 4, 15, 0, 0, 0, loc)
	l := &UsageLog{Dir: t.TempDir()}
	require.NoError(t, l.Append(UsageRecord{Time: now.Add(-time.Hour).Unix(), CostUSD: 2}))
	require.NoError(t, l.Append(UsageRecord{Time: now.AddDate(0, 0, -2).Unix(), CostUSD: 40}))
	require.NoError(t, l.Append(UsageRecord{Time: now.AddDate(0, -1, 0).Unix(), CostUSD: 100}))

	st, err := Budget{DailyUSD: 5}.Status(l, now)
	require.NoError(t, err)
	assert.InDelta(t, 2.0, st.SpentTodayUSD, 1e-9)
	assert.InDelta(t, 42.0, st.SpentThisMonthUSD, 1e-9, "last month does not count")
	assert.InDelta(t, 3.0, st.RemainingUSD, 1e-9)
	assert.Equal(t, "daily", st.Binding)
	assert.Equal(t, time.Date(2026, 11, 5, 0, 0, 0, 0, loc), st.Resets)
	assert.False(t, st.Exceeded())

	st, err = Budget{DailyUSD: 5, MonthlyUSD: 43}.Status(l, now)
	require.NoError(t, err)
	assert.InDelta(t, 1.0, st.RemainingUSD, 1e-9, "the monthly limit leaves less")
	assert.Equal(t, "monthly", st.Binding)
	assert.Equal(t, time.Date(2026, 12, 1, 0, 0, 0, 0, loc), st.Resets)

	st, err = Budget{MonthlyUSD: 30}.Status(l, now)
	require.NoError(t, err)
	assert.True(t, st.Exceeded())
	assert.InDelta(t, 0.0, st.RemainingUSD, 0, "remaining never goes negative")
	assert.Equal(t, "monthly budget used up: $42.00 of $30.00 spent this month", (&BudgetError{Status: st}).Error())
}

// budgetClient is a fake client with a usage log holding spentToday.
func budgetClient(t *testing.T, s *bqfake.Server, b Budget, spentToday float64) *Client {
	t.Helper()
	c := fakeClient(t, s)
	c.Settings.Budget = b
	c.Usage = &UsageLog{Dir: t.TempDir()}
	if spentToday > 0 {
		require.NoError(t, c.Usage.Append(UsageRecord{Time: time.Now().Unix(), CostUSD: spentToday}))
	}

	return c
}

func TestRunRefusesWhenBudgetUsedUp(t *testing.T) {
	t.Parallel()
	s := bqfake.New(t)
	c := budgetClient(t, s, Budget{DailyUSD: 1}, 1.5)

	_, err := c.Run(t.Context(), QueryOptions{SQL: "SELECT 1", MaxCostUSD: 1, PricePerTiB: testPrice})
	require.Error(t, err)
	assert.Equal(t, errs.KindBudget, errs.Classify(err).Kind)
	assert.Equal(t, 8, errs.Classify(err).ExitCode())
	assert.Empty(t, s.Jobs(), "BigQuery is never contacted")
}

func TestRunCapsJobAtRemainingBudget(t *testing.T) {
	t.Parallel()
	s := bqfake.New(t)
	s.SetQuery(bqfake.Query{Schema: observationSchema, Rows: observationRows()})
	c := budgetClient(t, s, Budget{DailyUSD: 1}, 0.75)

	_, err := c.Run(t.Context(), QueryOptions{SQL: "SELECT 1", MaxCostUSD: 1, PricePerTiB: testPrice})
	require.NoError(t, err)
	assert.Equal(t, maxBytesBilled(0.25, testPrice), s.LastJob().Configuration.Query.MaximumBytesBilled, "the remaining $0.25, not --max-cost")

	_, err = c.Run(t.Context(), QueryOptions{SQL: "SELECT 1", MaxCostUSD: 0.1, PricePerTiB: testPrice})
	require.NoError(t, err)
	assert.Equal(t, maxBytesBilled(0.1, testPrice), s.LastJob().Configuration.Query.MaximumBytesBilled, "--max-cost when it is smaller")

	_, err = c.Run(t.Context(), QueryOptions{SQL: "SELECT 1", PricePerTiB: testPrice})
	require.NoError(t, err)
	assert.Equal(t, maxBytesBilled(0.25, testPrice), s.LastJob().Configuration.Query.MaximumBytesBilled, "a budget caps a query even with --max-cost 0")
}

func TestRunJobStoppedAtBudgetCap(t *testing.T) {
	t.Parallel()
	s := bqfake.New(t)
	s.SetQuery(bqfake.Query{Schema: observationSchema, Err: &bqfake.JobError{Reason: "bytesBilledLimitExceeded", Message: "Query exceeded limit for bytes billed: 10485760. 3221225472 or higher required."}})

	c := budgetClient(t, s, Budget{DailyUSD: 1}, 0.9)
	_, err := c.Run(t.Context(), QueryOptions{SQL: "SELECT 1", MaxCostUSD: 1, PricePerTiB: testPrice})
	var be *BudgetError
	require.True(t, errors.As(err, &be), "%T: %v", err, err)
	assert.True(t, be.Stopped)
	assert.Equal(t, int64(3221225472), be.RequiredBytes)
	e := errs.Classify(err)
	assert.Equal(t, errs.KindBudget, e.Kind)
	assert.Contains(t, e.Hint, "budget set")

	c = budgetClient(t, s, Budget{DailyUSD: 100}, 0)
	_, err = c.Run(t.Context(), QueryOptions{SQL: "SELECT 1", MaxCostUSD: 1, PricePerTiB: testPrice})
	assert.Equal(t, errs.KindCostLimit, errs.Classify(err).Kind, "--max-cost was the cap, so it is a cost limit")
}

func TestRunBudgetFailsClosedWithoutLog(t *testing.T) {
	t.Parallel()
	s := bqfake.New(t)
	c := fakeClient(t, s)
	c.Settings.Budget = Budget{MonthlyUSD: 10}

	_, err := c.Run(t.Context(), QueryOptions{SQL: "SELECT 1", PricePerTiB: testPrice})
	assert.Equal(t, errs.KindBudget, errs.Classify(err).Kind)
	assert.Empty(t, s.Jobs())
}
