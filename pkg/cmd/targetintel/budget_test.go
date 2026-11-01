package targetintel

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulncheck-oss/cli/internal/bqfake"
	"github.com/vulncheck-oss/cli/internal/errs"
	"github.com/vulncheck-oss/cli/internal/output"
	"github.com/vulncheck-oss/cli/pkg/config"
	"github.com/vulncheck-oss/cli/pkg/targetintel"
)

// These tests swap package-level seams, so none may call t.Parallel.

func TestE2EBudgetSetShowClear(t *testing.T) {
	at := time.Date(2026, 11, 4, 15, 0, 0, 0, time.Local)
	fixUsage(t, at, targetintel.UsageRecord{Time: at.Add(-time.Hour).Unix(), CostUSD: 2})
	require.NoError(t, config.SetTargetIntel(config.TargetIntelConfig{Project: "keep-me"}))

	stdout, _, err := runTI(t, output.ModeText, "budget", "show")
	require.NoError(t, err)
	assert.Contains(t, stdout, "No budget set")

	stdout, _, err = runTI(t, output.ModeJSON, "budget", "set", "--daily", "5", "--monthly", "50")
	require.NoError(t, err)
	got := decodeOne(t, stdout)
	assert.InDelta(t, 5, got["daily_budget_usd"], 0)
	assert.Equal(t, "config", got["daily_source"])
	st := got["status"].(map[string]any)
	assert.InDelta(t, 3, st["remaining_usd"], 1e-9)
	assert.Equal(t, "daily", st["binding"])
	saved := config.TargetIntel()
	assert.Equal(t, "keep-me", saved.Project, "setting a budget keeps the other saved settings")
	assert.InDelta(t, 50, saved.MonthlyBudgetUSD, 0)

	stdout, _, err = runTI(t, output.ModeText, "budget", "show")
	require.NoError(t, err)
	assert.Contains(t, stdout, "$2.00 of $5.00 spent")
	assert.Contains(t, stdout, "$2.00 of $50.00 spent")

	stdout, _, err = runTI(t, output.ModeText, "usage")
	require.NoError(t, err)
	assert.Contains(t, stdout, "Budget: $2.00 of $5.00 today, $2.00 of $50.00 this month")

	_, _, err = runTI(t, output.ModeText, "budget", "clear", "--daily")
	require.NoError(t, err)
	assert.InDelta(t, 0, config.TargetIntel().DailyBudgetUSD, 0)
	assert.InDelta(t, 50, config.TargetIntel().MonthlyBudgetUSD, 0, "--daily clears only the daily budget")

	_, _, err = runTI(t, output.ModeText, "budget", "clear")
	require.NoError(t, err)
	assert.Equal(t, config.TargetIntelConfig{Project: "keep-me"}, config.TargetIntel())
}

func TestE2EBudgetSetValidation(t *testing.T) {
	fixUsage(t, time.Now())
	for _, args := range [][]string{
		{},
		{"--daily", "0"},
		{"--daily", "-1"},
		{"--monthly", "NaN"},
		{"--monthly", "abc"},
	} {
		_, _, err := runTI(t, output.ModeText, append([]string{"budget", "set"}, args...)...)
		require.Error(t, err, args)
		assert.Equal(t, errs.KindValidation, errs.Classify(err).Kind, "%v: %v", args, err)
	}
}

func TestE2EBudgetEnvWarnsAndTightens(t *testing.T) {
	fixUsage(t, time.Now())
	t.Setenv(targetintel.EnvDailyBudget, "1")

	stdout, stderr, err := runTI(t, output.ModeJSON, "budget", "set", "--daily", "5")
	require.NoError(t, err)
	assert.Contains(t, stderr, targetintel.EnvDailyBudget)
	got := decodeOne(t, stdout)
	assert.InDelta(t, 1, got["daily_budget_usd"], 0, "the stricter environment budget applies")
	assert.Equal(t, "env", got["daily_source"])
}

func TestE2EQueryRefusedOverBudget(t *testing.T) {
	s := fakeBQ(t)
	s.SetQuery(bqfake.Query{Schema: ipPortSchema, Rows: ipPortRows(1)})
	t.Setenv(targetintel.EnvDailyBudget, "1")
	log, err := targetintel.DefaultUsageLog()
	require.NoError(t, err)
	require.NoError(t, log.Append(targetintel.UsageRecord{Time: time.Now().Unix(), CostUSD: 1.25}))

	_, _, err = runTI(t, output.ModeJSON, "query", "-q", "SELECT 1")
	require.Error(t, err)
	e := errs.Classify(err)
	assert.Equal(t, errs.KindBudget, e.Kind)
	assert.Equal(t, 8, e.ExitCode())
	assert.Contains(t, e.Message, "daily budget used up")
	assert.Empty(t, s.Jobs())

	// Free commands still work.
	_, _, err = runTI(t, output.ModeJSON, "estimate", "-q", "SELECT 1")
	require.NoError(t, err)
	stdout, _, err := runTI(t, output.ModeJSON, "auth", "status")
	require.NoError(t, err)
	assert.InDelta(t, 1, decodeOne(t, stdout)["daily_budget_usd"], 0)
}
