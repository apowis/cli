package targetintel

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/vulncheck-oss/cli/internal/errs"
	"github.com/vulncheck-oss/cli/pkg/config"
)

const (
	// EnvDailyBudget and EnvMonthlyBudget set a spending budget in USD for
	// the local day and calendar month. They can only tighten a budget saved
	// with `target-intel budget set`, never loosen it.
	EnvDailyBudget   = "VC_TI_DAILY_BUDGET"
	EnvMonthlyBudget = "VC_TI_MONTHLY_BUDGET"
)

// Budget limits what queries may spend, counted from the local usage log.
// A zero limit is no limit.
type Budget struct {
	DailyUSD   float64
	MonthlyUSD float64
	// DailySource and MonthlySource say which source set each limit: "env",
	// "config", or "" when there is none.
	DailySource   string
	MonthlySource string
}

// IsSet reports whether either limit is in force.
func (b Budget) IsSet() bool { return b.DailyUSD > 0 || b.MonthlyUSD > 0 }

// ResolveBudget reads the budget from the environment and the config file.
// When both set a limit the stricter one applies, so an environment
// variable can tighten a saved budget but never raise it. A value that does
// not parse is kept as NaN for Validate to reject: a broken budget must not
// quietly become no budget.
func ResolveBudget() Budget {
	stored := config.TargetIntel()
	var b Budget
	b.DailyUSD, b.DailySource = stricter(os.Getenv(EnvDailyBudget), stored.DailyBudgetUSD)
	b.MonthlyUSD, b.MonthlySource = stricter(os.Getenv(EnvMonthlyBudget), stored.MonthlyBudgetUSD)

	return b
}

func stricter(env string, stored float64) (float64, string) {
	env = strings.TrimSpace(env)
	if env == "" {
		if stored != 0 {
			return stored, "config"
		}

		return 0, ""
	}
	v, err := strconv.ParseFloat(env, 64)
	if err != nil {
		return math.NaN(), "env"
	}
	if v == 0 && stored != 0 {
		// An env var of 0 cannot switch a saved budget off.
		return stored, "config"
	}
	if stored > 0 && stored < v {
		return stored, "config"
	}

	return v, "env"
}

// Validate rejects a limit that is negative, infinite or did not parse.
func (b Budget) Validate() error {
	check := func(v float64, source, env, flag string) error {
		if finite(v) && v >= 0 {
			return nil
		}
		if source == "env" {
			return errs.Validation("%s must be an amount in USD, 0 or more; got %q", env, os.Getenv(env))
		}

		return errs.Validation("the saved %s budget must be an amount in USD, 0 or more; got %v", flag, v).
			WithHint("run `vulncheck target-intel budget set --%s <usd>` or `budget clear`", flag)
	}
	if err := check(b.DailyUSD, b.DailySource, EnvDailyBudget, "daily"); err != nil {
		return err
	}

	return check(b.MonthlyUSD, b.MonthlySource, EnvMonthlyBudget, "monthly")
}

// BudgetStatus is the budget measured against the usage log at one moment.
type BudgetStatus struct {
	DailyUSD          float64 `json:"daily_budget_usd,omitempty"`
	MonthlyUSD        float64 `json:"monthly_budget_usd,omitempty"`
	SpentTodayUSD     float64 `json:"spent_today_usd"`
	SpentThisMonthUSD float64 `json:"spent_this_month_usd"`
	RemainingUSD      float64 `json:"remaining_usd"`
	// Binding is the limit that leaves the least to spend: "daily" or
	// "monthly".
	Binding string    `json:"binding"`
	Resets  time.Time `json:"resets"`
}

// Exceeded reports whether nothing is left to spend.
func (s BudgetStatus) Exceeded() bool { return s.RemainingUSD <= 0 }

// Status measures b against the log as of now. Days and months are those of
// now's location.
func (b Budget) Status(log *UsageLog, now time.Time) (BudgetStatus, error) {
	month := StartOfMonth(now)
	recs, err := log.Records(month, now.Add(time.Second))
	if err != nil {
		return BudgetStatus{}, err
	}
	today := StartOfDay(now)
	st := BudgetStatus{DailyUSD: b.DailyUSD, MonthlyUSD: b.MonthlyUSD, RemainingUSD: math.Inf(1)}
	for _, r := range recs {
		st.SpentThisMonthUSD += r.CostUSD
		if r.Time >= today.Unix() {
			st.SpentTodayUSD += r.CostUSD
		}
	}
	if b.DailyUSD > 0 {
		st.RemainingUSD, st.Binding, st.Resets = b.DailyUSD-st.SpentTodayUSD, "daily", today.AddDate(0, 0, 1)
	}
	if b.MonthlyUSD > 0 {
		if left := b.MonthlyUSD - st.SpentThisMonthUSD; left < st.RemainingUSD {
			st.RemainingUSD, st.Binding, st.Resets = left, "monthly", month.AddDate(0, 1, 0)
		}
	}
	st.RemainingUSD = max(st.RemainingUSD, 0)

	return st, nil
}

// Limit is the binding limit in USD.
func (s BudgetStatus) Limit() float64 {
	if s.Binding == "monthly" {
		return s.MonthlyUSD
	}

	return s.DailyUSD
}

// Spent is what the binding period has spent so far.
func (s BudgetStatus) Spent() float64 {
	if s.Binding == "monthly" {
		return s.SpentThisMonthUSD
	}

	return s.SpentTodayUSD
}

func (s BudgetStatus) period() string {
	if s.Binding == "monthly" {
		return "this month"
	}

	return "today"
}

// BudgetError is returned when the budget is used up before a query starts
// (Stopped false), or when BigQuery stopped a job at the cap the remaining
// budget set (Stopped true). Nothing was billed either way.
type BudgetError struct {
	Status  BudgetStatus
	Stopped bool
	// RequiredBytes is the cap BigQuery reported as sufficient for a stopped
	// job, zero when it did not say.
	RequiredBytes int64
	PricePerTiB   float64
}

func (e *BudgetError) Error() string {
	s := e.Status
	if e.Stopped {
		return fmt.Sprintf("query would go over the %s budget: %s of %s left %s", s.Binding, FormatCost(s.RemainingUSD), FormatCost(s.Limit()), s.period())
	}

	return fmt.Sprintf("%s budget used up: %s of %s spent %s", s.Binding, FormatCost(s.Spent()), FormatCost(s.Limit()), s.period())
}

// Classified maps the error onto the CLI's exit-code contract.
func (e *BudgetError) Classified() *errs.Error {
	hint := "BigQuery was not charged. The budget resets " + e.Status.Resets.Format("Mon 2 Jan 15:04")
	if e.Stopped && e.RequiredBytes > 0 {
		hint += fmt.Sprintf("; this query needs about %s", FormatCost(cost(e.RequiredBytes, e.PricePerTiB)))
	}
	hint += ". Only a person should raise it, with `vulncheck target-intel budget set`"

	return errs.Wrap(errs.KindBudget, e, "%s", e.Error()).WithHint("%s", hint)
}
