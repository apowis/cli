package targetintel

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/vulncheck-oss/cli/internal/errs"
	"github.com/vulncheck-oss/cli/internal/output"
	"github.com/vulncheck-oss/cli/pkg/config"
	"github.com/vulncheck-oss/cli/pkg/i18n"
	"github.com/vulncheck-oss/cli/pkg/targetintel"
)

func budgetCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "budget <command>",
		Short:   i18n.C.TargetIntelBudgetShort,
		Long:    i18n.C.TargetIntelBudgetLong,
		Example: i18n.C.TargetIntelBudgetExample,
		Args:    validArgs(cobra.NoArgs),
		RunE:    groupRunE,
	}
	cmd.AddCommand(budgetShowCommand(), budgetSetCommand(), budgetClearCommand())

	return cmd
}

// budgetPayload is the JSON of every budget subcommand: the limits in force,
// where each came from, and spend measured against them.
type budgetPayload struct {
	SchemaVersion int     `json:"schema_version"`
	DailyUSD      float64 `json:"daily_budget_usd"`
	DailySource   string  `json:"daily_source,omitempty"`
	MonthlyUSD    float64 `json:"monthly_budget_usd"`
	MonthlySource string  `json:"monthly_source,omitempty"`
	// Status is omitted when no budget is set.
	Status *targetintel.BudgetStatus `json:"status,omitempty"`
}

// budgetStatus resolves and validates the budget in force and, when there
// is one, measures it against the usage log.
func budgetStatus() (targetintel.Budget, *targetintel.BudgetStatus, error) {
	b := targetintel.ResolveBudget()
	if err := b.Validate(); err != nil {
		return b, nil, err
	}
	if !b.IsSet() {
		return b, nil, nil
	}
	log, err := usageLog()
	if err != nil {
		return b, nil, err
	}
	st, err := b.Status(log, now())
	if err != nil {
		return b, nil, err
	}

	return b, &st, nil
}

func renderBudget(cmd *cobra.Command) error {
	r := output.FromCmd(cmd)
	b, st, err := budgetStatus()
	if err != nil {
		return err
	}
	if r.IsJSON() {
		return r.JSON(budgetPayload{
			SchemaVersion: output.SchemaVersion,
			DailyUSD:      b.DailyUSD, DailySource: b.DailySource,
			MonthlyUSD: b.MonthlyUSD, MonthlySource: b.MonthlySource,
			Status: st,
		})
	}
	if st == nil {
		r.Info("No budget set: each query is capped only by --max-cost")

		return nil
	}
	limit := func(usd, spent float64, source string) string {
		if usd <= 0 {
			return "none"
		}
		s := targetintel.FormatCost(spent) + " of " + targetintel.FormatCost(usd) + " spent"
		if source == "env" {
			s += " (from the environment)"
		}

		return s
	}
	r.Stat("Daily", limit(b.DailyUSD, st.SpentTodayUSD, b.DailySource))
	r.Stat("Monthly", limit(b.MonthlyUSD, st.SpentThisMonthUSD, b.MonthlySource))
	r.Stat("Remaining", targetintel.FormatCost(st.RemainingUSD)+" until "+st.Resets.Format("Mon 2 Jan 15:04"))
	if st.Exceeded() {
		r.Warn("the %s budget is used up: queries are refused until it resets", st.Binding)
	}

	return nil
}

func budgetShowCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: i18n.C.TargetIntelBudgetShowShort,
		Args:  validArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return renderBudget(cmd)
		},
	}
}

func budgetSetCommand() *cobra.Command {
	var daily, monthly float64
	cmd := &cobra.Command{
		Use:   "set",
		Short: i18n.C.TargetIntelBudgetSetShort,
		Args:  validArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			setDaily, setMonthly := cmd.Flags().Changed("daily"), cmd.Flags().Changed("monthly")
			if !setDaily && !setMonthly {
				return errs.Validation("pass --daily, --monthly or both").WithHint("run `%s --help` for usage", cmd.CommandPath())
			}
			for _, v := range []struct {
				set  bool
				name string
				usd  float64
			}{{setDaily, "--daily", daily}, {setMonthly, "--monthly", monthly}} {
				if v.set && !(v.usd > 0 && v.usd <= 1e9) {
					return errs.Validation("%s must be an amount in USD above 0; got %v", v.name, v.usd).
						WithHint("to remove a budget, run `vulncheck target-intel budget clear`")
				}
			}
			ti := config.TargetIntel()
			if setDaily {
				ti.DailyBudgetUSD = daily
			}
			if setMonthly {
				ti.MonthlyBudgetUSD = monthly
			}
			if err := config.SetTargetIntel(ti); err != nil {
				return err
			}
			warnEnvBudget(cmd)

			return renderBudget(cmd)
		},
	}
	cmd.Flags().Float64Var(&daily, "daily", 0, "Most queries may spend per local day, in USD")
	cmd.Flags().Float64Var(&monthly, "monthly", 0, "Most queries may spend per calendar month, in USD")

	return cmd
}

func budgetClearCommand() *cobra.Command {
	var daily, monthly bool
	cmd := &cobra.Command{
		Use:   "clear",
		Short: i18n.C.TargetIntelBudgetClearShort,
		Args:  validArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			both := !daily && !monthly
			ti := config.TargetIntel()
			if daily || both {
				ti.DailyBudgetUSD = 0
			}
			if monthly || both {
				ti.MonthlyBudgetUSD = 0
			}
			if err := config.SetTargetIntel(ti); err != nil {
				return err
			}
			warnEnvBudget(cmd)

			return renderBudget(cmd)
		},
	}
	cmd.Flags().BoolVar(&daily, "daily", false, "Clear only the daily budget")
	cmd.Flags().BoolVar(&monthly, "monthly", false, "Clear only the monthly budget")

	return cmd
}

// warnEnvBudget says when an environment variable still sets a budget, since
// set and clear only change the saved one.
func warnEnvBudget(cmd *cobra.Command) {
	r := output.FromCmd(cmd)
	for _, env := range []string{targetintel.EnvDailyBudget, targetintel.EnvMonthlyBudget} {
		if os.Getenv(env) != "" {
			r.Warn("%s is set and applies too when it is stricter than the saved budget", env)
		}
	}
}
