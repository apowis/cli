package targetintel

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/vulncheck-oss/cli/internal/errs"
	"github.com/vulncheck-oss/cli/internal/output"
	"github.com/vulncheck-oss/cli/pkg/i18n"
	"github.com/vulncheck-oss/cli/pkg/targetintel"
	"github.com/vulncheck-oss/cli/pkg/ui"
)

// openClient opens a client that records every billed job in the local
// usage log. A log that cannot be opened or written only warns: tracking
// spend must never stop a query.
func openClient(ctx context.Context, s targetintel.Settings) (*targetintel.Client, error) {
	c, err := targetintel.NewClient(ctx, s)
	if err != nil {
		return nil, err
	}
	attachUsageLog(ctx, c)

	return c, nil
}

func attachUsageLog(ctx context.Context, c *targetintel.Client) {
	r := output.FromContext(ctx)
	warn := func(err error) {
		r.Warn("could not record this query in the usage log: %v", err)
	}
	log, err := usageLog()
	if err != nil {
		warn(err)

		return
	}
	c.Usage = log
	c.OnUsageError = warn
}

// usageLog opens the usage log. It is a variable so tests can point it at a
// temporary directory.
var usageLog = targetintel.DefaultUsageLog

// now is the clock `usage` reads. It is a variable so tests can fix it.
var now = time.Now

// usageCommandName is the command path below target-intel, as recorded in
// the usage log: "query", "host", "service http".
func usageCommandName(cmd *cobra.Command) string {
	path := strings.Fields(cmd.CommandPath())
	for i, p := range path {
		if p == "target-intel" {
			return strings.Join(path[i+1:], " ")
		}
	}

	return cmd.Name()
}

type usageFlags struct {
	today, week, month, year bool
	since, until, by         string
}

// usagePeriod is the resolved reporting window: [From, To), labelled.
type usagePeriod struct {
	From, To time.Time
	Label    string
}

func (f *usageFlags) period(t time.Time) (usagePeriod, error) {
	set := 0
	for _, b := range []bool{f.today, f.week, f.month, f.year, f.since != ""} {
		if b {
			set++
		}
	}
	if set > 1 {
		return usagePeriod{}, errs.Validation("--today, --week, --month, --year and --since pick the period; pass at most one").
			WithHint("run `vulncheck target-intel usage --help` for usage")
	}
	if f.until != "" && f.since == "" {
		return usagePeriod{}, errs.Validation("--until needs --since")
	}
	switch f.by {
	case "", targetintel.ByDay, targetintel.ByWeek, targetintel.ByMonth:
	default:
		return usagePeriod{}, errs.Validation("--by must be day, week or month; got %q", f.by)
	}

	switch {
	case f.week:
		return usagePeriod{From: targetintel.StartOfWeek(t), To: targetintel.StartOfWeek(t).AddDate(0, 0, 7), Label: "This week"}, nil
	case f.month:
		return usagePeriod{From: targetintel.StartOfMonth(t), To: targetintel.StartOfMonth(t).AddDate(0, 1, 0), Label: "This month"}, nil
	case f.year:
		return usagePeriod{From: targetintel.StartOfYear(t), To: targetintel.StartOfYear(t).AddDate(1, 0, 0), Label: "This year"}, nil
	case f.since != "":
		from, err := targetintel.ParseSince(f.since, t)
		if err != nil {
			return usagePeriod{}, errs.Validation("--since: %s", err.Error())
		}
		to := targetintel.StartOfDay(t).AddDate(0, 0, 1)
		if f.until != "" {
			if to, err = targetintel.ParseUntil(f.until, t); err != nil {
				return usagePeriod{}, errs.Validation("--until: %s", err.Error())
			}
		}
		if !from.Before(to) {
			return usagePeriod{}, errs.Validation("--since %s is after --until %s", f.since, f.until)
		}

		return usagePeriod{From: from, To: to}, nil
	default:
		return usagePeriod{From: targetintel.StartOfDay(t), To: targetintel.StartOfDay(t).AddDate(0, 0, 1), Label: "Today"}, nil
	}
}

// dates renders the period as its first and last calendar day, stopping at
// today for a period that runs into the future.
func (p usagePeriod) dates(t time.Time) string {
	last := p.To.AddDate(0, 0, -1)
	if today := targetintel.StartOfDay(t); today.Before(last) {
		last = today
	}
	first := p.From.Format(time.DateOnly)
	if !last.After(p.From) {
		return first
	}

	return first + " to " + last.Format(time.DateOnly)
}

type usagePayload struct {
	SchemaVersion int       `json:"schema_version"`
	From          time.Time `json:"from"`
	To            time.Time `json:"to"`
	targetintel.UsageTotals
	By      string                    `json:"by,omitempty"`
	Buckets []targetintel.UsageBucket `json:"buckets,omitempty"`
}

func usageCommand() *cobra.Command {
	f := &usageFlags{}
	cmd := &cobra.Command{
		Use:     "usage",
		Aliases: []string{"cost", "spend"},
		Short:   i18n.C.TargetIntelUsageShort,
		Long:    i18n.C.TargetIntelUsageLong,
		Example: i18n.C.TargetIntelUsageExample,
		Args:    validArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := output.FromCmd(cmd)
			t := now()
			p, err := f.period(t)
			if err != nil {
				return err
			}
			log, err := usageLog()
			if err != nil {
				return err
			}
			recs, err := log.Records(p.From, p.To)
			if err != nil {
				return err
			}
			payload := usagePayload{
				SchemaVersion: output.SchemaVersion,
				From:          p.From,
				To:            p.To,
				UsageTotals:   targetintel.SumUsage(recs),
				By:            f.by,
			}
			if f.by != "" {
				if payload.Buckets, err = targetintel.BucketUsage(recs, p.From, p.To, t, f.by); err != nil {
					return err
				}
			}
			kept := targetintel.StartOfMonth(t.UTC()).AddDate(0, -targetintel.UsageRetentionMonths, 0)
			if p.From.Before(kept) {
				r.Warn("the usage log keeps %d months; nothing before %s is counted", targetintel.UsageRetentionMonths, kept.In(t.Location()).Format(time.DateOnly))
			}
			if r.IsJSON() {
				return r.JSON(payload)
			}
			renderUsage(r, p, payload, t)

			return nil
		},
	}
	cmd.Flags().BoolVar(&f.today, "today", false, "Since local midnight (the default)")
	cmd.Flags().BoolVar(&f.week, "week", false, "Since Monday")
	cmd.Flags().BoolVar(&f.month, "month", false, "Since the first of the month")
	cmd.Flags().BoolVar(&f.year, "year", false, "Since 1 January")
	cmd.Flags().StringVar(&f.since, "since", "", "Start date (YYYY-MM-DD), or a number of days or weeks back including today (7d, 2w)")
	cmd.Flags().StringVar(&f.until, "until", "", "Last date to include (YYYY-MM-DD); needs --since")
	cmd.Flags().StringVar(&f.by, "by", "", "Break the total down by day, week or month")

	return cmd
}

func renderUsage(r *output.Renderer, p usagePeriod, u usagePayload, t time.Time) {
	period := p.dates(t)
	if p.Label != "" {
		period = p.Label + " (" + period + ")"
	}
	r.Stat("Period", period)
	queries := strconv.Itoa(u.Queries)
	if u.CacheHits > 0 {
		queries += " (" + strconv.Itoa(u.CacheHits) + " from cache)"
	}
	r.Stat("Queries", queries)
	r.Stat("Billed", targetintel.FormatBytes(u.BytesBilled))
	r.Stat("Cost", targetintel.FormatCost(u.CostUSD))
	if len(u.Buckets) == 0 {
		return
	}
	header, layout := "Day", time.DateOnly
	switch u.By {
	case targetintel.ByWeek:
		header = "Week of"
	case targetintel.ByMonth:
		header, layout = "Month", "2006-01"
	}
	rows := make([][]string, 0, len(u.Buckets))
	for _, b := range u.Buckets {
		rows = append(rows, []string{
			b.Start.Format(layout),
			strconv.Itoa(b.Queries),
			targetintel.FormatBytes(b.BytesBilled),
			targetintel.FormatCost(b.CostUSD),
		})
	}
	r.Println(ui.Table([]string{header, "Queries", "Billed", "Cost"}, rows))
}
