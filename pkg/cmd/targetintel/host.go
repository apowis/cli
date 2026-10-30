package targetintel

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vulncheck-oss/cli/internal/errs"
	"github.com/vulncheck-oss/cli/internal/output"
	"github.com/vulncheck-oss/cli/pkg/i18n"
	"github.com/vulncheck-oss/cli/pkg/targetintel"
	"github.com/vulncheck-oss/cli/pkg/ui"
)

// hostJob is the billing record of one of the lookups behind a host payload.
type hostJob struct {
	Name        string  `json:"name"`
	JobID       string  `json:"job_id"`
	BytesBilled int64   `json:"bytes_billed"`
	CostUSD     float64 `json:"cost_usd"`
	CacheHit    bool    `json:"cache_hit"`
}

// hostPayload is the JSON emitted by host.
type hostPayload struct {
	SchemaVersion int                   `json:"schema_version"`
	Query         targetintel.HostQuery `json:"query"`
	Found         bool                  `json:"found"`
	Profile       map[string]any        `json:"profile"`
	Fingerprints  []map[string]any      `json:"fingerprints"`
	CVEs          []targetintel.HostCVE `json:"cves"`
	CVEsBelow     int                   `json:"cves_below_min_confidence"`
	Jobs          []hostJob             `json:"jobs"`
}

// namedLookup is one of the queries behind a single-IP host lookup.
type namedLookup struct {
	name string
	opts targetintel.QueryOptions
}

// rangeTextColumns is the column set of the one-row-per-host inventory.
var rangeTextColumns = []string{"ip", "country_code", "asn", "last_seen", "port_count", "services", "products"}

func hostCommand() *cobra.Command {
	var f queryFlags
	var days, limit, minConfidence int
	var all, dryRun bool

	cmd := &cobra.Command{
		Use:     "host <ipv4|cidr> [--days <n>] [--min-confidence <10|20|30|40>]",
		Short:   i18n.C.TargetIntelHostShort,
		Long:    i18n.C.TargetIntelHostLong,
		Example: i18n.C.TargetIntelHostExample,
		Args:    validArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			q, err := targetintel.ParseHostTarget(args[0])
			if err != nil {
				return err
			}
			q.LookbackDays = days
			if q.CIDR == "" && (cmd.Flags().Changed("limit") || all) {
				return errs.Validation("--limit and --all apply only to a CIDR range; a single IP returns one host")
			}
			if q.CIDR != "" && cmd.Flags().Changed("min-confidence") {
				return errs.Validation("--min-confidence applies only to a single IP; a CIDR range lists no CVEs")
			}
			if q.CIDR == "" {
				if !targetintel.ValidMinConfidence(minConfidence) {
					return errs.Validation("--min-confidence must be one of 10, 20, 30 or 40")
				}
				q.MinConfidence = minConfidence
			}
			s, base, err := f.options(cmd, "")
			if err != nil {
				return err
			}

			if q.CIDR != "" {
				opts := base
				opts.SQL, opts.Params, err = s.HostRange(q)
				if err != nil {
					return err
				}
				if opts.Limit, err = rowLimit(limit, all); err != nil {
					return err
				}
				c, err := newClient(cmd.Context(), s)
				if err != nil {
					return err
				}
				defer func() { _ = c.Close() }()
				if dryRun {
					return renderEstimate(cmd, c, opts)
				}

				return runRange(cmd, c, opts, q)
			}

			profile := base
			profile.SQL, profile.Params, err = s.HostProfile(q)
			if err != nil {
				return err
			}
			fps := base
			fps.SQL, fps.Params, err = s.HostFingerprints(q)
			if err != nil {
				return err
			}
			matches := base
			matches.SQL, matches.Params, err = s.HostCPEMatches(q)
			if err != nil {
				return err
			}
			lookups := []namedLookup{{"host_profile", profile}, {"fingerprint_current", fps}, {"cpe_cve_matches", matches}}

			c, err := newClient(cmd.Context(), s)
			if err != nil {
				return err
			}
			defer func() { _ = c.Close() }()

			if dryRun {
				return renderHostEstimates(cmd, c, lookups)
			}

			results := make([]*targetintel.Result, 0, len(lookups))
			p := hostPayload{SchemaVersion: output.SchemaVersion, Query: q}
			for _, l := range lookups {
				res, err := c.Run(cmd.Context(), l.opts)
				if err != nil {
					return err
				}
				results = append(results, res)
				p.Jobs = append(p.Jobs, hostJob{Name: l.name, JobID: res.JobID, BytesBilled: res.BytesBilled, CostUSD: res.CostUSD, CacheHit: res.CacheHit})
			}
			pr, fr, mr := results[0], results[1], results[2]
			p.Found = len(pr.Rows) > 0 || len(fr.Rows) > 0
			p.Fingerprints = fr.Rows
			p.CVEs, p.CVEsBelow = targetintel.HostCVEs(fr.Rows, mr.Rows, int64(minConfidence))
			if len(pr.Rows) > 0 {
				p.Profile = pr.Rows[0]
			}
			if p.Fingerprints == nil {
				p.Fingerprints = []map[string]any{}
			}

			r := output.FromCmd(cmd)
			if r.IsJSON() {
				return r.JSON(p)
			}

			return renderHost(r, p)
		},
	}
	f.bindCommon(cmd)
	cmd.Flags().IntVar(&days, "days", 30, "Lookback window in days for fingerprints")
	cmd.Flags().IntVar(&minConfidence, "min-confidence", 20, "Minimum CVE confidence tier for a single IP: 40, 30, 20 (default) or 10 (adds versionless product matches)")
	cmd.Flags().IntVar(&limit, "limit", 100, "Max hosts to return for a CIDR range")
	cmd.Flags().BoolVar(&all, "all", false, "Return every host in the range (ignores --limit)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print the estimates and exit without running the lookups")

	return cmd
}

// hostEstimatePayload is the JSON emitted by host --dry-run for a single
// IP: one document covering every lookup.
type hostEstimatePayload struct {
	SchemaVersion int                 `json:"schema_version"`
	Estimates     []namedEstimateJSON `json:"estimates"`
}

type namedEstimateJSON struct {
	Name string `json:"name"`
	estimateResult
}

func renderHostEstimates(cmd *cobra.Command, c *targetintel.Client, lookups []namedLookup) error {
	r := output.FromCmd(cmd)
	p := hostEstimatePayload{SchemaVersion: output.SchemaVersion}
	for _, job := range lookups {
		e, err := estimate(cmd, c, job.opts)
		if err != nil {
			return err
		}
		p.Estimates = append(p.Estimates, namedEstimateJSON{Name: job.name, estimateResult: e})
	}
	if r.IsJSON() {
		return r.JSON(p)
	}
	for i, e := range p.Estimates {
		if i > 0 {
			r.Println("")
		}
		r.Stat("Lookup", e.Name)
		printEstimate(r, e.estimateResult, lookups[i].opts)
	}

	return nil
}

func renderHost(r *output.Renderer, p hostPayload) error {
	var cost float64
	for _, j := range p.Jobs {
		cost += j.CostUSD
	}
	r.Info("Billed %s across %d lookups", targetintel.FormatCost(cost), len(p.Jobs))
	if !p.Found {
		r.Warn("%s was not seen listening on any port in the current scan window.", p.Query.IP)

		return nil
	}

	if p.Profile != nil {
		cell := func(k string) string { return targetintel.CellString(p.Profile[k]) }
		r.Stat("Host", cell("ip"))
		r.Stat("Location", fmt.Sprintf("%s (%s)", cell("country"), cell("country_code")))
		r.Stat("Network", fmt.Sprintf("%s %s (%s)", cell("asn"), cell("as_name"), cell("as_domain")))
		r.Stat("Last seen", cell("last_seen"))
		r.Stat("Ports listening", cell("port_count"))
		r.Stat("Identified", cell("identified"))
		if p.Profile["truncated"] == true {
			r.Warn("The port list is truncated: this host answers on more ports than the profile keeps.")
		}
		r.Println("")
		r.Println(ui.Table([]string{"port", "service", "transport"}, serviceRows(p.Profile["services"])))
	} else {
		r.Warn("%s has no host profile row; showing fingerprints only.", p.Query.IP)
	}

	r.Println("")
	if len(p.Fingerprints) == 0 {
		r.Info("No fingerprints in the last %d days.", p.Query.LookbackDays)

		return nil
	}
	headers := []string{"port", "protocol", "vendor", "product", "version", "cpe", "rule_id"}
	r.Println(rowTable(headers, p.Fingerprints))

	r.Println("")
	if len(p.CVEs) == 0 {
		r.Info("No CVEs at confidence %d or above.%s", p.Query.MinConfidence, belowNote(p))

		return nil
	}
	rows := make([][]string, 0, len(p.CVEs))
	for _, c := range p.CVEs {
		rows = append(rows, []string{fmt.Sprint(c.Port), c.CVEID, fmt.Sprint(c.Confidence), c.Match, c.CPE})
	}
	r.Println(ui.Table([]string{"port", "cve_id", "confidence", "match", "cpe"}, rows))
	r.Info("%d CVEs at confidence %d or above; 40 and 30 are confirmed.%s --json carries every field.", len(p.CVEs), p.Query.MinConfidence, belowNote(p))

	return nil
}

// belowNote names the CVEs hidden by --min-confidence, if any.
func belowNote(p hostPayload) string {
	if p.CVEsBelow == 0 {
		return ""
	}

	return fmt.Sprintf(" %d more below it; lower --min-confidence to see them.", p.CVEsBelow)
}

// serviceRows flattens host_profile.services, an array of {port, service,
// transport} records, into table rows.
func serviceRows(v any) [][]string {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	rows := make([][]string, 0, len(items))
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		rows = append(rows, []string{targetintel.CellString(m["port"]), targetintel.CellString(m["service"]), targetintel.CellString(m["transport"])})
	}

	return rows
}

// runRange renders the one-row-per-host inventory of a CIDR. Arrays are
// joined with commas in text mode; --json keeps them as arrays.
func runRange(cmd *cobra.Command, c *targetintel.Client, opts targetintel.QueryOptions, q targetintel.HostQuery) error {
	r := output.FromCmd(cmd)
	res, err := c.Run(cmd.Context(), opts)
	if err != nil {
		return err
	}
	if r.IsJSON() {
		return r.JSON(resultPayload{SchemaVersion: output.SchemaVersion, Extra: map[string]any{"query": q}, Result: res})
	}
	r.Info("Billed %s (%s%s), %d of %d hosts%s",
		targetintel.FormatCost(res.CostUSD), targetintel.FormatBytes(res.BytesBilled), capNote(opts), res.ReturnedRows, res.TotalRows, truncatedNote(res))
	if res.TotalRows == 0 {
		r.Warn("No host in %s was seen listening on any port in the current scan window.", q.CIDR)

		return nil
	}
	for _, row := range res.Rows {
		row["services"] = joinStrings(row["services"])
		row["products"] = joinStrings(row["products"])
	}

	return renderRows(cmd, res, rangeTextColumns)
}

// joinStrings renders an array of strings as a comma-separated cell.
func joinStrings(v any) any {
	items, ok := v.([]any)
	if !ok {
		return v
	}
	parts := make([]string, 0, len(items))
	for _, it := range items {
		parts = append(parts, targetintel.CellString(it))
	}

	return strings.Join(parts, ", ")
}
