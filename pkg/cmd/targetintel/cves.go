package targetintel

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/vulncheck-oss/cli/internal/errs"
	"github.com/vulncheck-oss/cli/internal/output"
	"github.com/vulncheck-oss/cli/pkg/i18n"
	"github.com/vulncheck-oss/cli/pkg/targetintel"
)

// cvesTextColumns is the compact column set shown in text mode; --json
// carries every column the routine returns.
var cvesTextColumns = []string{"matched_cve_id", "ip", "port", "service", "vendor", "product", "version", "confidence", "country_code", "asn", "kev_in_catalog", "timestamp"}

// countsTextColumns is the compact column set for --counts.
var countsTextColumns = []string{"cve_id", "hosts", "hosts_confirmed", "hosts_40", "hosts_30", "hosts_20", "hosts_10", "kev_in_catalog", "epss_score", "top_countries"}

func cvesCommand() *cobra.Command {
	var f queryFlags
	var cves []string
	var days, minConfidence, limit int
	var all, dryRun, counts, top, kev bool
	var minEPSS float64
	var groupBy string

	cmd := &cobra.Command{
		Use:     "cves (--cves <id>[,<id>...] [--days <n>] [--min-confidence <10|20|30|40>] [--group-by <key> | --counts]) | (--top [--kev] [--min-epss <0-1>])",
		Short:   i18n.C.TargetIntelCvesShort,
		Long:    i18n.C.TargetIntelCvesLong,
		Example: i18n.C.TargetIntelCvesExample,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if counts && groupBy != "" {
				return errs.Validation("--counts and --group-by are mutually exclusive")
			}
			if top && (len(cves) > 0 || counts || groupBy != "") {
				return errs.Validation("--top takes no --cves, --counts or --group-by")
			}
			s, opts := f.options(cmd, "")
			if !all {
				opts.Limit = limit
			}

			if top {
				t := targetintel.TopCVEs{KEVOnly: kev, MinEPSS: minEPSS}
				sql, params, err := s.CVELeaderboard(t)
				if err != nil {
					return err
				}
				opts.SQL, opts.Params = sql, params
				c, err := targetintel.NewClient(cmd.Context(), s)
				if err != nil {
					return err
				}
				defer func() { _ = c.Close() }()
				if dryRun {
					return renderEstimate(cmd, c, opts)
				}

				return runCounts(cmd, c, opts, nil, map[string]any{"top": t})
			}

			ids, err := targetintel.NormalizeCVEs(cves)
			if err != nil {
				return err
			}

			if counts {
				opts.SQL, opts.Params = s.CVEHostCounts(ids)
				c, err := targetintel.NewClient(cmd.Context(), s)
				if err != nil {
					return err
				}
				defer func() { _ = c.Close() }()
				if dryRun {
					return renderEstimate(cmd, c, opts)
				}

				return runCounts(cmd, c, opts, ids, map[string]any{"cves": ids})
			}

			q := targetintel.CVEQuery{CVEs: ids, MinConfidence: minConfidence, LookbackDays: days}
			sql, params, err := s.ObservationsByCVEs(q)
			if err != nil {
				return err
			}
			extra := map[string]any{"routine": "observations_by_cves_scored", "query": q}
			textColumns := cvesTextColumns
			if groupBy != "" {
				var leading []string
				if len(ids) > 1 {
					leading = []string{"matched_cve_id"}
				}
				sql, err = targetintel.GroupBy(sql, groupBy, leading...)
				if err != nil {
					return err
				}
				extra["group_by"] = groupBy
				textColumns = nil
			}
			opts.SQL, opts.Params = sql, params

			c, err := targetintel.NewClient(cmd.Context(), s)
			if err != nil {
				return err
			}
			defer func() { _ = c.Close() }()

			if dryRun {
				return renderEstimate(cmd, c, opts)
			}

			return runAndRender(cmd, c, opts, extra, textColumns)
		},
	}
	f.bindCommon(cmd)
	cmd.Flags().StringSliceVar(&cves, "cves", nil, "CVE ids, comma-separated or repeated (required unless --top)")
	cmd.Flags().IntVar(&days, "days", 30, "Lookback window in days")
	cmd.Flags().IntVar(&minConfidence, "min-confidence", 20, "Minimum confidence tier: 40, 30, 20 (default) or 10 (adds versionless product matches)")
	cmd.Flags().StringVar(&groupBy, "group-by", "", "Roll hosts up by "+strings.Join(targetintel.GroupByKeys(), ", ")+" instead of listing observations")
	cmd.Flags().BoolVar(&counts, "counts", false, "Read the nightly per-CVE host counts (30-day window, split by tier) instead of calling the routine; near-free")
	cmd.Flags().BoolVar(&top, "top", false, "Leaderboard: every CVE by exposed hosts over the last 30 days, most first; near-free")
	cmd.Flags().BoolVar(&kev, "kev", false, "With --top: only CVEs in the VulnCheck KEV catalog")
	cmd.Flags().Float64Var(&minEPSS, "min-epss", 0, "With --top: only CVEs with an EPSS score at or above this (0 to 1)")
	cmd.Flags().IntVar(&limit, "limit", 100, "Max rows to return. Does not reduce bytes scanned")
	cmd.Flags().BoolVar(&all, "all", false, "Return all rows (ignores --limit)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print the estimate and exit without running the query")

	return cmd
}

// runCounts renders the cve_host_counts lookup and names any requested CVE
// that has no row, so an absent CVE is never mistaken for zero hosts.
func runCounts(cmd *cobra.Command, c *targetintel.Client, opts targetintel.QueryOptions, ids []string, query map[string]any) error {
	r := output.FromCmd(cmd)
	res, err := c.Run(cmd.Context(), opts)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, row := range res.Rows {
		if id, ok := row["cve_id"].(string); ok {
			seen[id] = true
		}
	}
	missing := []string{}
	for _, id := range ids {
		if !seen[id] {
			missing = append(missing, id)
		}
	}
	extra := map[string]any{"table": "cve_host_counts", "query": query}
	if ids != nil {
		extra["missing"] = missing
	}
	if r.IsJSON() {
		return r.JSON(resultPayload{SchemaVersion: output.SchemaVersion, Extra: extra, Result: res})
	}
	if ids == nil {
		r.Info("%d of %d CVEs%s", res.ReturnedRows, res.TotalRows, truncatedNote(res))
	}
	for _, row := range res.Rows {
		row["top_countries"] = compactCountries(row["top_countries"])
	}
	if err := renderRows(cmd, res, countsTextColumns); err != nil {
		return err
	}
	if len(missing) > 0 {
		r.Warn("No row for %s: not matched on any host at any tier in the last 30 days, or not in the index.", strings.Join(missing, ", "))
	}
	r.Info("hosts_confirmed is tiers 40 and 30; read it together with hosts_unconfirmed, a distro-packaged product can be structurally unconfirmed.")

	return nil
}

// compactCountries renders top_countries, an array of {country_code, hosts}
// records, as "US 1031, IN 142, ..." for the text table.
func compactCountries(v any) any {
	items, ok := v.([]any)
	if !ok {
		return v
	}
	parts := make([]string, 0, len(items))
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		parts = append(parts, targetintel.CellString(m["country_code"])+" "+targetintel.CellString(m["hosts"]))
	}

	return strings.Join(parts, ", ")
}
