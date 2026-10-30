package targetintel

import (
	"github.com/spf13/cobra"

	"github.com/vulncheck-oss/cli/pkg/i18n"
	"github.com/vulncheck-oss/cli/pkg/targetintel"
)

// cvesTextColumns is the compact column set shown in text mode; --json
// carries every column the routine returns.
var cvesTextColumns = []string{"matched_cve_id", "ip", "port", "service", "vendor", "product", "version", "confidence", "country_code", "asn", "kev_in_catalog", "timestamp"}

func cvesCommand() *cobra.Command {
	var f queryFlags
	var cves []string
	var days, minConfidence, limit int
	var all, dryRun bool

	cmd := &cobra.Command{
		Use:     "cves --cves <id>[,<id>...] [--days <n>] [--min-confidence <10|20|30|40>]",
		Short:   i18n.C.TargetIntelCvesShort,
		Long:    i18n.C.TargetIntelCvesLong,
		Example: i18n.C.TargetIntelCvesExample,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ids, err := targetintel.NormalizeCVEs(cves)
			if err != nil {
				return err
			}
			q := targetintel.CVEQuery{CVEs: ids, MinConfidence: minConfidence, LookbackDays: days}
			s, opts := f.options(cmd, "")
			sql, params, err := s.ObservationsByCVEs(q)
			if err != nil {
				return err
			}
			opts.SQL, opts.Params = sql, params
			if !all {
				opts.Limit = limit
			}

			c, err := targetintel.NewClient(cmd.Context(), s)
			if err != nil {
				return err
			}
			defer func() { _ = c.Close() }()

			if dryRun {
				return renderEstimate(cmd, c, opts)
			}

			return runAndRender(cmd, c, opts, map[string]any{
				"routine": "observations_by_cves_scored",
				"query":   q,
			}, cvesTextColumns)
		},
	}
	f.bindCommon(cmd)
	cmd.Flags().StringSliceVar(&cves, "cves", nil, "CVE ids, comma-separated or repeated (required)")
	_ = cmd.MarkFlagRequired("cves")
	cmd.Flags().IntVar(&days, "days", 30, "Lookback window in days")
	cmd.Flags().IntVar(&minConfidence, "min-confidence", 20, "Minimum confidence tier: 40, 30, 20 (default) or 10 (adds versionless product matches)")
	cmd.Flags().IntVar(&limit, "limit", 100, "Max rows to return. Does not reduce bytes scanned")
	cmd.Flags().BoolVar(&all, "all", false, "Return all rows (ignores --limit)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print the estimate and exit without running the query")

	return cmd
}
