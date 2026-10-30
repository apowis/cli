package targetintel

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/vulncheck-oss/cli/pkg/i18n"
	"github.com/vulncheck-oss/cli/pkg/targetintel"
)

// productTextColumns is the compact column set shown in text mode.
var productTextColumns = []string{"ip", "port", "service", "vendor", "product", "version", "confidence", "distro_packaged", "country_code", "asn", "hostname", "timestamp"}

func productCommand() *cobra.Command {
	var f queryFlags
	var vendor, product, groupBy string
	var days, limit int
	var all, dryRun bool

	cmd := &cobra.Command{
		Use:     "product [--vendor <pattern>] [--product <pattern>] [--days <n>] [--group-by <key>]",
		Short:   i18n.C.TargetIntelProductShort,
		Long:    i18n.C.TargetIntelProductLong,
		Example: i18n.C.TargetIntelProductExample,
		Args:    validArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			q := targetintel.ProductQuery{Vendor: vendor, Product: product, LookbackDays: days}
			s, opts, err := f.options(cmd, "")
			if err != nil {
				return err
			}
			if opts.Limit, err = rowLimit(limit, all); err != nil {
				return err
			}
			sql, params, err := s.ObservationsByProduct(q)
			if err != nil {
				return err
			}
			extra := map[string]any{"routine": "observations_by_product", "query": q}
			textColumns := productTextColumns
			if groupBy != "" {
				sql, err = targetintel.GroupBy(sql, groupBy)
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
	cmd.Flags().StringVar(&vendor, "vendor", "", "Vendor pattern (case-insensitive substring; % for an explicit LIKE pattern). Also matched against the product name")
	cmd.Flags().StringVar(&product, "product", "", "Product pattern (case-insensitive substring; % for an explicit LIKE pattern)")
	cmd.Flags().IntVar(&days, "days", 30, "Lookback window in days")
	cmd.Flags().StringVar(&groupBy, "group-by", "", "Roll hosts up by "+strings.Join(targetintel.GroupByKeys(), ", ")+" instead of listing observations")
	cmd.Flags().IntVar(&limit, "limit", 100, "Max rows to return. Does not reduce bytes scanned")
	cmd.Flags().BoolVar(&all, "all", false, "Return all rows (ignores --limit)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print the estimate and exit without running the query")

	return cmd
}
