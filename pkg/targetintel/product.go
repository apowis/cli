package targetintel

import (
	"strings"

	"cloud.google.com/go/bigquery"

	"github.com/vulncheck-oss/cli/internal/errs"
)

// ProductQuery describes a call to the observations_by_product routine.
type ProductQuery struct {
	Vendor       string `json:"vendor,omitempty"`
	Product      string `json:"product,omitempty"`
	LookbackDays int    `json:"lookback_days"`
}

// likePattern turns a plain word into the substring LIKE pattern the
// routine expects. A pattern that already carries % is passed through.
func likePattern(s string) bigquery.NullString {
	s = strings.TrimSpace(s)
	if s == "" {
		return bigquery.NullString{}
	}
	if !strings.Contains(s, "%") {
		s = "%" + s + "%"
	}

	return bigquery.NullString{StringVal: s, Valid: true}
}

// ObservationsByProduct builds the parameterised call to
// observations_by_product. At least one of vendor or product is required;
// the routine matches the vendor pattern against the product name too, so
// a product can be passed in either slot.
func (s Settings) ObservationsByProduct(q ProductQuery) (string, []bigquery.QueryParameter, error) {
	if q.LookbackDays <= 0 {
		return "", nil, errs.Validation("--days must be at least 1")
	}
	vendor, product := likePattern(q.Vendor), likePattern(q.Product)
	if !vendor.Valid && !product.Valid {
		return "", nil, errs.Validation("at least one of --vendor or --product is required")
	}
	// A pattern of only wildcards matches every product, which is the full
	// scan the vendor/product requirement exists to prevent.
	for _, f := range [][2]string{{"--vendor", q.Vendor}, {"--product", q.Product}} {
		if raw := strings.TrimSpace(f[1]); raw != "" && strings.Trim(raw, "%_") == "" {
			return "", nil, errs.Validation("%s %q matches every product; give at least one character besides %% and _", f[0], raw)
		}
	}
	sql := "SELECT * FROM " + s.ViewsRoutine(RoutineProduct) + "(@vendor, @product, @lookback_days)"
	params := []bigquery.QueryParameter{
		{Name: "vendor", Value: vendor},
		{Name: "product", Value: product},
		{Name: "lookback_days", Value: int64(q.LookbackDays)},
	}

	return sql, params, nil
}
