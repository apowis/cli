package targetintel

import (
	"testing"

	"cloud.google.com/go/bigquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestObservationsByProduct(t *testing.T) {
	t.Parallel()
	s := Settings{Project: "p", ViewsDataset: "v"}
	sql, params, err := s.ObservationsByProduct(ProductQuery{Vendor: " Citrix ", Product: "net%", LookbackDays: 7})
	require.NoError(t, err)
	assert.Equal(t, "SELECT * FROM `p.v.observations_by_product`(@vendor, @product, @lookback_days)", sql)
	require.Len(t, params, 3)
	assert.Equal(t, bigquery.NullString{StringVal: "%Citrix%", Valid: true}, params[0].Value, "a plain word becomes a substring pattern")
	assert.Equal(t, bigquery.NullString{StringVal: "net%", Valid: true}, params[1].Value, "an explicit pattern is kept")
	assert.Equal(t, int64(7), params[2].Value)

	_, params, err = s.ObservationsByProduct(ProductQuery{Product: "netscaler", LookbackDays: 30})
	require.NoError(t, err)
	assert.Equal(t, bigquery.NullString{}, params[0].Value, "an empty filter is passed as NULL")

	_, _, err = s.ObservationsByProduct(ProductQuery{LookbackDays: 30})
	requireValidation(t, err, "one filter is required")
	assert.ErrorContains(t, err, "at least one of --vendor or --product is required")
	_, _, err = s.ObservationsByProduct(ProductQuery{Vendor: "x", LookbackDays: 0})
	requireValidation(t, err)
	assert.ErrorContains(t, err, "--days must be at least 1")
}

func TestGroupBy(t *testing.T) {
	t.Parallel()
	sql, err := GroupBy("SELECT * FROM r(@a)", "country")
	require.NoError(t, err)
	assert.Equal(t, "SELECT country_code, country, COUNT(DISTINCT ip_int) AS hosts, COUNT(*) AS observations"+
		" FROM (SELECT * FROM r(@a)) GROUP BY country_code, country ORDER BY hosts DESC, country_code, country", sql)

	sql, err = GroupBy("SELECT * FROM r(@a)", "version", "matched_cve_id")
	require.NoError(t, err)
	assert.Contains(t, sql, "SELECT matched_cve_id, vendor, product, version, COUNT(DISTINCT ip_int)")
	assert.Contains(t, sql, "GROUP BY matched_cve_id, vendor, product, version")

	_, err = GroupBy("x", "hostname")
	requireValidation(t, err)
	assert.ErrorContains(t, err, "--group-by must be one of asn, country, product, version")
	assert.Equal(t, []string{"asn", "country", "product", "version"}, GroupByKeys())
}

func TestCVEHostCounts(t *testing.T) {
	t.Parallel()
	s := Settings{Project: "p", Dataset: "d"}
	sql, params := s.CVEHostCounts([]string{"CVE-2024-6387"})
	assert.Contains(t, sql, "FROM `p.d.cve_host_counts` WHERE cve_id IN UNNEST(@cves)")
	assert.True(t, len(sql) > 0 && sql[:15] == "SELECT cve_id, ")
	require.Len(t, params, 1)
	assert.Equal(t, []string{"CVE-2024-6387"}, params[0].Value)
}

func TestCVELeaderboard(t *testing.T) {
	t.Parallel()
	s := Settings{Project: "p", Dataset: "d"}
	sql, params, err := s.CVELeaderboard(TopCVEs{KEVOnly: true, MinEPSS: 0.5})
	require.NoError(t, err)
	assert.Contains(t, sql, "FROM `p.d.cve_host_counts` WHERE hosts > 0 AND epss_score >= @min_epss AND kev_in_catalog ORDER BY hosts DESC, cve_id")
	require.Len(t, params, 1)
	assert.Equal(t, 0.5, params[0].Value)

	sql, _, err = s.CVELeaderboard(TopCVEs{})
	require.NoError(t, err)
	assert.NotContains(t, sql, "kev_in_catalog ORDER")

	_, _, err = s.CVELeaderboard(TopCVEs{MinEPSS: 1.5})
	requireValidation(t, err)
	assert.ErrorContains(t, err, "--min-epss must be between 0 and 1")
}

func TestObservationsByProductPatterns(t *testing.T) {
	t.Parallel()
	s := Settings{Project: "p", ViewsDataset: "v"}
	tests := []struct {
		q   ProductQuery
		err string
	}{
		{q: ProductQuery{Vendor: "apache"}},
		{q: ProductQuery{Product: "%net_scaler%"}},
		{q: ProductQuery{Vendor: "a%"}},
		{q: ProductQuery{Vendor: "  ", Product: "x"}},

		{q: ProductQuery{}, err: "at least one of"},
		{q: ProductQuery{Vendor: "  ", Product: "\t"}, err: "at least one of"},
		{q: ProductQuery{Vendor: "%"}, err: `--vendor "%" matches every product`},
		{q: ProductQuery{Vendor: "%%"}, err: "matches every product"},
		{q: ProductQuery{Vendor: "_"}, err: "matches every product"},
		{q: ProductQuery{Vendor: " %_% "}, err: "matches every product"},
		{q: ProductQuery{Vendor: "apache", Product: "%"}, err: `--product "%" matches every product`},
	}
	for _, tt := range tests {
		t.Run(tt.q.Vendor+"|"+tt.q.Product, func(t *testing.T) {
			t.Parallel()
			tt.q.LookbackDays = 30
			_, _, err := s.ObservationsByProduct(tt.q)
			if tt.err != "" {
				requireValidation(t, err)
				assert.Contains(t, err.Error(), tt.err)

				return
			}
			require.NoError(t, err)
		})
	}
}
