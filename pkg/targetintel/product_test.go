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
	require.Error(t, err, "one filter is required")
	_, _, err = s.ObservationsByProduct(ProductQuery{Vendor: "x", LookbackDays: 0})
	require.Error(t, err)
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
	require.Error(t, err)
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
