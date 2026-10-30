package targetintel

import (
	"math"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeCVEs(t *testing.T) {
	t.Parallel()
	got, err := NormalizeCVEs([]string{"cve-2024-6387, CVE-2024-3400", "CVE-2024-6387", " "})
	require.NoError(t, err)
	assert.Equal(t, []string{"CVE-2024-6387", "CVE-2024-3400"}, got)

	_, err = NormalizeCVEs([]string{"2024-6387"})
	requireValidation(t, err)
	assert.ErrorContains(t, err, `"2024-6387" is not a CVE id`)
	_, err = NormalizeCVEs(nil)
	requireValidation(t, err)
	assert.ErrorContains(t, err, "at least one CVE id is required")
}

func TestObservationsByCVEs(t *testing.T) {
	t.Parallel()
	s := Settings{Project: "p", ViewsDataset: "v"}
	sql, params, err := s.ObservationsByCVEs(CVEQuery{CVEs: []string{"CVE-2024-6387"}, MinConfidence: 20, LookbackDays: 30})
	require.NoError(t, err)
	assert.Equal(t, "SELECT * FROM `p.v.observations_by_cves_scored`(@cves, @min_confidence, @lookback_days)", sql)
	require.Len(t, params, 3)
	assert.Equal(t, []string{"CVE-2024-6387"}, params[0].Value)
	assert.Equal(t, int64(20), params[1].Value)
	assert.Equal(t, int64(30), params[2].Value)

	_, _, err = s.ObservationsByCVEs(CVEQuery{CVEs: []string{"CVE-2024-6387"}, MinConfidence: 25, LookbackDays: 30})
	requireValidation(t, err)
	assert.ErrorContains(t, err, "--min-confidence must be one of 10, 20, 30 or 40")
	_, _, err = s.ObservationsByCVEs(CVEQuery{CVEs: []string{"CVE-2024-6387"}, MinConfidence: 20, LookbackDays: 0})
	requireValidation(t, err)
	assert.ErrorContains(t, err, "--days must be at least 1")
}

func TestNormalizeCVEsInputs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   []string
		want []string
		err  string
	}{
		{in: []string{"CVE-1999-0001"}, want: []string{"CVE-1999-0001"}},
		{in: []string{"CVE-2024-6387"}, want: []string{"CVE-2024-6387"}},
		{in: []string{"cve-2024-6387"}, want: []string{"CVE-2024-6387"}},
		{in: []string{"CVE-2021-1234567"}, want: []string{"CVE-2021-1234567"}},
		{in: []string{" CVE-2024-6387 ,, CVE-2024-3400"}, want: []string{"CVE-2024-6387", "CVE-2024-3400"}},

		{in: nil, err: "at least one CVE id"},
		{in: []string{""}, err: "at least one CVE id"},
		{in: []string{" , "}, err: "at least one CVE id"},
		{in: []string{"CVE-24-1"}, err: "not a CVE id"},
		{in: []string{"CVE-2024-123"}, err: "not a CVE id"},
		{in: []string{"CVE-0000-0000"}, err: "not a CVE id"},
		{in: []string{"CVE-1998-0001"}, err: "not a CVE id"},
		{in: []string{"CVE-20245-0001"}, err: "not a CVE id"},
		{in: []string{"CVE-2024-6387x"}, err: "not a CVE id"},
		{in: []string{"CVE-2024-6387;DROP"}, err: "not a CVE id"},
		{in: []string{"CVE_2024_6387"}, err: "not a CVE id"},
		{in: []string{"CVE-2024-6387 CVE-2024-3400"}, err: "not a CVE id"},
		{in: []string{"CVE-2024-١٢٣٤"}, err: "not a CVE id"},
		{in: []string{"GHSA-xxxx-xxxx-xxxx"}, err: "not a CVE id"},
		{in: []string{"CVE-2024-6387", "bogus"}, err: "not a CVE id"},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.in, "|"), func(t *testing.T) {
			t.Parallel()
			got, err := NormalizeCVEs(tt.in)
			if tt.err != "" {
				requireValidation(t, err)
				assert.Contains(t, err.Error(), tt.err)

				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCVERangeChecks(t *testing.T) {
	t.Parallel()
	s := Settings{Project: "p", ViewsDataset: "v", Dataset: "d"}
	for _, conf := range []int{-1, 0, 5, 25, 50} {
		_, _, err := s.ObservationsByCVEs(CVEQuery{CVEs: []string{"CVE-2024-6387"}, MinConfidence: conf, LookbackDays: 30})
		requireValidation(t, err, conf)
	}
	for _, days := range []int{-1, 0} {
		_, _, err := s.ObservationsByCVEs(CVEQuery{CVEs: []string{"CVE-2024-6387"}, MinConfidence: 20, LookbackDays: days})
		requireValidation(t, err, days)
	}
	for _, epss := range []float64{0, 0.5, 1} {
		_, _, err := s.CVELeaderboard(TopCVEs{MinEPSS: epss})
		require.NoError(t, err, epss)
	}
	sql, params, err := s.CVELeaderboard(TopCVEs{})
	require.NoError(t, err)
	assert.NotContains(t, sql, "@min_epss", "no EPSS floor must keep CVEs with a NULL score")
	assert.Empty(t, params)
	sql, params, err = s.CVELeaderboard(TopCVEs{MinEPSS: 0.5})
	require.NoError(t, err)
	assert.Contains(t, sql, "epss_score >= @min_epss")
	assert.Len(t, params, 1)
	for _, epss := range []float64{-0.1, 1.01, math.NaN(), math.Inf(1), math.Inf(-1)} {
		_, _, err := s.CVELeaderboard(TopCVEs{MinEPSS: epss})
		requireValidation(t, err, epss)
	}
}
