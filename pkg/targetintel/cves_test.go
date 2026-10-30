package targetintel

import (
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
	require.Error(t, err)
	_, err = NormalizeCVEs(nil)
	require.Error(t, err)
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
	require.Error(t, err)
	_, _, err = s.ObservationsByCVEs(CVEQuery{CVEs: []string{"CVE-2024-6387"}, MinConfidence: 20, LookbackDays: 0})
	require.Error(t, err)
}
