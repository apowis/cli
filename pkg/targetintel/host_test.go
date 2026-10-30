package targetintel

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseHostIP(t *testing.T) {
	t.Parallel()
	got, err := ParseHostIP(" 1.2.3.4 ")
	require.NoError(t, err)
	assert.Equal(t, "1.2.3.4", got)
	got, err = ParseHostIP("::ffff:1.2.3.4")
	require.NoError(t, err)
	assert.Equal(t, "1.2.3.4", got, "an IPv4-mapped address is IPv4")

	for _, bad := range []string{"", "example.com", "1.2.3", "2001:db8::1"} {
		_, err := ParseHostIP(bad)
		require.Error(t, err, bad)
	}
}

func TestHostQueries(t *testing.T) {
	t.Parallel()
	s := Settings{Project: "p", Dataset: "d"}
	sql, params, err := s.HostProfile(HostQuery{IP: "1.2.3.4"})
	require.NoError(t, err)
	assert.Contains(t, sql, "FROM `p.d.host_profile` AS h LEFT JOIN `p.d.ipgeo_snapshot` AS g")
	assert.Contains(t, sql, "WHERE h.ip_int = NET.IPV4_TO_INT64(NET.IP_FROM_STRING(@ip))")
	require.Len(t, params, 1)
	assert.Equal(t, "1.2.3.4", params[0].Value)

	sql, params, err = s.HostFingerprints(HostQuery{IP: "1.2.3.4", LookbackDays: 30})
	require.NoError(t, err)
	assert.Contains(t, sql, "FROM `p.d.fingerprint_current` WHERE ip_int = NET.IPV4_TO_INT64(NET.IP_FROM_STRING(@ip))")
	assert.Contains(t, sql, "INTERVAL @lookback_days DAY")
	require.Len(t, params, 2)
	assert.Equal(t, int64(30), params[1].Value)

	_, _, err = s.HostFingerprints(HostQuery{IP: "1.2.3.4"})
	require.Error(t, err)
	_, _, err = s.HostProfile(HostQuery{IP: "nope"})
	require.Error(t, err)
}

func TestParseHostTarget(t *testing.T) {
	t.Parallel()
	q, err := ParseHostTarget("1.2.3.4")
	require.NoError(t, err)
	assert.Equal(t, HostQuery{IP: "1.2.3.4"}, q)

	q, err = ParseHostTarget("81.82.248.77/24")
	require.NoError(t, err)
	assert.Equal(t, HostQuery{CIDR: "81.82.248.0/24"}, q, "a CIDR is normalised to its network")

	q, err = ParseHostTarget("10.0.0.0/16")
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.0/16", q.CIDR)

	for _, bad := range []string{"10.0.0.0/8", "10.0.0.0/15", "2001:db8::/32", "10.0.0.0/33", "x/24"} {
		_, err := ParseHostTarget(bad)
		require.Error(t, err, bad)
	}
}

func TestHostRange(t *testing.T) {
	t.Parallel()
	s := Settings{Project: "p", Dataset: "d"}
	sql, params, err := s.HostRange(HostQuery{CIDR: "81.82.248.0/24", LookbackDays: 30})
	require.NoError(t, err)
	assert.Contains(t, sql, "FROM `p.d.host_profile` WHERE ip_int BETWEEN @lo AND @hi")
	assert.Contains(t, sql, "FROM `p.d.fingerprint_current` WHERE ip_int BETWEEN @lo AND @hi")
	require.Len(t, params, 3)
	assert.Equal(t, int64(81<<24|82<<16|248<<8), params[0].Value)
	assert.Equal(t, int64(81<<24|82<<16|248<<8|255), params[1].Value)
	assert.Equal(t, int64(30), params[2].Value)

	_, _, err = s.HostRange(HostQuery{CIDR: "81.82.248.0/24"})
	require.Error(t, err)
}
