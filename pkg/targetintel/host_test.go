package targetintel

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulncheck-oss/cli/internal/errs"
)

func TestParseHostIP(t *testing.T) {
	t.Parallel()
	got, err := ParseHostIP(" 1.2.3.4 ")
	require.NoError(t, err)
	assert.Equal(t, "1.2.3.4", got)
	got, err = ParseHostIP("::ffff:1.2.3.4")
	require.NoError(t, err)
	assert.Equal(t, "1.2.3.4", got, "an IPv4-mapped address is IPv4")

	for bad, msg := range map[string]string{
		"":            "is required",
		"example.com": "is not an IP address",
		"1.2.3":       "is not an IP address",
		"2001:db8::1": "is IPv6",
	} {
		_, err := ParseHostIP(bad)
		requireValidation(t, err, bad)
		assert.ErrorContains(t, err, msg, bad)
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
	requireValidation(t, err)
	assert.ErrorContains(t, err, "--days must be at least 1")
	_, _, err = s.HostProfile(HostQuery{IP: "nope"})
	requireValidation(t, err)
	assert.ErrorContains(t, err, `"nope" is not an IP address`)
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

	for bad, msg := range map[string]string{
		"10.0.0.0/8":    "wider than /16",
		"10.0.0.0/15":   "wider than /16",
		"2001:db8::/32": "is IPv6",
		"10.0.0.0/33":   "is not a CIDR range",
		"x/24":          "is not a CIDR range",
	} {
		_, err := ParseHostTarget(bad)
		requireValidation(t, err, bad)
		assert.ErrorContains(t, err, msg, bad)
	}
}

func TestHostRange(t *testing.T) {
	t.Parallel()
	s := Settings{Project: "p", Dataset: "d"}
	sql, params, err := s.HostRange(HostQuery{CIDR: "81.82.248.0/24", LookbackDays: 30})
	require.NoError(t, err)
	assert.Contains(t, sql, "FROM `p.d.host_profile` WHERE ip_int BETWEEN @lo AND @hi")
	assert.Contains(t, sql, "FROM `p.d.fingerprint_current` WHERE ip_int BETWEEN @lo AND @hi")
	assert.Contains(t, sql, "COALESCE(sv.service, 'unknown')", "a NULL service must not become a NULL array element")
	require.Len(t, params, 3)
	assert.Equal(t, int64(81<<24|82<<16|248<<8), params[0].Value)
	assert.Equal(t, int64(81<<24|82<<16|248<<8|255), params[1].Value)
	assert.Equal(t, int64(30), params[2].Value)

	_, _, err = s.HostRange(HostQuery{CIDR: "81.82.248.0/24"})
	requireValidation(t, err)
	assert.ErrorContains(t, err, "--days must be at least 1")
}

// requireValidation asserts err is a validation error, the kind that exits 2.
func requireValidation(t *testing.T, err error, msgAndArgs ...any) {
	t.Helper()
	require.Error(t, err, msgAndArgs...)
	var e *errs.Error
	require.ErrorAs(t, err, &e, msgAndArgs...)
	assert.Equal(t, errs.KindValidation, e.Kind, msgAndArgs...)
	assert.Equal(t, 2, e.ExitCode(), msgAndArgs...)
}

func TestParseHostTargetInputs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want HostQuery
		err  string
	}{
		{in: "1.2.3.4", want: HostQuery{IP: "1.2.3.4"}},
		{in: " 1.2.3.4\t", want: HostQuery{IP: "1.2.3.4"}},
		{in: "0.0.0.0", want: HostQuery{IP: "0.0.0.0"}},
		{in: "255.255.255.255", want: HostQuery{IP: "255.255.255.255"}},
		{in: "::ffff:1.2.3.4", want: HostQuery{IP: "1.2.3.4"}},
		{in: "10.0.0.0/16", want: HostQuery{CIDR: "10.0.0.0/16"}},
		{in: "10.0.0.5/24", want: HostQuery{CIDR: "10.0.0.0/24"}},
		{in: "10.255.255.255/16", want: HostQuery{CIDR: "10.255.0.0/16"}},
		{in: "1.2.3.4/32", want: HostQuery{CIDR: "1.2.3.4/32"}},
		{in: "::ffff:10.0.0.0/112", want: HostQuery{CIDR: "10.0.0.0/16"}},
		{in: "::ffff:10.0.0.9/120", want: HostQuery{CIDR: "10.0.0.0/24"}},

		{in: "", err: "required"},
		{in: "   ", err: "required"},
		{in: "garbage", err: "not an IP address"},
		{in: "999.1.1.1", err: "not an IP address"},
		{in: "256.0.0.0", err: "not an IP address"},
		{in: "1.2.3", err: "not an IP address"},
		{in: "1.2.3.4.5", err: "not an IP address"},
		{in: "01.2.3.4", err: "not an IP address"},
		{in: "1.2.3.04", err: "not an IP address"},
		{in: "0x1.2.3.4", err: "not an IP address"},
		{in: "-1.2.3.4", err: "not an IP address"},
		{in: "1.2.3.4%eth0", err: "not an IP address"},
		{in: "1.2.3. 4", err: "not an IP address"},
		{in: "example.com", err: "not an IP address"},
		{in: "::1", err: "IPv6"},
		{in: "2001:db8::1", err: "IPv6"},
		{in: "fe80::1%eth0", err: "IPv6"},
		{in: "2001:db8::/32", err: "IPv6"},
		{in: "::ffff:0:0/80", err: "IPv6"},
		{in: "10.0.0.0/8", err: "wider than /16"},
		{in: "10.0.0.0/15", err: "wider than /16"},
		{in: "0.0.0.0/0", err: "wider than /16"},
		{in: "::ffff:0.0.0.0/96", err: "wider than /16"},
		{in: "::ffff:10.0.0.0/111", err: "wider than /16"},
		{in: "10.0.0.0/33", err: "not a CIDR range"},
		{in: "10.0.0.0/", err: "not a CIDR range"},
		{in: "/24", err: "not a CIDR range"},
		{in: "10.0.0.0/-1", err: "not a CIDR range"},
		{in: "10.0.0.0/+24", err: "not a CIDR range"},
		{in: "10.0.0.0/024", err: "not a CIDR range"},
		{in: "10.0.0.0/24/24", err: "not a CIDR range"},
		{in: "10.0.0.0 /24", err: "not a CIDR range"},
		{in: "x/24", err: "not a CIDR range"},
		{in: "010.0.0.0/24", err: "not a CIDR range"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			got, err := ParseHostTarget(tt.in)
			if tt.err != "" {
				requireValidation(t, err, tt.in)
				assert.Contains(t, err.Error(), tt.err)

				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCIDRBounds(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in     string
		lo, hi int64
	}{
		{"10.0.0.0/16", 10 << 24, 10<<24 | 0xffff},
		{"10.0.0.7/24", 10 << 24, 10<<24 | 0xff},
		{"1.2.3.4/32", 1<<24 | 2<<16 | 3<<8 | 4, 1<<24 | 2<<16 | 3<<8 | 4},
		{"255.255.0.0/16", 0xffff0000, 0xffffffff},
		{"::ffff:10.0.0.0/112", 10 << 24, 10<<24 | 0xffff},
	}
	for _, tt := range tests {
		lo, hi, err := cidrBounds(tt.in)
		require.NoError(t, err, tt.in)
		assert.Equal(t, tt.lo, lo, tt.in)
		assert.Equal(t, tt.hi, hi, tt.in)
	}

	// HostRange is public, so a hand-built query is held to the same width
	// limit as the command line.
	for _, bad := range []string{"", "10.0.0.0/8", "::ffff:0.0.0.0/96", "2001:db8::/120"} {
		_, _, err := Settings{Project: "p", Dataset: "d"}.HostRange(HostQuery{CIDR: bad, LookbackDays: 30})
		requireValidation(t, err, bad)
	}
}
