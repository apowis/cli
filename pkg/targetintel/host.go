package targetintel

import (
	"net"
	"strings"

	"cloud.google.com/go/bigquery"

	"github.com/vulncheck-oss/cli/internal/errs"
)

// HostQuery describes a host lookup.
type HostQuery struct {
	IP           string `json:"ip"`
	LookbackDays int    `json:"lookback_days"`
}

// ParseHostIP validates and normalises the IP a host lookup takes. Only
// IPv4 is supported: the warehouse keys hosts on ip_int, an IPv4 integer.
func ParseHostIP(s string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return "", errs.Validation("%q is not an IP address", s)
	}
	v4 := ip.To4()
	if v4 == nil {
		return "", errs.Validation("%s is IPv6; host lookups support IPv4 only", ip)
	}

	return v4.String(), nil
}

// HostProfileColumns are the columns HostProfile selects, in order.
var HostProfileColumns = []string{
	"ip", "last_seen", "port_count", "identified", "truncated", "protocols", "services",
	"country", "country_code", "asn", "as_name", "as_domain",
}

// HostProfile builds the point lookup of one host in host_profile (ports
// and protocols seen listening, clustered on ip_int) joined to its
// geolocation. One row, or none when the host was not seen.
func (s Settings) HostProfile(q HostQuery) (string, []bigquery.QueryParameter, error) {
	ip, err := ParseHostIP(q.IP)
	if err != nil {
		return "", nil, err
	}
	sql := "SELECT NET.IP_TO_STRING(h.ip) AS ip, h.last_seen, h.port_count, h.identified, h.truncated, h.protocols, h.services," +
		" g.country, g.country_code, g.asn, g.as_name, g.as_domain" +
		" FROM " + s.Table("host_profile") + " AS h" +
		" LEFT JOIN " + s.Table("ipgeo_snapshot") + " AS g ON g.snapshot_hash = h.ipgeo_hash" +
		" WHERE h.ip_int = NET.IPV4_TO_INT64(NET.IP_FROM_STRING(@ip))"

	return sql, []bigquery.QueryParameter{{Name: "ip", Value: ip}}, nil
}

// HostFingerprintColumns are the columns HostFingerprints selects, in order.
var HostFingerprintColumns = []string{
	"port", "protocol", "vendor", "product", "version", "cpe", "confidence", "rule_id", "rule_source", "cves", "hostname", "timestamp",
}

// HostFingerprints builds the point lookup of one host's current
// fingerprints: every product identified in its most recent scan of each
// port within the lookback window. cves holds the rule-annotated CVEs only;
// version-range exposure is what the cves command answers.
func (s Settings) HostFingerprints(q HostQuery) (string, []bigquery.QueryParameter, error) {
	ip, err := ParseHostIP(q.IP)
	if err != nil {
		return "", nil, err
	}
	if q.LookbackDays <= 0 {
		return "", nil, errs.Validation("--days must be at least 1")
	}
	sql := "SELECT " + strings.Join(HostFingerprintColumns, ", ") +
		" FROM " + s.Table("fingerprint_current") +
		" WHERE ip_int = NET.IPV4_TO_INT64(NET.IP_FROM_STRING(@ip))" +
		" AND timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @lookback_days DAY)" +
		" ORDER BY port, vendor, product"
	params := []bigquery.QueryParameter{
		{Name: "ip", Value: ip},
		{Name: "lookback_days", Value: int64(q.LookbackDays)},
	}

	return sql, params, nil
}
