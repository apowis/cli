package targetintel

import (
	"encoding/binary"
	"net"
	"strings"

	"cloud.google.com/go/bigquery"

	"github.com/vulncheck-oss/cli/internal/errs"
)

// MaxHostPrefix is the shortest prefix a range lookup accepts.
const MaxHostPrefix = 16

// HostQuery describes a host lookup: one IP, or a CIDR range.
type HostQuery struct {
	IP           string `json:"ip,omitempty"`
	CIDR         string `json:"cidr,omitempty"`
	LookbackDays int    `json:"lookback_days"`
}

// ParseHostTarget accepts an IPv4 address or an IPv4 CIDR of /16 or
// longer and returns the query for it. A CIDR is normalised to its
// network address.
func ParseHostTarget(s string) (HostQuery, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		ip, err := ParseHostIP(s)
		if err != nil {
			return HostQuery{}, err
		}

		return HostQuery{IP: ip}, nil
	}
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return HostQuery{}, errs.Validation("%q is not a CIDR range", s)
	}
	if ipnet.IP.To4() == nil {
		return HostQuery{}, errs.Validation("%s is IPv6; host lookups support IPv4 only", s)
	}
	ones, _ := ipnet.Mask.Size()
	if ones < MaxHostPrefix {
		return HostQuery{}, errs.Validation("%s is wider than /%d; narrow the range", s, MaxHostPrefix)
	}

	return HostQuery{CIDR: ipnet.String()}, nil
}

// cidrBounds returns the first and last ip_int of an IPv4 CIDR.
func cidrBounds(cidr string) (int64, int64, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, 0, errs.Validation("%q is not a CIDR range", cidr)
	}
	v4 := ipnet.IP.To4()
	if v4 == nil {
		return 0, 0, errs.Validation("%s is IPv6; host lookups support IPv4 only", cidr)
	}
	lo := int64(binary.BigEndian.Uint32(v4))
	ones, bits := ipnet.Mask.Size()
	hi := lo + int64(1)<<uint(bits-ones) - 1

	return lo, hi, nil
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

// HostRangeColumns are the columns HostRange selects, in order.
var HostRangeColumns = []string{"ip", "country_code", "asn", "as_name", "last_seen", "port_count", "services", "products"}

// HostRange builds the inventory of every host seen listening in a CIDR:
// one row per host with its services (port/transport service) and the
// distinct products identified within the lookback window. Both tables
// are clustered on ip_int, so the range filter prunes to the block; a /16
// bills well under 1 GiB.
func (s Settings) HostRange(q HostQuery) (string, []bigquery.QueryParameter, error) {
	lo, hi, err := cidrBounds(q.CIDR)
	if err != nil {
		return "", nil, err
	}
	if q.LookbackDays <= 0 {
		return "", nil, errs.Validation("--days must be at least 1")
	}
	const label = "TRIM(CONCAT(COALESCE(vendor, ''), ' ', COALESCE(product, ''), ' ', COALESCE(version, '')))"
	sql := "WITH h AS (" +
		" SELECT ip_int, ip, ipgeo_hash, last_seen, port_count, services" +
		" FROM " + s.Table("host_profile") +
		" WHERE ip_int BETWEEN @lo AND @hi" +
		"), f AS (" +
		" SELECT ip_int, ARRAY_AGG(DISTINCT " + label + " ORDER BY " + label + ") AS products" +
		" FROM " + s.Table("fingerprint_current") +
		" WHERE ip_int BETWEEN @lo AND @hi" +
		" AND timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @lookback_days DAY)" +
		" GROUP BY ip_int" +
		") SELECT NET.IP_TO_STRING(h.ip) AS ip, g.country_code, g.asn, g.as_name, h.last_seen, h.port_count," +
		" ARRAY(SELECT CONCAT(CAST(sv.port AS STRING), '/', COALESCE(sv.transport, 'unknown'), ' ', sv.service) FROM UNNEST(h.services) AS sv) AS services," +
		" COALESCE(f.products, []) AS products" +
		" FROM h" +
		" LEFT JOIN " + s.Table("ipgeo_snapshot") + " AS g ON g.snapshot_hash = h.ipgeo_hash" +
		" LEFT JOIN f USING (ip_int)" +
		" ORDER BY h.ip_int"
	params := []bigquery.QueryParameter{
		{Name: "lo", Value: lo},
		{Name: "hi", Value: hi},
		{Name: "lookback_days", Value: int64(q.LookbackDays)},
	}

	return sql, params, nil
}
