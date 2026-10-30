package targetintel

import (
	"regexp"
	"strings"

	"cloud.google.com/go/bigquery"

	"github.com/vulncheck-oss/cli/internal/errs"
)

// cveID matches a CVE id: a year from 1999, when the first ids were
// assigned, and a sequence number of at least four digits. \d is ASCII-only
// in RE2, so no other script's digits slip through.
var cveID = regexp.MustCompile(`^CVE-(?:1999|2\d{3})-\d{4,}$`)

// CVEQuery describes a call to the observations_by_cves_scored routine.
type CVEQuery struct {
	CVEs          []string `json:"cves"`
	MinConfidence int      `json:"min_confidence"`
	LookbackDays  int      `json:"lookback_days"`
}

// NormalizeCVEs upper-cases, trims, de-duplicates and validates CVE ids.
func NormalizeCVEs(in []string) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, raw := range in {
		for _, part := range strings.Split(raw, ",") {
			id := strings.ToUpper(strings.TrimSpace(part))
			if id == "" {
				continue
			}
			if !cveID.MatchString(id) {
				return nil, errs.Validation("%q is not a CVE id (expected CVE-YYYY-NNNN, year 1999 or later)", part)
			}
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	if len(out) == 0 {
		return nil, errs.Validation("at least one CVE id is required (--cves CVE-2024-6387), or --top for a leaderboard")
	}

	return out, nil
}

// ObservationsByCVEs builds the parameterised call to
// observations_by_cves_scored. The routine scans its inputs once however
// many CVEs are passed, so one call always beats one call per CVE.
func (s Settings) ObservationsByCVEs(q CVEQuery) (string, []bigquery.QueryParameter, error) {
	if q.LookbackDays <= 0 {
		return "", nil, errs.Validation("--days must be at least 1")
	}
	if !ValidMinConfidence(q.MinConfidence) {
		return "", nil, errs.Validation("--min-confidence must be one of 10, 20, 30 or 40")
	}
	sql := "SELECT * FROM " + s.ViewsRoutine("observations_by_cves_scored") + "(@cves, @min_confidence, @lookback_days)"
	params := []bigquery.QueryParameter{
		{Name: "cves", Value: q.CVEs},
		{Name: "min_confidence", Value: int64(q.MinConfidence)},
		{Name: "lookback_days", Value: int64(q.LookbackDays)},
	}

	return sql, params, nil
}

// CVEHostCountsColumns are the columns CVEHostCounts selects, in order.
var CVEHostCountsColumns = []string{
	"cve_id", "hosts", "hosts_confirmed", "hosts_unconfirmed",
	"hosts_40", "hosts_30", "hosts_20", "hosts_10",
	"rule_derived_hosts", "cpe_derived_hosts",
	"epss_score", "epss_percentile",
	"kev_in_catalog", "kev_known_ransomware_use", "kev_vulncheck_exploitation",
	"top_countries",
}

// CVEHostCounts reads the nightly cve_host_counts aggregate for the given
// CVEs: hosts exposing each one over the last 30 days, split by confidence
// tier, with the KEV and EPSS signals and the top countries. The table is
// clustered on cve_id, so this is a point lookup. A CVE no tier reaches has
// no row.
func (s Settings) CVEHostCounts(cves []string) (string, []bigquery.QueryParameter) {
	sql := "SELECT " + strings.Join(CVEHostCountsColumns, ", ") +
		" FROM " + s.Table("cve_host_counts") +
		" WHERE cve_id IN UNNEST(@cves) ORDER BY hosts DESC, cve_id"

	return sql, []bigquery.QueryParameter{{Name: "cves", Value: cves}}
}

// TopCVEs describes a cve_host_counts leaderboard.
type TopCVEs struct {
	KEVOnly bool    `json:"kev_only"`
	MinEPSS float64 `json:"min_epss"`
}

// CVELeaderboard reads cve_host_counts ordered by exposed hosts, most first,
// optionally limited to VulnCheck KEV entries and to an EPSS floor. CVEs
// with only tier-10 hosts are left out, since their hosts column is zero.
// A CVE with no EPSS score yet is only left out when a floor above 0 is set.
func (s Settings) CVELeaderboard(t TopCVEs) (string, []bigquery.QueryParameter, error) {
	// Written as a negated range so NaN, which fails every comparison, is
	// rejected too.
	if !(t.MinEPSS >= 0 && t.MinEPSS <= 1) {
		return "", nil, errs.Validation("--min-epss must be between 0 and 1")
	}
	sql := "SELECT " + strings.Join(CVEHostCountsColumns, ", ") +
		" FROM " + s.Table("cve_host_counts") +
		" WHERE hosts > 0"
	var params []bigquery.QueryParameter
	if t.MinEPSS > 0 {
		sql += " AND epss_score >= @min_epss"
		params = append(params, bigquery.QueryParameter{Name: "min_epss", Value: t.MinEPSS})
	}
	if t.KEVOnly {
		sql += " AND kev_in_catalog"
	}
	sql += " ORDER BY hosts DESC, cve_id"

	return sql, params, nil
}
