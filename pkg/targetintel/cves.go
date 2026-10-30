package targetintel

import (
	"regexp"
	"strings"

	"cloud.google.com/go/bigquery"

	"github.com/vulncheck-oss/cli/internal/errs"
)

var cveID = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

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
				return nil, errs.Validation("%q is not a CVE id (expected CVE-YYYY-NNNN)", part)
			}
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	if len(out) == 0 {
		return nil, errs.Validation("at least one CVE id is required (--cves CVE-2024-6387)")
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
	switch q.MinConfidence {
	case 10, 20, 30, 40:
	default:
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
