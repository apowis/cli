package targetintel

import (
	"sort"
	"strings"

	"github.com/vulncheck-oss/cli/internal/errs"
)

// groupByColumns maps a --group-by key to the routine columns it groups on.
var groupByColumns = map[string][]string{
	"country": {"country_code", "country"},
	"asn":     {"asn", "as_name"},
	"product": {"vendor", "product"},
	"version": {"vendor", "product", "version"},
}

// GroupByKeys lists the accepted --group-by values.
func GroupByKeys() []string {
	keys := make([]string, 0, len(groupByColumns))
	for k := range groupByColumns {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	return keys
}

// GroupBy wraps a routine call in a host rollup: one row per group with
// COUNT(DISTINCT ip_int) as hosts and COUNT(*) as observations, largest
// first. Routine output has one row per observation, so a plain COUNT(*)
// overstates hosts; this is the counting the routines are meant to be
// summarised with. Leading columns are grouped on ahead of the key, so a
// multi-CVE call can keep its rows apart by matched_cve_id.
func GroupBy(routineSQL, key string, leading ...string) (string, error) {
	cols, ok := groupByColumns[key]
	if !ok {
		return "", errs.Validation("--group-by must be one of %s", strings.Join(GroupByKeys(), ", "))
	}
	cols = append(append([]string{}, leading...), cols...)
	list := strings.Join(cols, ", ")

	return "SELECT " + list + ", COUNT(DISTINCT ip_int) AS hosts, COUNT(*) AS observations" +
		" FROM (" + routineSQL + ")" +
		" GROUP BY " + list +
		" ORDER BY hosts DESC, " + list, nil
}
