package targetintel

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"cloud.google.com/go/bigquery"

	"github.com/vulncheck-oss/cli/internal/errs"
)

// MaxServiceLookbackDays bounds --days for the service commands, so a typo
// cannot ask for every partition of a snapshot table.
const MaxServiceLookbackDays = 365

// FilterKind says how a filter value is validated and matched.
type FilterKind int

const (
	// FilterSubstring is a case-insensitive substring match; a value
	// carrying % is passed through as a LIKE pattern.
	FilterSubstring FilterKind = iota
	// FilterInt is an exact integer between Min and Max.
	FilterInt
	// FilterHex is an exact, lower-cased hex string of HexLen characters.
	FilterHex
	// FilterFavicon matches one of the Favicon columns, chosen by the
	// value's shape.
	FilterFavicon
)

// FaviconColumns names the columns a FilterFavicon value is matched
// against: an optionally negative decimal integer is the Shodan hash, 32
// hex characters MD5 and 64 hex characters SHA-256.
type FaviconColumns struct {
	Shodan, MD5, SHA256 string
}

// Filter is one flag a service command accepts and the column it matches.
type Filter struct {
	Flag   string
	Column string
	Kind   FilterKind
	// Narrows is false for a filter that cannot bound a scan on its own
	// (an HTTP status code matches hundreds of millions of rows). At least
	// one narrowing filter is required.
	Narrows bool
	// Min and Max bound a FilterInt; HexLen is the length of a FilterHex.
	Min, Max int64
	HexLen   int
	Favicon  *FaviconColumns
	// Arg and Usage are the flag's placeholder and help text.
	Arg, Usage string
}

// param is the query parameter name a filter binds to.
func (f Filter) param() string {
	return strings.ReplaceAll(f.Flag, "-", "_")
}

// Protocol describes the snapshot table of one scanned protocol and the
// filters a service command offers over it. Column and table names live
// here and nowhere else; user input only ever reaches BigQuery as a query
// parameter.
type Protocol struct {
	Name          string
	SnapshotTable string
	Filters       []Filter
	// Columns is the SELECT list of the configuration query, in order.
	Columns []string
	// TextColumns is the compact set shown in text mode.
	TextColumns []string
}

// Protocols is the service registry. A snapshot table is one row per
// distinct response, keyed on snapshot_hash and partitioned by
// DATE(last_seen). The HTTP snapshot carries no host; whoever adds dns
// should note its snapshot keeps ip_int.
var Protocols = map[string]Protocol{
	"http": {
		Name:          "http",
		SnapshotTable: "http_snapshot",
		// body, body_b64, headers, robots_txt and security_txt are never
		// read: they multiply the bytes billed tens of times over.
		Filters: []Filter{
			{Flag: "title", Column: "title", Kind: FilterSubstring, Narrows: true, Arg: "<pattern>",
				Usage: "Page title (case-insensitive substring; % for an explicit LIKE pattern)"},
			{Flag: "server", Column: "server", Kind: FilterSubstring, Narrows: true, Arg: "<pattern>",
				Usage: "Server header (case-insensitive substring; % for an explicit LIKE pattern)"},
			{Flag: "status", Column: "status_code", Kind: FilterInt, Min: 100, Max: 599, Arg: "<code>",
				Usage: "HTTP status code (100 to 599); needs another filter beside it"},
			{Flag: "favicon", Kind: FilterFavicon, Narrows: true, Arg: "<hash>",
				Favicon: &FaviconColumns{Shodan: "favicon_shodan_hash", MD5: "favicon_md5", SHA256: "favicon_sha_256"},
				Usage:   "Favicon hash: a Shodan (mmh3) integer, an MD5 (32 hex) or a SHA-256 (64 hex)"},
			{Flag: "body-hash", Column: "body_sha_256", Kind: FilterHex, HexLen: 64, Narrows: true, Arg: "<sha256>",
				Usage: "SHA-256 of the response body (64 hex)"},
			{Flag: "hash", Column: "snapshot_hash", Kind: FilterHex, HexLen: 64, Narrows: true, Arg: "<snapshot_hash>",
				Usage: "Configuration hash (64 hex), as returned in snapshot_hash"},
		},
		Columns: []string{
			"snapshot_hash", "title", "server", "status_code", "content_length",
			"favicon_shodan_hash", "body_sha_256", "first_seen", "last_seen",
		},
		TextColumns: []string{
			"snapshot_hash", "title", "server", "status_code", "content_length",
			"favicon_shodan_hash", "last_seen",
		},
	},
}

// ProtocolNames lists the registered protocols, sorted.
func ProtocolNames() []string {
	names := make([]string, 0, len(Protocols))
	for n := range Protocols {
		names = append(names, n)
	}
	sort.Strings(names)

	return names
}

// ServiceQuery describes a configuration lookup over a protocol's snapshot.
type ServiceQuery struct {
	Protocol string
	// Filters maps a registry flag name to its raw value; an empty value
	// is unset.
	Filters      map[string]string
	LookbackDays int
	// Limit caps the rows in SQL; 0 means no LIMIT clause (--all).
	Limit int
}

var hexOnly = regexp.MustCompile(`^[0-9a-f]+$`)

// ServiceConfigurations builds the parameterised query listing the
// distinct configurations of q.Protocol that match every filter, newest
// last_seen first. The row cap is a LIMIT in the SQL rather than a client
// cut: a broad filter matches tens of millions of configurations, and
// sorting all of them to keep a hundred is what runs out of resources.
func (s Settings) ServiceConfigurations(q ServiceQuery) (string, []bigquery.QueryParameter, error) {
	p, ok := Protocols[q.Protocol]
	if !ok {
		return "", nil, errs.Validation("unknown protocol %q; one of %s", q.Protocol, strings.Join(ProtocolNames(), ", "))
	}
	if q.LookbackDays < 1 || q.LookbackDays > MaxServiceLookbackDays {
		return "", nil, errs.Validation("--days must be between 1 and %d, got %d", MaxServiceLookbackDays, q.LookbackDays)
	}
	if q.Limit < 0 {
		return "", nil, errs.Validation("--limit must be at least 1, got %d; use --all for every row", q.Limit)
	}
	known := map[string]bool{}
	for _, f := range p.Filters {
		known[f.Flag] = true
	}
	for flag, v := range q.Filters {
		if !known[flag] && strings.TrimSpace(v) != "" {
			return "", nil, errs.Validation("%s takes no --%s filter", p.Name, flag)
		}
	}

	where := []string{"last_seen >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @lookback_days DAY)"}
	params := []bigquery.QueryParameter{{Name: "lookback_days", Value: int64(q.LookbackDays)}}
	narrowed := false
	for _, f := range p.Filters {
		raw := strings.TrimSpace(q.Filters[f.Flag])
		if raw == "" {
			continue
		}
		cond, value, err := f.match(raw)
		if err != nil {
			return "", nil, err
		}
		where = append(where, cond)
		params = append(params, bigquery.QueryParameter{Name: f.param(), Value: value})
		narrowed = narrowed || f.Narrows
	}
	if !narrowed {
		return "", nil, errs.Validation("at least one of %s is required", narrowingFlags(p))
	}

	sql := "SELECT " + strings.Join(p.Columns, ", ") +
		" FROM " + s.Table(p.SnapshotTable) +
		" WHERE " + strings.Join(where, " AND ") +
		" ORDER BY last_seen DESC, snapshot_hash"
	if q.Limit > 0 {
		sql += " LIMIT @limit"
		params = append(params, bigquery.QueryParameter{Name: "limit", Value: int64(q.Limit)})
	}

	return sql, params, nil
}

// match validates a trimmed, non-empty value and returns the WHERE
// condition and the parameter value it binds.
func (f Filter) match(raw string) (string, any, error) {
	flag := "--" + f.Flag
	switch f.Kind {
	case FilterSubstring:
		// A pattern of only wildcards matches every row, which is the full
		// scan the narrowing-filter rule exists to prevent.
		if strings.Trim(raw, "%_") == "" {
			return "", nil, errs.Validation("%s %q matches everything; give at least one character besides %% and _", flag, raw)
		}

		return "LOWER(" + f.Column + ") LIKE LOWER(@" + f.param() + ")", likePattern(raw).StringVal, nil
	case FilterInt:
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < f.Min || n > f.Max {
			return "", nil, errs.Validation("%s must be an integer from %d to %d, got %q", flag, f.Min, f.Max, raw)
		}

		return f.Column + " = @" + f.param(), n, nil
	case FilterHex:
		h, err := normalizeHex(flag, raw, f.HexLen)
		if err != nil {
			return "", nil, err
		}

		return f.Column + " = @" + f.param(), h, nil
	case FilterFavicon:
		col, v, err := faviconMatch(f.Favicon, raw)
		if err != nil {
			return "", nil, err
		}

		return col + " = @" + f.param(), v, nil
	}

	return "", nil, errs.Validation("%s has an unknown filter kind", flag)
}

// faviconMatch picks the favicon column by the value's shape. A decimal
// that fits the Shodan hash's 32 bits is read as one before the hex
// lengths are tried, so an MD5 that happens to be all digits still works.
func faviconMatch(c *FaviconColumns, raw string) (string, any, error) {
	if n, err := strconv.ParseInt(raw, 10, 32); err == nil {
		return c.Shodan, n, nil
	}
	h := strings.ToLower(raw)
	if hexOnly.MatchString(h) {
		switch len(h) {
		case 32:
			return c.MD5, h, nil
		case 64:
			return c.SHA256, h, nil
		}
	}

	return "", nil, errs.Validation("--favicon %q is not a Shodan favicon hash (a 32-bit integer), an MD5 (32 hex) or a SHA-256 (64 hex)", raw)
}

// normalizeHex lower-cases a hash and checks it is n hex characters.
func normalizeHex(flag, raw string, n int) (string, error) {
	h := strings.ToLower(raw)
	if len(h) != n || !hexOnly.MatchString(h) {
		return "", errs.Validation("%s must be %d hex characters, got %q", flag, n, raw)
	}

	return h, nil
}

// narrowingFlags renders "--a, --b or --c" for the filters that narrow.
func narrowingFlags(p Protocol) string {
	var flags []string
	for _, f := range p.Filters {
		if f.Narrows {
			flags = append(flags, "--"+f.Flag)
		}
	}
	if len(flags) < 2 {
		return strings.Join(flags, "")
	}

	return strings.Join(flags[:len(flags)-1], ", ") + " or " + flags[len(flags)-1]
}
