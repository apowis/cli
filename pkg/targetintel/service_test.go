package targetintel

import (
	"regexp"
	"strings"
	"testing"

	"cloud.google.com/go/bigquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// paramMap returns the query parameters as name to value.
func paramMap(params []bigquery.QueryParameter) map[string]any {
	out := make(map[string]any, len(params))
	for _, p := range params {
		out[p.Name] = p.Value
	}

	return out
}

func httpQuery(filters map[string]string) ServiceQuery {
	return ServiceQuery{Protocol: "http", Filters: filters, LookbackDays: 30, Limit: 100}
}

func TestServiceConfigurations(t *testing.T) {
	t.Parallel()
	s := Settings{Project: "p", Dataset: "d"}
	sql, params, err := s.ServiceConfigurations(httpQuery(map[string]string{"title": " Login ", "status": "200"}))
	require.NoError(t, err)
	assert.Equal(t, "SELECT snapshot_hash, title, server, status_code, content_length, favicon_shodan_hash, body_sha_256, first_seen, last_seen"+
		" FROM `p.d.http_snapshot`"+
		" WHERE last_seen >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @lookback_days DAY)"+
		" AND LOWER(title) LIKE LOWER(@title) AND status_code = @status"+
		" ORDER BY last_seen DESC, snapshot_hash LIMIT @limit", sql)
	assert.Equal(t, map[string]any{
		"lookback_days": int64(30),
		"title":         "%Login%",
		"status":        int64(200),
		"limit":         int64(100),
	}, paramMap(params))
}

func TestServiceConfigurationsFilterKinds(t *testing.T) {
	t.Parallel()
	s := Settings{Project: "p", Dataset: "d"}
	h64 := strings.Repeat("ab", 32)
	tests := []struct {
		name, flag, value, cond, param string
		want                           any
	}{
		{name: "substring", flag: "server", value: "nginx", cond: "LOWER(server) LIKE LOWER(@server)", param: "server", want: "%nginx%"},
		{name: "explicit pattern", flag: "title", value: "Index of /%", cond: "LOWER(title) LIKE LOWER(@title)", param: "title", want: "Index of /%"},
		{name: "favicon shodan", flag: "favicon", value: "-1132923558", cond: "favicon_shodan_hash = @favicon", param: "favicon", want: int64(-1132923558)},
		{name: "favicon shodan positive", flag: "favicon", value: "377577930", cond: "favicon_shodan_hash = @favicon", param: "favicon", want: int64(377577930)},
		{name: "favicon md5", flag: "favicon", value: "FE97A42735B0EDFFCD1684711BFD5D99", cond: "favicon_md5 = @favicon", param: "favicon", want: "fe97a42735b0edffcd1684711bfd5d99"},
		{name: "favicon md5 all digits", flag: "favicon", value: "12345678901234567890123456789012", cond: "favicon_md5 = @favicon", param: "favicon", want: "12345678901234567890123456789012"},
		{name: "favicon sha256", flag: "favicon", value: h64, cond: "favicon_sha_256 = @favicon", param: "favicon", want: h64},
		{name: "body hash", flag: "body-hash", value: strings.ToUpper(h64), cond: "body_sha_256 = @body_hash", param: "body_hash", want: h64},
		{name: "snapshot hash", flag: "hash", value: " " + h64 + " ", cond: "snapshot_hash = @hash", param: "hash", want: h64},
	}
	for _, tt := range tests {
		sql, params, err := s.ServiceConfigurations(httpQuery(map[string]string{tt.flag: tt.value}))
		require.NoError(t, err, tt.name)
		assert.Contains(t, sql, " AND "+tt.cond+" ORDER BY", tt.name)
		assert.Equal(t, tt.want, paramMap(params)[tt.param], tt.name)
	}
}

func TestServiceConfigurationsLimit(t *testing.T) {
	t.Parallel()
	s := Settings{Project: "p", Dataset: "d"}
	q := httpQuery(map[string]string{"title": "x"})
	q.Limit = 0
	sql, params, err := s.ServiceConfigurations(q)
	require.NoError(t, err)
	assert.NotContains(t, sql, "LIMIT", "--all leaves the LIMIT out")
	assert.True(t, strings.HasSuffix(sql, "ORDER BY last_seen DESC, snapshot_hash"), sql)
	assert.NotContains(t, paramMap(params), "limit")

	q.Limit = 7
	sql, params, err = s.ServiceConfigurations(q)
	require.NoError(t, err)
	assert.True(t, strings.HasSuffix(sql, " LIMIT @limit"), sql)
	assert.Equal(t, int64(7), paramMap(params)["limit"])
}

// TestServiceConfigurationsNeverReadsExpensiveColumns guards the anti-goal:
// whatever the filters, the SQL never names a column or table that bills
// tens of times more than the snapshot identity columns.
func TestServiceConfigurationsNeverReadsExpensiveColumns(t *testing.T) {
	t.Parallel()
	s := Settings{Project: "p", Dataset: "d"}
	expensive := regexp.MustCompile(`\b(body|body_b64|headers|robots_txt|security_txt|http_parsed|timeline\w*)\b`)
	h64 := strings.Repeat("0", 64)
	all := map[string]string{"title": "a", "server": "b", "status": "404", "favicon": "1", "body-hash": h64, "hash": h64}
	for _, q := range []ServiceQuery{
		httpQuery(all),
		{Protocol: "http", Filters: all, LookbackDays: 365},
		httpQuery(map[string]string{"favicon": h64}),
		httpQuery(map[string]string{"favicon": h64[:32]}),
	} {
		sql, _, err := s.ServiceConfigurations(q)
		require.NoError(t, err)
		assert.Empty(t, expensive.FindAllString(sql, -1), sql)
	}
}

func TestServiceConfigurationsRefusals(t *testing.T) {
	t.Parallel()
	s := Settings{Project: "p", Dataset: "d"}
	h64 := strings.Repeat("a", 64)
	tests := []struct {
		name string
		q    ServiceQuery
		msg  string
	}{
		{name: "no filter", q: httpQuery(nil), msg: "at least one of --title, --server, --favicon, --body-hash or --hash is required"},
		{name: "blank filter", q: httpQuery(map[string]string{"title": "  "}), msg: "at least one of"},
		{name: "status alone", q: httpQuery(map[string]string{"status": "200"}), msg: "at least one of"},
		{name: "wildcard title", q: httpQuery(map[string]string{"title": "%%"}), msg: `--title "%%" matches everything`},
		{name: "wildcard server", q: httpQuery(map[string]string{"server": "_"}), msg: "--server"},
		{name: "status low", q: httpQuery(map[string]string{"title": "x", "status": "99"}), msg: "--status must be an integer from 100 to 599"},
		{name: "status high", q: httpQuery(map[string]string{"title": "x", "status": "600"}), msg: "--status"},
		{name: "status text", q: httpQuery(map[string]string{"title": "x", "status": "ok"}), msg: "--status"},
		{name: "favicon garbage", q: httpQuery(map[string]string{"favicon": "0xdeadbeef"}), msg: "--favicon"},
		{name: "favicon too wide", q: httpQuery(map[string]string{"favicon": "4294967296"}), msg: "--favicon"},
		{name: "favicon wrong hex length", q: httpQuery(map[string]string{"favicon": "abcd"}), msg: "--favicon"},
		{name: "hash short", q: httpQuery(map[string]string{"hash": h64[:63]}), msg: "--hash must be 64 hex characters"},
		{name: "hash non-hex", q: httpQuery(map[string]string{"hash": strings.Repeat("g", 64)}), msg: "--hash"},
		{name: "body hash short", q: httpQuery(map[string]string{"body-hash": "abc"}), msg: "--body-hash must be 64 hex characters"},
		{name: "days zero", q: ServiceQuery{Protocol: "http", Filters: map[string]string{"title": "x"}}, msg: "--days must be between 1 and 365"},
		{name: "days over", q: ServiceQuery{Protocol: "http", Filters: map[string]string{"title": "x"}, LookbackDays: 366}, msg: "--days must be between 1 and 365"},
		{name: "negative limit", q: ServiceQuery{Protocol: "http", Filters: map[string]string{"title": "x"}, LookbackDays: 1, Limit: -1}, msg: "--limit"},
		{name: "unknown protocol", q: ServiceQuery{Protocol: "gopher", Filters: map[string]string{"title": "x"}, LookbackDays: 1}, msg: `unknown protocol "gopher"`},
		{name: "unknown filter", q: httpQuery(map[string]string{"title": "x", "banner": "y"}), msg: "http takes no --banner filter"},
	}
	for _, tt := range tests {
		_, _, err := s.ServiceConfigurations(tt.q)
		requireValidation(t, err, tt.name)
		assert.ErrorContains(t, err, tt.msg, tt.name)
	}
}

func TestProtocolRegistry(t *testing.T) {
	t.Parallel()
	assert.Equal(t, []string{"http"}, ProtocolNames())
	for name, p := range Protocols {
		assert.Equal(t, name, p.Name)
		cols := map[string]bool{}
		for _, c := range p.Columns {
			cols[c] = true
		}
		for _, c := range p.TextColumns {
			assert.True(t, cols[c], "%s text column %s is not selected", name, c)
		}
		assert.True(t, cols["snapshot_hash"] && cols["last_seen"], "%s must select the ORDER BY columns", name)
	}
}
