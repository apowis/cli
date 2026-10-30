package targetintel

import (
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"testing"
	"time"

	gauth "cloud.google.com/go/auth"
	"cloud.google.com/go/bigquery"
	"cloud.google.com/go/civil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"google.golang.org/api/googleapi"

	"github.com/vulncheck-oss/cli/internal/errs"
)

func TestCost(t *testing.T) {
	t.Parallel()
	assert.InDelta(t, 6.25, cost(tib, 6.25), 1e-9)
	assert.InDelta(t, 0.0, cost(0, 6.25), 1e-9)
	assert.InDelta(t, 14.82, cost(2605959446528, 6.25), 0.01)
}

func TestCostLimitErrorClassified(t *testing.T) {
	t.Parallel()
	e := (&CostLimitError{MaxCostUSD: 1, RequiredBytes: 3 << 30, PricePerTiB: 6.25}).Classified()
	assert.Equal(t, errs.KindCostLimit, e.Kind)
	assert.Equal(t, 7, e.ExitCode())
	assert.Equal(t, "query exceeded max cost $1.00", e.Message)
	assert.Contains(t, e.Hint, "--max-cost 0.02")
	assert.Contains(t, e.Hint, "3.00 GiB billed")

	var cost *CostLimitError
	require.True(t, errors.As(e, &cost), "the cause survives wrapping")
}

func TestCostLimitFromJob(t *testing.T) {
	t.Parallel()
	opts := QueryOptions{MaxCostUSD: 1, PricePerTiB: 6.25}

	berr := &bigquery.Error{Reason: "bytesBilledLimitExceeded", Message: "Query exceeded limit for bytes billed: 10485760. 3221225472 or higher required."}
	err := costLimitFromJob(berr, opts)
	var cost *CostLimitError
	require.True(t, errors.As(err, &cost))
	assert.Equal(t, int64(3221225472), cost.RequiredBytes)

	gerr := &googleapi.Error{Code: 400, Errors: []googleapi.ErrorItem{{Reason: "bytesBilledLimitExceeded", Message: "Query exceeded limit for bytes billed: 10485760."}}}
	err = costLimitFromJob(gerr, opts)
	require.True(t, errors.As(err, &cost))
	assert.Equal(t, int64(0), cost.RequiredBytes, "no required figure in the message")

	other := &bigquery.Error{Reason: "invalidQuery", Message: "syntax error"}
	assert.Equal(t, other, costLimitFromJob(other, opts), "other job errors pass through")
	assert.Equal(t, errs.KindCostLimit, classify(err).(*errs.Error).Kind)
}

func TestClassifyGoogleAPIErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		code int
		kind errs.Kind
		exit int
	}{
		{401, errs.KindAuthInvalid, 3},
		{403, errs.KindAuthInvalid, 3},
		{404, errs.KindNotFound, 4},
		{429, errs.KindRateLimited, 5},
		{400, errs.KindBadRequest, 2},
		{500, errs.KindInternal, 1},
	}
	for _, tt := range tests {
		err := classify(&googleapi.Error{Code: tt.code, Message: "boom"})
		var e *errs.Error
		require.True(t, errors.As(err, &e))
		assert.Equal(t, tt.kind, e.Kind, "HTTP %d", tt.code)
		assert.Equal(t, tt.exit, e.ExitCode(), "HTTP %d", tt.code)
		assert.Equal(t, tt.code, e.HTTPStatus)
		assert.Equal(t, "boom", e.Message)
	}

	assert.Nil(t, classify(nil))
	already := errs.Validation("x")
	assert.Same(t, already, classify(already))
}

func TestToJSONValue(t *testing.T) {
	t.Parallel()
	ts := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	row := map[string]bigquery.Value{
		"ip":      "203.0.113.4",
		"port":    int64(443),
		"seen":    ts,
		"raw":     []byte{0xde, 0xad},
		"num":     big.NewRat(1, 4),
		"day":     civil.Date{Year: 2026, Month: 10, Day: 30},
		"nothing": nil,
		"tags":    []bigquery.Value{"a", "b"},
		"nested":  map[string]bigquery.Value{"k": int64(1)},
	}
	got := toJSONRow(row)
	assert.Equal(t, "203.0.113.4", got["ip"])
	assert.Equal(t, int64(443), got["port"])
	assert.Equal(t, "2026-10-30T12:00:00Z", got["seen"])
	assert.Equal(t, "3q0=", got["raw"])
	assert.Equal(t, "0.250000000", got["num"])
	assert.Equal(t, "2026-10-30", got["day"])
	assert.Nil(t, got["nothing"])
	assert.Equal(t, []any{"a", "b"}, got["tags"])
	assert.Equal(t, map[string]any{"k": int64(1)}, got["nested"])

	assert.Equal(t, "NULL", CellString(nil))
	assert.Equal(t, "443", CellString(int64(443)))
	assert.Equal(t, `[1,2]`, CellString([]any{int64(1), int64(2)}))
	assert.Equal(t, `{"k":1}`, CellString(map[string]any{"k": int64(1)}))
}

func TestFormatHelpers(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "$0.00", FormatCost(0))
	assert.Equal(t, "$0.0030", FormatCost(0.003))
	assert.Equal(t, "$14.82", FormatCost(14.82))
	assert.Equal(t, "500.00 MiB", FormatBytes(500<<20))
	assert.Equal(t, "12 B", FormatBytes(12))
}

func TestClassifyTokenRefreshErrors(t *testing.T) {
	t.Parallel()
	rerr := &oauth2.RetrieveError{ErrorCode: "invalid_grant", ErrorDescription: "reauth related error (invalid_rapt)"}
	err := classify(&url.Error{Op: "Get", URL: "https://example", Err: rerr})
	var e *errs.Error
	require.ErrorAs(t, err, &e)
	assert.Equal(t, errs.KindAuthInvalid, e.Kind)
	assert.Equal(t, 3, e.ExitCode())
	assert.Equal(t, "google credential rejected: invalid_grant (reauth related error (invalid_rapt))", e.Message)
	assert.Contains(t, e.Hint, "auth login")

	aerr := &gauth.Error{Body: []byte(`{"error":"invalid_grant","error_description":"Token has been expired or revoked."}`)}
	err = classify(fmt.Errorf("auth: cannot fetch token: %w", aerr))
	require.ErrorAs(t, err, &e)
	assert.Equal(t, errs.KindAuthInvalid, e.Kind)
	assert.Equal(t, "google credential rejected: invalid_grant (Token has been expired or revoked.)", e.Message)

	// A plain network failure inside url.Error stays unclassified here and
	// falls through to the root classifier.
	plain := &url.Error{Op: "Get", URL: "https://example", Err: errors.New("connection refused")}
	assert.Equal(t, plain, classify(plain))
}

func TestIsSelect(t *testing.T) {
	t.Parallel()
	ok := []string{
		"SELECT 1",
		"  select ip FROM t;",
		"WITH a AS (SELECT 1) SELECT * FROM a",
		"-- note\nSELECT 1",
		"/* block */ SELECT 1 -- trailing ; in a comment",
		"(SELECT 1)",
		"SELECT * FROM `p.d.observations_by_cves`(@cves, 20, 30)",
	}
	for _, sql := range ok {
		assert.True(t, IsSelect(sql), sql)
	}
	bad := []string{
		"",
		"DELETE FROM t",
		"INSERT INTO t SELECT 1",
		"CREATE TABLE t AS SELECT 1",
		"SELECT 1; DELETE FROM t",
		"DECLARE x INT64; SELECT x",
		"CALL p()",
		"/* SELECT */ DROP TABLE t",
	}
	for _, sql := range bad {
		assert.False(t, IsSelect(sql), sql)
	}
}
