package targetintel

import (
	"testing"
	"time"

	"cloud.google.com/go/bigquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulncheck-oss/cli/internal/bqfake"
	"github.com/vulncheck-oss/cli/internal/errs"
)

func TestSQLType(t *testing.T) {
	t.Parallel()
	assert.Empty(t, SQLType(nil))
	assert.Equal(t, "INT64", SQLType(&bigquery.StandardSQLDataType{TypeKind: "INT64"}))
	assert.Equal(t, "ARRAY<STRING>", SQLType(&bigquery.StandardSQLDataType{
		TypeKind: "ARRAY", ArrayElementType: &bigquery.StandardSQLDataType{TypeKind: "STRING"},
	}))
	assert.Equal(t, "STRUCT<a INT64, b ARRAY<STRING>>", SQLType(&bigquery.StandardSQLDataType{
		TypeKind: "STRUCT",
		StructType: &bigquery.StandardSQLStructType{Fields: []*bigquery.StandardSQLField{
			{Name: "a", Type: &bigquery.StandardSQLDataType{TypeKind: "INT64"}},
			{Name: "b", Type: &bigquery.StandardSQLDataType{TypeKind: "ARRAY", ArrayElementType: &bigquery.StandardSQLDataType{TypeKind: "STRING"}}},
		}},
	}))
}

func TestParseRoutineRef(t *testing.T) {
	t.Parallel()
	s := Settings{Project: "p", ViewsDataset: "views"}
	cases := map[string]RoutineRef{
		"fn":          {Project: "p", Dataset: "views", Routine: "fn"},
		"other.fn":    {Project: "p", Dataset: "other", Routine: "fn"},
		"proj.ds.fn":  {Project: "proj", Dataset: "ds", Routine: "fn"},
		"  views.fn ": {Project: "p", Dataset: "views", Routine: "fn"},
	}
	for in, want := range cases {
		got, err := ParseRoutineRef(in, s)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}
	for _, bad := range []string{"", "a.b.c.d", "bad-ds.fn", "ds."} {
		_, err := ParseRoutineRef(bad, s)
		assert.Error(t, err, bad)
	}
}

func TestDescribeAndListRoutines(t *testing.T) {
	t.Parallel()
	s := bqfake.New(t)
	mod := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	s.AddRoutine("p", "views", RoutineCVEs, bqfake.Routine{
		Language:      "SQL",
		Description:   "hosts by CVE",
		Arguments:     []bqfake.Argument{{Name: "cves", Type: "ARRAY<STRING>"}, {Name: "min_confidence", Type: "INT64"}},
		ReturnColumns: []bqfake.Argument{{Name: "ip", Type: "STRING"}},
		Body:          "SELECT 1",
		LastModified:  mod,
	})
	s.AddRoutine("p", "views", "helper", bqfake.Routine{Type: "SCALAR_FUNCTION", Language: "SQL", ReturnType: "BOOL"})
	c := fakeClient(t, s)
	c.Settings.ViewsDataset = "views"

	info, err := c.DescribeRoutine(t.Context(), RoutineRef{Project: "p", Dataset: "views", Routine: RoutineCVEs}, false)
	require.NoError(t, err)
	assert.Equal(t, "TABLE_VALUED_FUNCTION", info.Type)
	assert.Equal(t, "cves", info.Command)
	assert.Equal(t, mod, info.LastModified.UTC())
	assert.Equal(t, []RoutineArgument{{Name: "cves", Type: "ARRAY<STRING>"}, {Name: "min_confidence", Type: "INT64"}}, info.Arguments)
	assert.Equal(t, []RoutineArgument{{Name: "ip", Type: "STRING"}}, info.ReturnColumns)
	assert.Empty(t, info.Body, "the body only on request")

	info, err = c.DescribeRoutine(t.Context(), RoutineRef{Project: "p", Dataset: "views", Routine: RoutineCVEs}, true)
	require.NoError(t, err)
	assert.Equal(t, "SELECT 1", info.Body)

	list, err := c.ListRoutines(t.Context(), TableRef{Project: "p", Dataset: "views"})
	require.NoError(t, err)
	require.Len(t, list, 2)
	assert.Equal(t, RoutineCVEs, list[0].Name)
	assert.Equal(t, "cves", list[0].Command)
	assert.Equal(t, "SCALAR_FUNCTION", list[1].Type)
	assert.Empty(t, list[1].Command)

	_, err = c.DescribeRoutine(t.Context(), RoutineRef{Project: "p", Dataset: "views", Routine: "nope"}, false)
	assert.Equal(t, errs.KindNotFound, errs.Classify(err).Kind)

	empty, err := c.ListRoutines(t.Context(), TableRef{Project: "p", Dataset: "empty"})
	require.NoError(t, err)
	assert.Empty(t, empty)
	assert.NotNil(t, empty, "an empty list encodes as [], not null")
}

func TestRoutineKind(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "table function", RoutineKind("TABLE_VALUED_FUNCTION"))
	assert.Equal(t, "procedure", RoutineKind("PROCEDURE"))
	assert.Equal(t, "something_new", RoutineKind("SOMETHING_NEW"))
}
