package targetintel

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulncheck-oss/cli/internal/bqfake"
	"github.com/vulncheck-oss/cli/internal/errs"
	"github.com/vulncheck-oss/cli/internal/output"
	"github.com/vulncheck-oss/cli/pkg/targetintel"
)

func addCVERoutine(s *bqfake.Server) {
	s.AddRoutine(e2eProject, targetintel.DefaultViewsDataset, targetintel.RoutineCVEs, bqfake.Routine{
		Language:      "SQL",
		Description:   "Hosts observed vulnerable to CVEs",
		Arguments:     []bqfake.Argument{{Name: "cves", Type: "ARRAY<STRING>"}, {Name: "lookback_days", Type: "INT64"}},
		ReturnColumns: []bqfake.Argument{{Name: "ip", Type: "STRING"}, {Name: "port", Type: "INT64"}},
		Body:          "SELECT ip, port FROM somewhere",
	})
}

func TestE2ERoutinesList(t *testing.T) {
	s := fakeBQ(t)
	addCVERoutine(s)
	s.AddRoutine(e2eProject, "other", "f", bqfake.Routine{Type: "SCALAR_FUNCTION", ReturnType: "BOOL"})

	stdout, _, err := runTI(t, output.ModeText, "routines", "list")
	require.NoError(t, err)
	assert.Contains(t, stdout, "1 routine in "+e2eProject+"."+targetintel.DefaultViewsDataset)
	assert.Contains(t, stdout, targetintel.RoutineCVEs)
	assert.Contains(t, stdout, "table function")
	assert.Contains(t, stdout, "cves")

	stdout, _, err = runTI(t, output.ModeJSON, "routines", "list", "other")
	require.NoError(t, err)
	var got []map[string]any
	require.NoError(t, json.Unmarshal([]byte(stdout), &got))
	require.Len(t, got, 1)
	assert.Equal(t, "f", got[0]["routine"])
	assert.Equal(t, "SCALAR_FUNCTION", got[0]["type"])
	assert.Empty(t, s.Jobs(), "metadata only, no query")
}

func TestE2ERoutinesDescribe(t *testing.T) {
	s := fakeBQ(t)
	addCVERoutine(s)

	stdout, _, err := runTI(t, output.ModeText, "routines", "describe", targetintel.RoutineCVEs)
	require.NoError(t, err)
	assert.Contains(t, stdout, "vulncheck target-intel cves")
	assert.Contains(t, stdout, "ARRAY<STRING>")
	assert.Contains(t, stdout, "lookback_days")
	assert.Contains(t, stdout, "Returned column")
	assert.NotContains(t, stdout, "SELECT ip")

	stdout, _, err = runTI(t, output.ModeJSON, "routines", "describe", targetintel.DefaultViewsDataset+"."+targetintel.RoutineCVEs, "--show-sql")
	require.NoError(t, err)
	got := decodeOne(t, stdout)
	assert.Equal(t, "cves", got["command"])
	assert.Equal(t, "SELECT ip, port FROM somewhere", got["body"])
	assert.Len(t, got["arguments"], 2)
	assert.Len(t, got["return_columns"], 2)

	_, _, err = runTI(t, output.ModeText, "routines", "describe", "missing")
	assert.Equal(t, errs.KindNotFound, errs.Classify(err).Kind)
	_, _, err = runTI(t, output.ModeText, "routines", "describe", "bad-ds.fn")
	assert.Equal(t, errs.KindValidation, errs.Classify(err).Kind)
}
