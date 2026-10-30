package targetintel

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulncheck-oss/cli/internal/output"
	"github.com/vulncheck-oss/cli/pkg/targetintel"
)

func testCmd(t *testing.T, interactive bool) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "x"}
	r := output.New(output.Options{Mode: output.ModeText, Interactive: interactive})
	cmd.SetContext(output.WithContext(t.Context(), r))

	return cmd
}

func TestReadSQL(t *testing.T) {
	t.Parallel()

	t.Run("query flag", func(t *testing.T) {
		t.Parallel()
		f := queryFlags{sql: "SELECT 1"}
		got, err := f.readSQL(testCmd(t, true), strings.NewReader(""))
		require.NoError(t, err)
		assert.Equal(t, "SELECT 1", got)
	})

	t.Run("both flags", func(t *testing.T) {
		t.Parallel()
		f := queryFlags{sql: "SELECT 1", fromFile: "x.sql"}
		_, err := f.readSQL(testCmd(t, true), strings.NewReader(""))
		require.Error(t, err)
	})

	t.Run("from file", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "q.sql")
		require.NoError(t, os.WriteFile(path, []byte("SELECT 2"), 0600))
		f := queryFlags{fromFile: path}
		got, err := f.readSQL(testCmd(t, true), strings.NewReader(""))
		require.NoError(t, err)
		assert.Equal(t, "SELECT 2", got)
	})

	t.Run("from stdin dash", func(t *testing.T) {
		t.Parallel()
		f := queryFlags{fromFile: "-"}
		got, err := f.readSQL(testCmd(t, true), strings.NewReader("SELECT 3"))
		require.NoError(t, err)
		assert.Equal(t, "SELECT 3", got)
	})

	t.Run("piped stdin without flags", func(t *testing.T) {
		t.Parallel()
		f := queryFlags{}
		got, err := f.readSQL(testCmd(t, false), strings.NewReader("SELECT 4"))
		require.NoError(t, err)
		assert.Equal(t, "SELECT 4", got)
	})

	t.Run("interactive with nothing", func(t *testing.T) {
		t.Parallel()
		f := queryFlags{}
		_, err := f.readSQL(testCmd(t, true), strings.NewReader("SELECT 5"))
		require.Error(t, err, "must not read a terminal's stdin")
	})
}

func TestResultPayloadFlattensExtra(t *testing.T) {
	t.Parallel()
	p := resultPayload{
		SchemaVersion: 1,
		Result:        &targetintel.Result{JobID: "j", Rows: []map[string]any{}, Schema: []targetintel.Column{}},
		Extra:         map[string]any{"routine": "r"},
	}
	b, err := json.Marshal(p)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	assert.Equal(t, float64(1), m["schema_version"])
	assert.Equal(t, "j", m["job_id"])
	assert.Equal(t, "r", m["routine"])
}

func TestCommandTree(t *testing.T) {
	t.Parallel()
	cmd := Command()
	assert.Contains(t, cmd.Aliases, "ti")
	assert.Equal(t, "true", cmd.Annotations["skipAuthCheck"])
	var names []string
	for _, c := range cmd.Commands() {
		names = append(names, c.Name())
	}
	assert.ElementsMatch(t, []string{"auth", "datasets", "tables", "query", "estimate", "cves"}, names)
}
