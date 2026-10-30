package targetintel

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulncheck-oss/cli/internal/errs"
	"github.com/vulncheck-oss/cli/pkg/targetintel"
)

// TestInvalidInputExitsValidation drives the real command tree with bad
// input and checks every case fails as a validation error (exit 2) before a
// client is built. VC_TI_CREDENTIALS points at a missing file, so input that
// slipped past validation would fail at client construction with an auth
// error (exit 3) instead, never reaching BigQuery.
func TestInvalidInputExitsValidation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home)
	t.Setenv(targetintel.EnvCredentials, filepath.Join(home, "missing.json"))
	for _, env := range []string{targetintel.EnvProject, targetintel.EnvLocation, targetintel.EnvViewsDataset, targetintel.EnvDataset, targetintel.EnvMaxCost, targetintel.EnvPricePerTiB} {
		t.Setenv(env, "")
	}

	run := func(args ...string) error {
		cmd := Command()
		cmd.SetArgs(args)
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetIn(strings.NewReader(""))

		return cmd.ExecuteContext(t.Context())
	}

	// Controls: valid input gets past validation to the client, proving
	// the harness tells the two apart.
	for _, args := range [][]string{
		{"host", "1.2.3.4", "--dry-run"},
		{"host", "1.2.3.4", "--min-confidence", "10", "--dry-run"},
		{"host", "10.0.0.5/24", "--dry-run"},
		{"cves", "--cves", "CVE-2024-6387", "--dry-run"},
		{"cves", "--cves", "CVE-2024-6387", "--counts", "--dry-run"},
		{"cves", "--top", "--limit", "10", "--dry-run"},
		{"product", "--vendor", "apache", "--dry-run"},
		{"service", "http", "--title", "login", "--status", "200", "--dry-run"},
		{"service", "http", "--favicon", "-1132923558", "--days", "365", "--dry-run"},
	} {
		err := run(args...)
		require.Error(t, err, args)
		assert.Equal(t, 3, errs.Classify(err).ExitCode(), "%v: %v", args, err)
	}

	tests := [][]string{
		// Arguments and flag parsing, handled by cobra.
		{"bogus"},
		{"tables", "bogus"},
		{"auth", "bogus"},
		{"host"},
		{"host", "1.2.3.4", "5.6.7.8"},
		{"host", "1.2.3.4", "--bogus"},
		{"host", "1.2.3.4", "--days", "abc"},
		{"host", "1.2.3.4", "--max-cost", "abc"},
		{"host", "1.2.3.4", "--timeout", "abc"},
		{"cves", "extra"},
		{"cves", "--cves", "CVE-2024-6387", "--min-confidence", "x"},
		{"cves", "--top", "--min-epss", "abc"},
		{"tables", "list"},
		{"datasets", "list", "extra"},

		// host
		{"host", ""},
		{"host", "999.1.1.1"},
		{"host", "01.2.3.4"},
		{"host", "2001:db8::1"},
		{"host", "10.0.0.0/8"},
		{"host", "10.0.0.0/024"},
		{"host", "::ffff:0.0.0.0/96"},
		{"host", "1.2.3.4", "--days", "0"},
		{"host", "10.0.0.0/24", "--days", "-1"},
		{"host", "10.0.0.0/24", "--limit", "0"},
		{"host", "10.0.0.0/24", "--limit", "-1"},
		{"host", "1.2.3.4", "--min-confidence", "25"},
		{"host", "1.2.3.4", "--min-confidence", "x"},
		{"host", "10.0.0.0/24", "--min-confidence", "30"},

		// Shared query flags
		{"host", "1.2.3.4", "--max-cost", "-1"},
		{"host", "1.2.3.4", "--max-cost", "NaN"},
		{"host", "1.2.3.4", "--max-cost", "Inf"},
		{"host", "1.2.3.4", "--timeout", "-1s"},
		{"host", "1.2.3.4", "--project", "bad project"},
		{"host", "1.2.3.4", "--project", "a`b"},
		{"host", "1.2.3.4", "--location", "no where"},
		{"host", "1.2.3.4", "--dataset", "a.b"},
		{"cves", "--cves", "CVE-2024-6387", "--views-dataset", "x` OR 1=1 --"},

		// cves
		{"cves"},
		{"cves", "--cves", "CVE-24-1"},
		{"cves", "--cves", "CVE-0000-0000"},
		{"cves", "--cves", "CVE-2024-6387", "--days", "0"},
		{"cves", "--cves", "CVE-2024-6387", "--min-confidence", "25"},
		{"cves", "--cves", "CVE-2024-6387", "--group-by", "nope"},
		{"cves", "--cves", "CVE-2024-6387", "--limit", "-3"},
		{"cves", "--cves", "CVE-2024-6387", "--counts", "--group-by", "version"},
		{"cves", "--cves", "CVE-2024-6387", "--counts", "--days", "7"},
		{"cves", "--cves", "CVE-2024-6387", "--counts", "--min-confidence", "40"},
		{"cves", "--cves", "CVE-2024-6387", "--counts", "--limit", "500"},
		{"cves", "--cves", "CVE-2024-6387", "--counts", "--all"},
		{"cves", "--cves", "CVE-2024-6387", "--kev"},
		{"cves", "--cves", "CVE-2024-6387", "--min-epss", "0.5"},
		{"cves", "--top", "--cves", "CVE-2024-6387"},
		{"cves", "--top", "--days", "7"},
		{"cves", "--top", "--min-epss", "2"},
		{"cves", "--top", "--min-epss", "NaN"},

		// product
		{"product"},
		{"product", "--vendor", "  "},
		{"product", "--vendor", "%"},
		{"product", "--product", "_"},
		{"product", "--vendor", "apache", "--days", "0"},
		{"product", "--vendor", "apache", "--group-by", "nope"},
		{"product", "--vendor", "apache", "--limit", "0"},

		// service
		{"service", "bogus"},
		{"service", "http", "extra"},
		{"service", "http"},
		{"service", "http", "--status", "200"},
		{"service", "http", "--title", "%"},
		{"service", "http", "--server", "%_%"},
		{"service", "http", "--title", "x", "--status", "99"},
		{"service", "http", "--title", "x", "--status", "abc"},
		{"service", "http", "--favicon", "0xdeadbeef"},
		{"service", "http", "--favicon", "abc123"},
		{"service", "http", "--snapshot-hash", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{"service", "http", "--snapshot-hash", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"},
		{"service", "http", "--body-hash", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0"},
		{"service", "http", "--title", "x", "--days", "0"},
		{"service", "http", "--title", "x", "--days", "366"},
		{"service", "http", "--title", "x", "--limit", "0"},
		{"service", "http", "--title", "x", "--days", "abc"},

		// query and estimate
		{"query"},
		{"query", "-q", "   "},
		{"query", "-q", "SELECT 1", "--from-file", "x.sql"},
		{"query", "-q", "SELECT 1", "--limit", "-1"},
		{"estimate", "-q", "SELECT 1", "--max-cost", "-1"},

		// tables
		{"tables", "describe", "foo"},
		{"tables", "describe", "a.b.c.d"},
		{"tables", "describe", "a..b"},
		{"tables", "describe", "ds.`tbl`"},
		{"tables", "list", ""},
		{"tables", "list", "proj."},
		{"tables", "list", "ds tbl"},
	}
	for _, args := range tests {
		err := run(args...)
		require.Error(t, err, args)
		c := errs.Classify(err)
		assert.Equal(t, errs.KindValidation, c.Kind, "%v: %v", args, err)
		assert.Equal(t, 2, c.ExitCode(), "%v", args)
	}
}

func TestRowLimit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		limit int
		all   bool
		want  int
		err   bool
	}{
		{limit: 100, want: 100},
		{limit: 1, want: 1},
		{limit: 0, err: true},
		{limit: -1, err: true},
		{limit: -1, all: true, want: 0},
		{limit: 5, all: true, want: 0},
	}
	for _, tt := range tests {
		got, err := rowLimit(tt.limit, tt.all)
		if tt.err {
			require.Error(t, err, tt.limit)
			assert.Equal(t, errs.KindValidation, errs.Classify(err).Kind)

			continue
		}
		require.NoError(t, err)
		assert.Equal(t, tt.want, got)
	}
}

func TestReadSQLRejectsEmpty(t *testing.T) {
	t.Parallel()
	empty := filepath.Join(t.TempDir(), "empty.sql")
	require.NoError(t, os.WriteFile(empty, []byte(" \n\t"), 0600))
	for name, f := range map[string]queryFlags{
		"blank query flag": {sql: "  \n "},
		"blank file":       {fromFile: empty},
		"blank stdin dash": {fromFile: "-"},
	} {
		_, err := f.readSQL(testCmd(t, true), strings.NewReader("   "))
		require.Error(t, err, name)
		assert.Equal(t, errs.KindValidation, errs.Classify(err).Kind, name)
	}
}

func TestOptionsRejectsNegativeTimeout(t *testing.T) {
	t.Parallel()
	f := queryFlags{timeout: -time.Second}
	_, _, err := f.options(testCmd(t, false), "SELECT 1")
	require.Error(t, err)
	assert.Equal(t, errs.KindValidation, errs.Classify(err).Kind)
}
