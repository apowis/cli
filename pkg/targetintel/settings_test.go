package targetintel

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveSettingsPrecedence(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // no config file
	t.Setenv(EnvProject, "")
	t.Setenv(EnvLocation, "")
	t.Setenv(EnvMaxCost, "")
	t.Setenv(EnvPricePerTiB, "")

	s := ResolveSettings(Overrides{})
	assert.Equal(t, DefaultProject, s.Project)
	assert.Equal(t, "default", s.ProjectSource)
	assert.Equal(t, DefaultLocation, s.Location)
	assert.Equal(t, DefaultViewsDataset, s.ViewsDataset)
	assert.Equal(t, "`"+DefaultProject+"."+DefaultViewsDataset+".observations_by_cves`", s.ViewsRoutine("observations_by_cves"))
	assert.Equal(t, DefaultMaxCostUSD, s.MaxCostUSD)
	assert.Equal(t, DefaultPricePerTiB, s.PricePerTiB)

	t.Setenv(EnvProject, "env-project")
	t.Setenv(EnvMaxCost, "2.5")
	s = ResolveSettings(Overrides{})
	assert.Equal(t, "env-project", s.Project)
	assert.Equal(t, "env", s.ProjectSource)
	assert.Equal(t, 2.5, s.MaxCostUSD)

	zero := 0.0
	s = ResolveSettings(Overrides{Project: "flag-project", MaxCostUSD: &zero})
	assert.Equal(t, "flag-project", s.Project)
	assert.Equal(t, "flag", s.ProjectSource)
	assert.Equal(t, 0.0, s.MaxCostUSD, "an explicit zero disables the limit and beats the env var")

	t.Setenv(EnvMaxCost, "not-a-number")
	s = ResolveSettings(Overrides{})
	assert.Equal(t, DefaultMaxCostUSD, s.MaxCostUSD, "garbage in the env var falls back to the default")
}

func TestParseRef(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in        string
		wantTable bool
		want      TableRef
		wantErr   bool
	}{
		{"ds", false, TableRef{Project: "p", Dataset: "ds"}, false},
		{"other.ds", false, TableRef{Project: "other", Dataset: "ds"}, false},
		{"ds.tbl", true, TableRef{Project: "p", Dataset: "ds", Table: "tbl"}, false},
		{"other.ds.tbl", true, TableRef{Project: "other", Dataset: "ds", Table: "tbl"}, false},
		{"ds", true, TableRef{}, true},
		{"a.b.c.d", true, TableRef{}, true},
		{"a.b.c", false, TableRef{}, true},
		{".tbl", true, TableRef{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			got, err := ParseRef(tt.in, "p", tt.wantTable)
			if tt.wantErr {
				require.Error(t, err)

				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
