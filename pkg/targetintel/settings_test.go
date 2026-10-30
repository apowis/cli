package targetintel

import (
	"math"
	"strings"
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
	t.Setenv(EnvDataset, "")

	s := ResolveSettings(Overrides{})
	assert.Equal(t, DefaultProject, s.Project)
	assert.Equal(t, "default", s.ProjectSource)
	assert.Equal(t, DefaultLocation, s.Location)
	assert.Equal(t, DefaultViewsDataset, s.ViewsDataset)
	assert.Equal(t, DefaultDataset, s.Dataset)
	assert.Equal(t, "`"+DefaultProject+"."+DefaultDataset+".host_profile`", s.Table("host_profile"))
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

	for _, v := range []string{"NaN", "Inf", "-Inf"} {
		t.Setenv(EnvMaxCost, v)
		s = ResolveSettings(Overrides{})
		assert.Equal(t, DefaultMaxCostUSD, s.MaxCostUSD, "a non-finite env var falls back to the default: %s", v)
	}

	t.Setenv(EnvMaxCost, "-1")
	s = ResolveSettings(Overrides{})
	assert.Equal(t, -1.0, s.MaxCostUSD, "a negative env var is kept for Validate to reject, not dropped")
	requireValidation(t, s.Validate())
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
		{"", false, TableRef{}, true},
		{"other.", false, TableRef{}, true},
		{".ds", false, TableRef{}, true},
		{"ds.", true, TableRef{}, true},
		{"a..b", true, TableRef{}, true},
		{"ds tbl", false, TableRef{}, true},
		{"ds-1", false, TableRef{}, true},
		{"ds;drop", false, TableRef{}, true},
		{"Other.ds", false, TableRef{}, true},
		{"other-.ds", false, TableRef{}, true},
		{"other.ds.`tbl`", true, TableRef{}, true},
		{"ds.tbl;drop", true, TableRef{}, true},
		{"ds.tbl$20240101", true, TableRef{}, true},
		{"ds.tbl*", true, TableRef{}, true},
		{"ds_1.tbl-2 v3", true, TableRef{Project: "p", Dataset: "ds_1", Table: "tbl-2 v3"}, false},
		{"ds.t\u00e4ble", true, TableRef{Project: "p", Dataset: "ds", Table: "t\u00e4ble"}, false},
		{" bigquery-public-data.samples.shakespeare ", true, TableRef{Project: "bigquery-public-data", Dataset: "samples", Table: "shakespeare"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			got, err := ParseRef(tt.in, "p", tt.wantTable)
			if tt.wantErr {
				requireValidation(t, err, tt.in)

				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSettingsValidate(t *testing.T) {
	t.Parallel()
	valid := Settings{
		Project: DefaultProject, ProjectSource: "default",
		Location: DefaultLocation, LocationSource: "default",
		ViewsDataset: DefaultViewsDataset, Dataset: DefaultDataset,
		MaxCostUSD: DefaultMaxCostUSD, PricePerTiB: DefaultPricePerTiB,
	}
	require.NoError(t, valid.Validate())

	tests := []struct {
		name   string
		mutate func(*Settings)
		err    string
	}{
		{"zero cost cap disables it", func(s *Settings) { s.MaxCostUSD = 0 }, ""},
		{"multi-region location", func(s *Settings) { s.Location = "US" }, ""},
		{"public project", func(s *Settings) { s.Project = "bigquery-public-data" }, ""},
		{"domain-scoped project", func(s *Settings) { s.Project = "example.com:my-project" }, ""},

		{"negative cost cap", func(s *Settings) { s.MaxCostUSD = -1 }, "--max-cost"},
		{"NaN cost cap", func(s *Settings) { s.MaxCostUSD = math.NaN() }, "--max-cost"},
		{"infinite cost cap", func(s *Settings) { s.MaxCostUSD = math.Inf(1) }, "--max-cost"},
		{"zero price", func(s *Settings) { s.PricePerTiB = 0 }, EnvPricePerTiB},
		{"infinite price", func(s *Settings) { s.PricePerTiB = math.Inf(1) }, EnvPricePerTiB},
		{"project with a space", func(s *Settings) { s.Project = "bad project" }, "project"},
		{"project with a backtick", func(s *Settings) { s.Project = "p`x" }, "project"},
		{"project with a dot", func(s *Settings) { s.Project = "a.b" }, "project"},
		{"uppercase project", func(s *Settings) { s.Project = "Viewport-473910" }, "project"},
		{"project ending in a hyphen", func(s *Settings) { s.Project = "viewport-" }, "project"},
		{"empty project", func(s *Settings) { s.Project = "" }, "project"},
		{"location with a space", func(s *Settings) { s.Location = "nowhere land" }, "location"},
		{"one-letter location", func(s *Settings) { s.Location = "U" }, "location"},
		{"dataset with a dot", func(s *Settings) { s.Dataset = "a.b" }, "dataset"},
		{"dataset with a hyphen", func(s *Settings) { s.Dataset = "a-b" }, "dataset"},
		{"empty dataset", func(s *Settings) { s.Dataset = "" }, "dataset"},
		{"views dataset injection", func(s *Settings) { s.ViewsDataset = "x` OR 1=1 --" }, "views dataset"},
		{"overlong dataset", func(s *Settings) { s.Dataset = strings.Repeat("a", 1025) }, "dataset"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := valid
			tt.mutate(&s)
			err := s.Validate()
			if tt.err == "" {
				require.NoError(t, err)

				return
			}
			requireValidation(t, err)
			assert.Contains(t, err.Error(), tt.err)
		})
	}
}
