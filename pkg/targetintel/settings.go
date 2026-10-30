// Package targetintel talks to the VulnCheck Target Intelligence warehouse in
// BigQuery: credential resolution, a gcloud-style browser login, and a query
// path that dry-runs every statement and refuses to run one whose estimated
// cost exceeds the caller's limit.
package targetintel

import (
	"os"
	"strconv"
	"strings"

	"github.com/vulncheck-oss/cli/pkg/config"
)

const (
	// DefaultProject is the billing project used when nothing else names one.
	DefaultProject = "viewport-473910"
	// DefaultLocation is the BigQuery location both Target Intelligence
	// datasets live in. A query sent to another location fails with "not found".
	DefaultLocation = "europe-west1"
	// DefaultViewsDataset holds the customer-facing routines (observations_by_*).
	DefaultViewsDataset = "anchorbreaker_views_prod"
	// DefaultMaxCostUSD is the per-invocation spend limit.
	DefaultMaxCostUSD = 1.00
	// DefaultPricePerTiB is BigQuery's on-demand analysis price.
	DefaultPricePerTiB = 6.25

	EnvProject      = "VC_TI_PROJECT"
	EnvLocation     = "VC_TI_LOCATION"
	EnvViewsDataset = "VC_TI_VIEWS_DATASET"
	EnvMaxCost      = "VC_TI_MAX_COST"
	EnvPricePerTiB  = "VC_TI_PRICE_PER_TIB"
	// EnvCredentials points at a Google credentials JSON file (service account
	// key or authorized_user) and takes precedence over every other source.
	EnvCredentials = "VC_TI_CREDENTIALS"
)

// Settings is everything a command needs to reach the warehouse. Build it
// with ResolveSettings so precedence lives in one place.
type Settings struct {
	Project      string
	Location     string
	ViewsDataset string
	MaxCostUSD   float64
	PricePerTiB  float64

	// ProjectSource and LocationSource say where each value came from:
	// "flag", "env", "config" or "default".
	ProjectSource  string
	LocationSource string
}

// ViewsRoutine returns the fully qualified name of a routine in the views
// dataset, ready to be called in SQL.
func (s Settings) ViewsRoutine(name string) string {
	return "`" + s.Project + "." + s.ViewsDataset + "." + name + "`"
}

// Overrides carries values set explicitly on the command line. Empty or zero
// means "not set".
type Overrides struct {
	Project      string
	Location     string
	ViewsDataset string
	MaxCostUSD   *float64
	PricePerTiB  *float64
}

// ResolveSettings applies precedence flag > environment > config file >
// built-in default for every setting.
func ResolveSettings(o Overrides) Settings {
	s := Settings{PricePerTiB: DefaultPricePerTiB, MaxCostUSD: DefaultMaxCostUSD}
	stored := config.TargetIntel()

	s.Project, s.ProjectSource = pick(o.Project, os.Getenv(EnvProject), stored.Project, DefaultProject)
	s.Location, s.LocationSource = pick(o.Location, os.Getenv(EnvLocation), stored.Location, DefaultLocation)
	s.ViewsDataset, _ = pick(o.ViewsDataset, os.Getenv(EnvViewsDataset), stored.ViewsDataset, DefaultViewsDataset)

	switch {
	case o.MaxCostUSD != nil:
		s.MaxCostUSD = *o.MaxCostUSD
	case os.Getenv(EnvMaxCost) != "":
		if v, err := strconv.ParseFloat(strings.TrimSpace(os.Getenv(EnvMaxCost)), 64); err == nil {
			s.MaxCostUSD = v
		}
	}

	switch {
	case o.PricePerTiB != nil:
		s.PricePerTiB = *o.PricePerTiB
	case os.Getenv(EnvPricePerTiB) != "":
		if v, err := strconv.ParseFloat(strings.TrimSpace(os.Getenv(EnvPricePerTiB)), 64); err == nil && v > 0 {
			s.PricePerTiB = v
		}
	}

	return s
}

func pick(flag, env, stored, def string) (string, string) {
	switch {
	case strings.TrimSpace(flag) != "":
		return strings.TrimSpace(flag), "flag"
	case strings.TrimSpace(env) != "":
		return strings.TrimSpace(env), "env"
	case strings.TrimSpace(stored) != "":
		return strings.TrimSpace(stored), "config"
	default:
		return def, "default"
	}
}
