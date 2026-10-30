// Package targetintel talks to the VulnCheck Target Intelligence warehouse in
// BigQuery: credential resolution, a gcloud-style browser login, and a query
// path that caps every job's bytes billed at the caller's cost limit, so
// BigQuery itself refuses a job that would cost more.
package targetintel

import (
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/vulncheck-oss/cli/internal/errs"
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
	// DefaultDataset holds the warehouse tables the host and counts commands
	// read directly (host_profile, fingerprint_current, cve_host_counts).
	DefaultDataset = "anchorbreaker_prod"
	// DefaultMaxCostUSD is the per-invocation spend limit.
	DefaultMaxCostUSD = 1.00
	// DefaultPricePerTiB is BigQuery's on-demand analysis price.
	DefaultPricePerTiB = 6.25

	EnvProject      = "VC_TI_PROJECT"
	EnvLocation     = "VC_TI_LOCATION"
	EnvViewsDataset = "VC_TI_VIEWS_DATASET"
	EnvDataset      = "VC_TI_DATASET"
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
	Dataset      string
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

// Table returns the fully qualified name of a table or view in the warehouse
// dataset, ready to be used in SQL.
func (s Settings) Table(name string) string {
	return "`" + s.Project + "." + s.Dataset + "." + name + "`"
}

// Overrides carries values set explicitly on the command line. Empty or zero
// means "not set".
type Overrides struct {
	Project      string
	Location     string
	ViewsDataset string
	Dataset      string
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
	s.Dataset, _ = pick(o.Dataset, os.Getenv(EnvDataset), stored.Dataset, DefaultDataset)

	switch {
	case o.MaxCostUSD != nil:
		s.MaxCostUSD = *o.MaxCostUSD
	case os.Getenv(EnvMaxCost) != "":
		// Garbage, NaN or Inf falls back to the default cap; a negative
		// number is kept so Validate can reject it rather than run uncapped.
		if v, err := strconv.ParseFloat(strings.TrimSpace(os.Getenv(EnvMaxCost)), 64); err == nil && finite(v) {
			s.MaxCostUSD = v
		}
	}

	switch {
	case o.PricePerTiB != nil:
		s.PricePerTiB = *o.PricePerTiB
	case os.Getenv(EnvPricePerTiB) != "":
		if v, err := strconv.ParseFloat(strings.TrimSpace(os.Getenv(EnvPricePerTiB)), 64); err == nil && v > 0 && finite(v) {
			s.PricePerTiB = v
		}
	}

	return s
}

func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }

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

var (
	// projectID admits the characters of a Google project id (lowercase
	// letters, digits and hyphens, starting with a letter and not ending
	// with a hyphen), with the optional "domain:" prefix of a domain-scoped
	// project. Length is left to Google.
	projectID = regexp.MustCompile(`^(?:[a-z0-9][a-z0-9.-]*:)?[a-z](?:[a-z0-9-]*[a-z0-9])?$`)
	// datasetID is BigQuery's dataset naming rule.
	datasetID = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
	// tableID is BigQuery's table naming rule: letters, marks, numbers,
	// connectors (including _), dashes and spaces.
	tableID = regexp.MustCompile(`^[\p{L}\p{M}\p{N}\p{Pc}\p{Pd}\p{Zs}]+$`)
	// locationName admits multi-regions (US, EU) and regions
	// (europe-west1). An unknown but well-formed location is left to
	// BigQuery to reject.
	locationName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{1,63}$`)
)

// maxNameBytes is BigQuery's limit on a dataset or table name.
const maxNameBytes = 1024

func validProject(s string) bool { return projectID.MatchString(s) }

func validDataset(s string) bool { return len(s) <= maxNameBytes && datasetID.MatchString(s) }

func validTable(s string) bool { return len(s) <= maxNameBytes && tableID.MatchString(s) }

// Validate rejects settings that would otherwise reach BigQuery as a
// malformed name or an unusable cost cap. Every source (flag, environment,
// config file) is checked, since all of them end up in the same SQL and
// job configuration. The project and datasets are spliced into SQL inside
// backticks, so this is also what keeps a stray backtick out of a query.
func (s Settings) Validate() error {
	if !validProject(s.Project) {
		return errs.Validation("project %q (from %s) is not a valid GCP project id", s.Project, s.ProjectSource).
			WithHint("set --project or %s to a project id such as %s", EnvProject, DefaultProject)
	}
	if !locationName.MatchString(s.Location) {
		return errs.Validation("location %q (from %s) is not a valid BigQuery location", s.Location, s.LocationSource).
			WithHint("set --location or %s to a location such as %s", EnvLocation, DefaultLocation)
	}
	if !validDataset(s.ViewsDataset) {
		return errs.Validation("views dataset %q is not a valid dataset name (letters, digits and underscores)", s.ViewsDataset).
			WithHint("check --views-dataset and %s", EnvViewsDataset)
	}
	if !validDataset(s.Dataset) {
		return errs.Validation("dataset %q is not a valid dataset name (letters, digits and underscores)", s.Dataset).
			WithHint("check --dataset and %s", EnvDataset)
	}
	if !finite(s.MaxCostUSD) || s.MaxCostUSD < 0 {
		return errs.Validation("--max-cost must be a finite amount in USD, 0 or more (0 disables the cap); got %v", s.MaxCostUSD).
			WithHint("check --max-cost and %s", EnvMaxCost)
	}
	if !finite(s.PricePerTiB) || s.PricePerTiB <= 0 {
		return errs.Validation("%s must be a positive price in USD; got %v", EnvPricePerTiB, s.PricePerTiB)
	}

	return nil
}
