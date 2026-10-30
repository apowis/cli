package targetintel

import (
	"github.com/pkg/browser"
	"github.com/spf13/cobra"

	"github.com/vulncheck-oss/cli/internal/errs"
	"github.com/vulncheck-oss/cli/internal/output"
	"github.com/vulncheck-oss/cli/pkg/config"
	"github.com/vulncheck-oss/cli/pkg/i18n"
	"github.com/vulncheck-oss/cli/pkg/targetintel"
)

func authCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth <command>",
		Short: i18n.C.TargetIntelAuthShort,
		Args:  validArgs(cobra.NoArgs),
		RunE:  groupRunE,
	}
	cmd.AddCommand(loginCommand(), logoutCommand(), statusCommand())

	return cmd
}

// loginPayload is the JSON emitted by `auth login --json`.
type loginPayload struct {
	SchemaVersion   int    `json:"schema_version"`
	Account         string `json:"account"`
	CredentialsPath string `json:"credentials_path"`
	Project         string `json:"project"`
	Location        string `json:"location"`
}

func loginCommand() *cobra.Command {
	var noBrowser bool
	cmd := &cobra.Command{
		Use:   "login",
		Short: i18n.C.TargetIntelAuthLoginShort,
		Long:  i18n.C.TargetIntelAuthLoginLong,
		Args:  validArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			r := output.FromCmd(cmd)

			// A login writes a credentials file that VC_TI_CREDENTIALS would
			// then shadow, so refuse rather than report a success that changes
			// nothing.
			if targetintel.CredentialsEnvSet() {
				return errs.Validation("%s is set, so the CLI already authenticates with it and `auth login` would have no effect", targetintel.EnvCredentials).
					WithHint("clear %s from your environment to log in with a browser instead", targetintel.EnvCredentials)
			}
			if !r.Interactive() && !noBrowser {
				return errs.Validation("%s", i18n.C.TargetIntelAuthLoginErrorCI)
			}
			// Resolved before the browser flow so a bad --project fails first.
			s, err := settingsFromCmd(cmd, targetintel.Overrides{})
			if err != nil {
				return err
			}

			opts := targetintel.LoginOptions{
				Notify: func(format string, args ...any) { r.Info(format, args...) },
			}
			if !noBrowser {
				opts.OpenBrowser = browser.OpenURL
			}
			res, err := targetintel.Login(cmd.Context(), opts)
			if err != nil {
				return err
			}

			// Save an explicit --project or --location so later invocations
			// need no flag. Everything else already stored is kept, and a
			// value that only came from the environment is not persisted.
			if s.ProjectSource == "flag" || s.LocationSource == "flag" {
				saved := config.TargetIntel()
				if s.ProjectSource == "flag" {
					saved.Project = s.Project
				}
				if s.LocationSource == "flag" {
					saved.Location = s.Location
				}
				if err := config.SetTargetIntel(saved); err != nil {
					return err
				}
			}

			if r.IsJSON() {
				return r.JSON(loginPayload{
					SchemaVersion:   output.SchemaVersion,
					Account:         res.Account,
					CredentialsPath: res.Path,
					Project:         s.Project,
					Location:        s.Location,
				})
			}
			r.Success("Authenticated as %s", res.Account)
			r.Stat("Credentials saved to", res.Path)
			r.Stat("Billing project", s.Project)
			r.Stat("Location", s.Location)

			return nil
		},
	}
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "Print the authorization URL instead of opening a browser")

	return cmd
}

func logoutCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: i18n.C.TargetIntelAuthLogoutShort,
		Args:  validArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			r := output.FromCmd(cmd)
			if targetintel.CredentialsEnvSet() {
				return errs.Validation("%s is set; `auth logout` cannot unset an environment variable", targetintel.EnvCredentials)
			}
			path, err := targetintel.RemoveCredentials()
			if err != nil {
				return err
			}
			if r.IsJSON() {
				return r.JSON(map[string]any{
					"schema_version":   output.SchemaVersion,
					"removed":          true,
					"credentials_path": path,
				})
			}
			r.Success("Removed stored Target Intelligence credentials")

			return nil
		},
	}
}

// statusPayload is the JSON emitted by `auth status --json`. Authenticated
// is always a bool so callers can dispatch on it without parsing an error
// envelope; the command exits 0 either way in JSON mode.
type statusPayload struct {
	SchemaVersion    int     `json:"schema_version"`
	Authenticated    bool    `json:"authenticated"`
	CredentialSource string  `json:"credential_source,omitempty"`
	CredentialsPath  string  `json:"credentials_path,omitempty"`
	Principal        string  `json:"principal,omitempty"`
	Project          string  `json:"project"`
	ProjectSource    string  `json:"project_source"`
	Location         string  `json:"location"`
	LocationSource   string  `json:"location_source"`
	MaxCostUSD       float64 `json:"max_cost_usd"`
	Reason           string  `json:"reason,omitempty"`
}

func statusCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: i18n.C.TargetIntelAuthStatusShort,
		Args:  validArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			r := output.FromCmd(cmd)
			s, serr := settingsFromCmd(cmd, targetintel.Overrides{})
			p := statusPayload{
				SchemaVersion:  output.SchemaVersion,
				Project:        s.Project,
				ProjectSource:  s.ProjectSource,
				Location:       s.Location,
				LocationSource: s.LocationSource,
				MaxCostUSD:     s.MaxCostUSD,
			}
			// JSON mode keeps its exit-0 contract: a bad setting is a reason,
			// like a missing credential.
			if serr != nil {
				if r.IsJSON() {
					p.Reason = serr.Error()

					return r.JSON(p)
				}

				return serr
			}

			creds, err := targetintel.ResolveCredentials(cmd.Context())
			if err != nil {
				if r.IsJSON() {
					p.Reason = err.Error()

					return r.JSON(p)
				}

				return err
			}
			p.CredentialSource = string(creds.Source)
			p.CredentialsPath = creds.Path

			principal, err := targetintel.Principal(cmd.Context(), creds.TokenSource())
			if err != nil {
				if r.IsJSON() {
					p.Reason = err.Error()

					return r.JSON(p)
				}

				return err
			}
			p.Authenticated = true
			p.Principal = principal

			if r.IsJSON() {
				return r.JSON(p)
			}
			r.Success("Authenticated as %s", principal)
			r.Stat("Credential source", credentialSourceLabel(creds))
			r.Stat("Billing project", s.Project+" (from "+s.ProjectSource+")")
			r.Stat("Location", s.Location+" (from "+s.LocationSource+")")
			r.Stat("Max cost per query", targetintel.FormatCost(s.MaxCostUSD))

			return nil
		},
	}
}

func credentialSourceLabel(c *targetintel.Credentials) string {
	switch c.Source {
	case targetintel.SourceEnv:
		return targetintel.EnvCredentials + " (" + c.Path + ")"
	case targetintel.SourceStored:
		return c.Path
	case targetintel.SourceADC:
		return "application default credentials"
	default:
		return string(c.Source)
	}
}
