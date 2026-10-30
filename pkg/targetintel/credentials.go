package targetintel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/vulncheck-oss/cli/internal/errs"
	"github.com/vulncheck-oss/cli/pkg/config"
)

// Scopes requested at login and attached to every credential. They match
// what `gcloud auth login` asks for, so the stored file is interchangeable
// with gcloud's own application-default credentials.
var Scopes = []string{
	"https://www.googleapis.com/auth/cloud-platform",
	"https://www.googleapis.com/auth/userinfo.email",
	"openid",
}

// CredentialSource identifies where the active Google credential came from.
// The string values are the agent-facing contract of `auth status --json`.
type CredentialSource string

const (
	SourceNone CredentialSource = ""
	// SourceEnv is a credentials file named by VC_TI_CREDENTIALS.
	SourceEnv CredentialSource = "env"
	// SourceStored is the file written by `target-intel auth login`.
	SourceStored CredentialSource = "stored"
	// SourceADC is Google Application Default Credentials (gcloud auth
	// application-default login, GOOGLE_APPLICATION_CREDENTIALS, or the
	// metadata server).
	SourceADC CredentialSource = "adc"
)

// Credentials is a resolved Google credential plus where it came from.
type Credentials struct {
	Source CredentialSource
	// Path is the file the credential was read from, when there is one.
	Path string
	// Account is the principal recorded at login time, when known without a
	// network call. Principal() verifies it against Google.
	Account string

	creds *google.Credentials
}

// TokenSource returns the OAuth2 token source backing the credential.
func (c *Credentials) TokenSource() oauth2.TokenSource {
	return c.creds.TokenSource
}

// CredentialsPath is the file `auth login` writes. It is in Google's
// authorized_user format, so GOOGLE_APPLICATION_CREDENTIALS can point at it.
func CredentialsPath() (string, error) {
	dir, err := config.Dir()
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, "target-intel-credentials.json"), nil
}

// storedCredentials is the on-disk shape. The first four fields are what
// google.CredentialsFromJSON expects for an authorized_user; account is ours.
type storedCredentials struct {
	Type         string `json:"type"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RefreshToken string `json:"refresh_token"`
	Account      string `json:"account,omitempty"`
}

// ResolveCredentials finds the credential to use. Precedence: the file named
// by VC_TI_CREDENTIALS, then the stored login, then Application Default
// Credentials. A missing credential is an auth_required error.
func ResolveCredentials(ctx context.Context) (*Credentials, error) {
	if path := strings.TrimSpace(os.Getenv(EnvCredentials)); path != "" {
		c, err := fromFile(ctx, path)
		if err != nil {
			return nil, errs.Wrap(errs.KindAuthInvalid, err, "%s: %s", EnvCredentials, err.Error())
		}
		c.Source = SourceEnv

		return c, nil
	}

	path, err := CredentialsPath()
	if err == nil {
		if _, statErr := os.Stat(path); statErr == nil {
			c, err := fromFile(ctx, path)
			if err != nil {
				return nil, errs.Wrap(errs.KindAuthInvalid, err, "stored credentials are unreadable: %s", err.Error()).
					WithHint("run `vulncheck target-intel auth login` again")
			}
			c.Source = SourceStored

			return c, nil
		}
	}

	creds, err := google.FindDefaultCredentials(ctx, Scopes...)
	if err != nil {
		return nil, errs.AuthRequired("no Google credentials found for Target Intelligence").
			WithHint("run `vulncheck target-intel auth login`, or set %s to a service-account key file", EnvCredentials)
	}

	return &Credentials{Source: SourceADC, creds: creds}, nil
}

func fromFile(ctx context.Context, path string) (*Credentials, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// The file is one the user named (VC_TI_CREDENTIALS) or one this CLI
	// wrote, so the unvalidated-configuration risk the deprecation warns
	// about does not apply.
	creds, err := google.CredentialsFromJSON(ctx, data, Scopes...) //nolint:staticcheck
	if err != nil {
		return nil, err
	}

	c := &Credentials{Path: path, creds: creds}
	var meta struct {
		Account     string `json:"account"`
		ClientEmail string `json:"client_email"`
	}
	if json.Unmarshal(data, &meta) == nil {
		c.Account = meta.Account
		if c.Account == "" {
			c.Account = meta.ClientEmail
		}
	}

	return c, nil
}

// SaveCredentials writes an authorized_user file for the refresh token.
func SaveCredentials(conf *oauth2.Config, tok *oauth2.Token, account string) (string, error) {
	if tok.RefreshToken == "" {
		return "", fmt.Errorf("google did not return a refresh token; revoke the app at https://myaccount.google.com/permissions and log in again")
	}
	path, err := CredentialsPath()
	if err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(storedCredentials{
		Type:         "authorized_user",
		ClientID:     conf.ClientID,
		ClientSecret: conf.ClientSecret,
		RefreshToken: tok.RefreshToken,
		Account:      account,
	}, "", "  ")
	if err != nil {
		return "", err
	}

	return path, os.WriteFile(path, data, 0600)
}

// RemoveCredentials deletes the stored login. Removing a file that does not
// exist is not an error.
func RemoveCredentials() (string, error) {
	path, err := CredentialsPath()
	if err != nil {
		return "", err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return path, err
	}

	return path, nil
}

// Principal asks Google who the credential belongs to. It also proves the
// credential still works, which a refresh token on disk does not.
func Principal(ctx context.Context, ts oauth2.TokenSource) (string, error) {
	client := oauth2.NewClient(ctx, ts)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.googleapis.com/oauth2/v3/userinfo", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", classify(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", authInvalid(fmt.Errorf("userinfo returned HTTP %d", resp.StatusCode), "", fmt.Sprintf("userinfo returned HTTP %d", resp.StatusCode))
	}
	var info struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return "", err
	}

	return info.Email, nil
}

// CredentialsEnvSet reports whether VC_TI_CREDENTIALS names a file.
func CredentialsEnvSet() bool {
	return strings.TrimSpace(os.Getenv(EnvCredentials)) != ""
}
