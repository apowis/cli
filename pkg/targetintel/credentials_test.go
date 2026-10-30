package targetintel

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/vulncheck-oss/cli/internal/errs"
)

const authorizedUser = `{"type":"authorized_user","client_id":"id","client_secret":"secret","refresh_token":"rt","account":"jane@example.com"}`

func TestResolveCredentialsPrecedence(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(home, "missing.json"))
	t.Setenv(EnvCredentials, "")
	ctx := context.Background()

	// Nothing anywhere: auth_required with a hint naming the login command.
	// (ADC lookup fails because GOOGLE_APPLICATION_CREDENTIALS points at a
	// missing file and HOME has no gcloud config.)
	_, err := ResolveCredentials(ctx)
	var e *errs.Error
	require.ErrorAs(t, err, &e)
	assert.Equal(t, errs.KindAuthRequired, e.Kind)
	assert.Contains(t, e.Hint, "target-intel auth login")

	// Stored login.
	path, err := CredentialsPath()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, []byte(authorizedUser), 0600))
	c, err := ResolveCredentials(ctx)
	require.NoError(t, err)
	assert.Equal(t, SourceStored, c.Source)
	assert.Equal(t, path, c.Path)
	assert.Equal(t, "jane@example.com", c.Account)
	assert.NotNil(t, c.TokenSource())

	// VC_TI_CREDENTIALS beats the stored login.
	envPath := filepath.Join(home, "sa.json")
	require.NoError(t, os.WriteFile(envPath, []byte(`{"type":"authorized_user","client_id":"i","client_secret":"s","refresh_token":"r"}`), 0600))
	t.Setenv(EnvCredentials, envPath)
	c, err = ResolveCredentials(ctx)
	require.NoError(t, err)
	assert.Equal(t, SourceEnv, c.Source)
	assert.Equal(t, envPath, c.Path)
	assert.True(t, CredentialsEnvSet())

	// A broken env file is auth_invalid, not a silent fallback.
	require.NoError(t, os.WriteFile(envPath, []byte(`not json`), 0600))
	_, err = ResolveCredentials(ctx)
	require.ErrorAs(t, err, &e)
	assert.Equal(t, errs.KindAuthInvalid, e.Kind)
}

func TestSaveAndRemoveCredentials(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(EnvCredentials, "")
	conf := &oauth2.Config{ClientID: "id", ClientSecret: "secret"}

	_, err := SaveCredentials(conf, &oauth2.Token{AccessToken: "at"}, "jane@example.com")
	require.Error(t, err, "a token without a refresh token is useless on disk")

	path, err := SaveCredentials(conf, &oauth2.Token{AccessToken: "at", RefreshToken: "rt"}, "jane@example.com")
	require.NoError(t, err)
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

	c, err := ResolveCredentials(context.Background())
	require.NoError(t, err)
	assert.Equal(t, SourceStored, c.Source)
	assert.Equal(t, "jane@example.com", c.Account)

	removed, err := RemoveCredentials()
	require.NoError(t, err)
	assert.Equal(t, path, removed)
	_, err = os.Stat(path)
	assert.True(t, os.IsNotExist(err))

	_, err = RemoveCredentials()
	assert.NoError(t, err, "removing twice is fine")
}
