package targetintel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulncheck-oss/cli/internal/errs"
	"github.com/vulncheck-oss/cli/internal/output"
	"github.com/vulncheck-oss/cli/pkg/config"
	"github.com/vulncheck-oss/cli/pkg/targetintel"
)

// These tests set environment variables and swap the package-level login
// seam, so none of them may call t.Parallel. That is safe alongside the
// parallel tests in this package: top-level parallel tests do not resume
// until every sequential test has finished, so nothing reads HOME or the
// VC_TI_* variables while these run.

// isolateEnv points the config file at a temp HOME and clears every VC_TI_*
// variable. It returns the temp HOME.
func isolateEnv(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	// config.Dir resolves through os.UserHomeDir, which reads HOME, or
	// USERPROFILE on Windows.
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", home)
	for _, env := range []string{targetintel.EnvProject, targetintel.EnvLocation, targetintel.EnvViewsDataset, targetintel.EnvDataset, targetintel.EnvMaxCost, targetintel.EnvPricePerTiB, targetintel.EnvCredentials, targetintel.EnvDailyBudget, targetintel.EnvMonthlyBudget} {
		t.Setenv(env, "")
	}

	return home
}

// isolateLogin isolates the environment with isolateEnv and stubs the
// browser flow. It returns the config file path and
// a counter of stub calls.
func isolateLogin(t *testing.T, err error) (string, *int) {
	t.Helper()
	home := isolateEnv(t)

	calls := 0
	orig := login
	login = func(context.Context, targetintel.LoginOptions) (*targetintel.LoginResult, error) {
		calls++
		if err != nil {
			return nil, err
		}

		return &targetintel.LoginResult{Account: "user@example.com", Path: filepath.Join(home, "creds.json")}, nil
	}
	t.Cleanup(func() { login = orig })

	return filepath.Join(home, ".config", "vulncheck", "vulncheck.yaml"), &calls
}

// runLogin executes `auth login` through the real command tree and returns
// what it wrote to stdout.
func runLogin(t *testing.T, mode output.Mode, interactive bool, args ...string) (string, error) {
	t.Helper()
	var stdout bytes.Buffer
	r := output.New(output.Options{Mode: mode, Interactive: interactive, Stdout: &stdout, Stderr: io.Discard})
	cmd := Command()
	cmd.SetArgs(append([]string{"auth", "login"}, args...))
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetIn(strings.NewReader(""))
	err := cmd.ExecuteContext(output.WithContext(t.Context(), r))

	return stdout.String(), err
}

func seedTargetIntel(t *testing.T) config.TargetIntelConfig {
	t.Helper()
	seed := config.TargetIntelConfig{Project: "oldproj", Location: "us-east1", ViewsDataset: "my_views", Dataset: "my_warehouse"}
	require.NoError(t, config.SetTargetIntel(seed))

	return seed
}

func TestLoginSavesProjectFlagKeepingOtherSettings(t *testing.T) {
	_, calls := isolateLogin(t, nil)
	seed := seedTargetIntel(t)

	_, err := runLogin(t, output.ModeText, false, "--no-browser", "--project", "newproj")
	require.NoError(t, err)
	assert.Equal(t, 1, *calls)

	want := seed
	want.Project = "newproj"
	assert.Equal(t, want, config.TargetIntel())
}

func TestLoginDoesNotSaveEnvProject(t *testing.T) {
	t.Run("seeded config is left untouched", func(t *testing.T) {
		path, calls := isolateLogin(t, nil)
		seed := seedTargetIntel(t)
		before, err := os.ReadFile(path)
		require.NoError(t, err)
		t.Setenv(targetintel.EnvProject, "envproj")

		_, err = runLogin(t, output.ModeText, false, "--no-browser")
		require.NoError(t, err)
		assert.Equal(t, 1, *calls)

		assert.Equal(t, seed, config.TargetIntel())
		after, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, string(before), string(after))
	})

	t.Run("no config file is created", func(t *testing.T) {
		path, calls := isolateLogin(t, nil)
		t.Setenv(targetintel.EnvProject, "envproj")

		_, err := runLogin(t, output.ModeText, false, "--no-browser")
		require.NoError(t, err)
		assert.Equal(t, 1, *calls)

		_, err = os.Stat(path)
		assert.True(t, os.IsNotExist(err), "nothing flag-sourced, so nothing is written: %v", err)
	})
}

func TestLoginSavesLocationFlagOnly(t *testing.T) {
	_, _ = isolateLogin(t, nil)
	seed := seedTargetIntel(t)

	_, err := runLogin(t, output.ModeText, false, "--no-browser", "--location", "us-central1")
	require.NoError(t, err)

	want := seed
	want.Location = "us-central1"
	assert.Equal(t, want, config.TargetIntel())
}

func TestLoginRefusesWithCredentialsEnv(t *testing.T) {
	_, calls := isolateLogin(t, nil)
	t.Setenv(targetintel.EnvCredentials, filepath.Join(t.TempDir(), "sa.json"))

	_, err := runLogin(t, output.ModeText, false, "--no-browser")
	require.Error(t, err)
	assert.Equal(t, 2, errs.Classify(err).ExitCode(), "%v", err)
	assert.Contains(t, err.Error(), targetintel.EnvCredentials)
	assert.Zero(t, *calls)
}

func TestLoginNonInteractiveNeedsNoBrowser(t *testing.T) {
	_, calls := isolateLogin(t, nil)

	_, err := runLogin(t, output.ModeText, false)
	require.Error(t, err)
	assert.Equal(t, 2, errs.Classify(err).ExitCode(), "%v", err)
	assert.Zero(t, *calls)
}

func TestLoginJSON(t *testing.T) {
	_, _ = isolateLogin(t, nil)

	out, err := runLogin(t, output.ModeJSON, false, "--no-browser", "--project", "newproj", "--location", "us-central1")
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &got), out)
	assert.Equal(t, "user@example.com", got["account"])
	assert.True(t, strings.HasSuffix(got["credentials_path"].(string), "creds.json"), got["credentials_path"])
	assert.Equal(t, "newproj", got["project"])
	assert.Equal(t, "us-central1", got["location"])
}

func TestLoginErrorLeavesConfig(t *testing.T) {
	path, calls := isolateLogin(t, errors.New("consent denied"))
	seedTargetIntel(t)
	before, err := os.ReadFile(path)
	require.NoError(t, err)

	_, err = runLogin(t, output.ModeText, false, "--no-browser", "--project", "newproj", "--location", "us-central1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "consent denied")
	assert.Equal(t, 1, *calls)

	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, string(before), string(after))
}
