package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTargetIntelRoundTrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	require.NoError(t, SaveToken("tok"))
	require.NoError(t, SetTargetIntel(TargetIntelConfig{Project: "p", Location: "l"}))
	got := TargetIntel()
	assert.Equal(t, TargetIntelConfig{Project: "p", Location: "l"}, got)
	assert.Equal(t, "tok", Token(), "saving target-intel settings keeps the token")
	raw, err := os.ReadFile(filepath.Join(home, ".config", "vulncheck", "vulncheck.yaml"))
	require.NoError(t, err)
	assert.Contains(t, string(raw), "targetintel:")
}
