package targetintel

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulncheck-oss/cli/internal/output"
	"github.com/vulncheck-oss/cli/pkg/targetintel"
)

// bufRenderer returns a text-mode renderer writing stdout and stderr to
// buffers, so tests can tell a warning (stderr) from the payload (stdout).
func bufRenderer() (*output.Renderer, *bytes.Buffer, *bytes.Buffer) {
	var out, errOut bytes.Buffer
	r := output.New(output.Options{Mode: output.ModeText, Stdout: &out, Stderr: &errOut})

	return r, &out, &errOut
}

// bufCmd returns a command carrying a buffered text-mode renderer.
func bufCmd(t *testing.T) (*cobra.Command, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	r, out, errOut := bufRenderer()
	cmd := &cobra.Command{Use: "x"}
	cmd.SetContext(output.WithContext(t.Context(), r))

	return cmd, out, errOut
}

func TestRenderHost(t *testing.T) {
	t.Parallel()
	jobs := []hostJob{{Name: "host_profile", CostUSD: 0.5}, {Name: "fingerprint_current", CostUSD: 0.25}}
	profile := func(truncated bool) map[string]any {
		return map[string]any{
			"ip":           "1.2.3.4",
			"country":      "United States",
			"country_code": "US",
			"asn":          int64(15169),
			"as_name":      "GOOGLE",
			"as_domain":    "google.com",
			"last_seen":    "2026-10-01T00:00:00Z",
			"port_count":   int64(2),
			"identified":   int64(1),
			"truncated":    truncated,
			"services": []any{
				map[string]any{"port": int64(22), "service": "ssh", "transport": "tcp"},
				map[string]any{"port": int64(53), "service": "dns", "transport": "udp"},
			},
		}
	}
	fps := []map[string]any{{"port": int64(22), "protocol": "ssh", "vendor": "openbsd", "product": "openssh", "version": "9.6"}}

	tests := []struct {
		name    string
		p       hostPayload
		wantOut []string
		notOut  []string
		wantErr []string
		notErr  []string
		noWarn  bool
	}{
		{
			name:    "not found",
			p:       hostPayload{Query: targetintel.HostQuery{IP: "1.2.3.4"}, Found: false, Jobs: jobs},
			wantOut: []string{"Billed $0.75 across 2 lookups"},
			notOut:  []string{"Host:", "port"},
			wantErr: []string{"1.2.3.4 was not seen listening on any port in the current scan window."},
		},
		{
			name: "truncated profile with fingerprints",
			p:    hostPayload{Query: targetintel.HostQuery{IP: "1.2.3.4", LookbackDays: 30}, Found: true, Profile: profile(true), Fingerprints: fps, Jobs: jobs},
			wantOut: []string{
				"Host: 1.2.3.4",
				"Location: United States (US)",
				"Network: 15169 GOOGLE (google.com)",
				"Last seen: 2026-10-01T00:00:00Z",
				"Ports listening: 2",
				"Identified: 1",
				"transport", "ssh", "udp", "dns",
				"openssh", "9.6",
				"cves lists rule-annotated CVEs only",
			},
			wantErr: []string{"The port list is truncated"},
		},
		{
			name:    "no profile but fingerprints",
			p:       hostPayload{Query: targetintel.HostQuery{IP: "1.2.3.4", LookbackDays: 30}, Found: true, Fingerprints: fps, Jobs: jobs},
			wantOut: []string{"openssh", "9.6", "rule_id", "cves lists rule-annotated CVEs only"},
			notOut:  []string{"Host:", "transport"},
			wantErr: []string{"1.2.3.4 has no host profile row; showing fingerprints only."},
		},
		{
			name:    "profile without fingerprints",
			p:       hostPayload{Query: targetintel.HostQuery{IP: "1.2.3.4", LookbackDays: 7}, Found: true, Profile: profile(false), Fingerprints: []map[string]any{}, Jobs: jobs},
			wantOut: []string{"Host: 1.2.3.4", "ssh", "No fingerprints in the last 7 days."},
			notOut:  []string{"rule_id", "cves lists"},
			noWarn:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, out, errOut := bufRenderer()
			require.NoError(t, renderHost(r, tt.p))
			for _, s := range tt.wantOut {
				assert.Contains(t, out.String(), s)
			}
			for _, s := range tt.notOut {
				assert.NotContains(t, out.String(), s)
			}
			for _, s := range tt.wantErr {
				assert.Contains(t, errOut.String(), s)
			}
			if tt.noWarn {
				assert.Empty(t, errOut.String(), "no warning expected")
			}
		})
	}
}

func TestServiceRows(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   any
		want [][]string
	}{
		{
			name: "records",
			in: []any{
				map[string]any{"port": int64(22), "service": "ssh", "transport": "tcp"},
				map[string]any{"port": int64(53), "service": nil, "transport": "udp"},
			},
			want: [][]string{{"22", "ssh", "tcp"}, {"53", "NULL", "udp"}},
		},
		{name: "empty", in: []any{}, want: [][]string{}},
		{name: "not a slice", in: "ssh", want: nil},
		{name: "nil", in: nil, want: nil},
		{
			name: "malformed elements skipped",
			in:   []any{"22/tcp", int64(1), nil, map[string]any{"port": int64(80)}},
			want: [][]string{{"80", "NULL", "NULL"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, serviceRows(tt.in))
		})
	}
}

func TestJoinStrings(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   any
		want any
	}{
		{name: "strings", in: []any{"ssh", "http"}, want: "ssh, http"},
		{name: "empty", in: []any{}, want: ""},
		{name: "not a slice passes through", in: "ssh", want: "ssh"},
		{name: "nil passes through", in: nil, want: nil},
		{name: "number passes through", in: int64(3), want: int64(3)},
		{name: "mixed elements", in: []any{"ssh", int64(22), nil, []any{"x"}}, want: `ssh, 22, NULL, ["x"]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, joinStrings(tt.in))
		})
	}
}

func TestCompactCountries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   any
		want any
	}{
		{
			name: "records",
			in: []any{
				map[string]any{"country_code": "US", "hosts": int64(1031)},
				map[string]any{"country_code": "IN", "hosts": int64(142)},
			},
			want: "US 1031, IN 142",
		},
		{name: "empty", in: []any{}, want: ""},
		{name: "not a slice passes through", in: "US", want: "US"},
		{name: "nil passes through", in: nil, want: nil},
		{
			name: "malformed elements skipped",
			in:   []any{"US", int64(5), map[string]any{"country_code": "DE"}},
			want: "DE NULL",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, compactCountries(tt.in))
		})
	}
}

func TestCapNote(t *testing.T) {
	t.Parallel()
	assert.Empty(t, capNote(targetintel.QueryOptions{}))
	assert.Empty(t, capNote(targetintel.QueryOptions{MaxCostUSD: -1}))
	assert.Equal(t, ", cap $5.00", capNote(targetintel.QueryOptions{MaxCostUSD: 5}))
	assert.Equal(t, ", cap $0.0050", capNote(targetintel.QueryOptions{MaxCostUSD: 0.005}))
}

func TestTruncatedNote(t *testing.T) {
	t.Parallel()
	assert.Empty(t, truncatedNote(&targetintel.Result{}))
	assert.Equal(t, " (use --all or a larger --limit for more)", truncatedNote(&targetintel.Result{Truncated: true}))
}

// WithinLimit is computed by estimate, which needs a BigQuery dry run; here
// it is set directly to drive each branch of printEstimate.
func TestPrintEstimate(t *testing.T) {
	t.Parallel()
	est := targetintel.Estimate{StatementType: "SELECT", BytesProcessed: 1 << 30, CostUSD: 2}
	tests := []struct {
		name    string
		e       estimateResult
		opts    targetintel.QueryOptions
		wantOut string
		wantErr string
	}{
		{
			name:    "unlimited",
			e:       estimateResult{Estimate: est, WithinLimit: true},
			opts:    targetintel.QueryOptions{PricePerTiB: 6.25},
			wantOut: "Max cost: unlimited",
		},
		{
			name:    "within limit",
			e:       estimateResult{Estimate: est, MaxCostUSD: 5, WithinLimit: true},
			opts:    targetintel.QueryOptions{MaxCostUSD: 5, PricePerTiB: 6.25},
			wantOut: "Max cost: $5.00 (within limit)",
		},
		{
			name:    "exceeds limit",
			e:       estimateResult{Estimate: est, MaxCostUSD: 1, WithinLimit: false},
			opts:    targetintel.QueryOptions{MaxCostUSD: 1, PricePerTiB: 6.25},
			wantErr: "The estimate exceeds the max cost $1.00.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, out, errOut := bufRenderer()
			printEstimate(r, tt.e, tt.opts)
			assert.Contains(t, out.String(), "Statement: SELECT")
			assert.Contains(t, out.String(), "Bytes to be scanned: ")
			assert.Contains(t, out.String(), "Estimated cost: $2.00 (on-demand, $6.25/TiB)")
			if tt.wantOut != "" {
				assert.Contains(t, out.String(), tt.wantOut)
				assert.Empty(t, errOut.String())
			}
			if tt.wantErr != "" {
				assert.Contains(t, errOut.String(), tt.wantErr)
				assert.NotContains(t, out.String(), "Max cost:")
			}
		})
	}
}

func TestRowTable(t *testing.T) {
	t.Parallel()
	got := rowTable([]string{"ip", "port"}, []map[string]any{
		{"ip": "1.2.3.4", "port": int64(443), "extra": "hidden"},
		{"ip": "5.6.7.8"},
	})
	assert.Contains(t, got, "ip")
	assert.Contains(t, got, "port")
	assert.Contains(t, got, "1.2.3.4")
	assert.Contains(t, got, "443")
	assert.Contains(t, got, "5.6.7.8")
	assert.Contains(t, got, "NULL", "a missing column renders as NULL")
	assert.NotContains(t, got, "hidden", "only the named columns are shown")
}

func TestRenderRows(t *testing.T) {
	t.Parallel()
	res := &targetintel.Result{
		Schema: []targetintel.Column{{Name: "ip"}, {Name: "port"}, {Name: "banner"}},
		Rows:   []map[string]any{{"ip": "1.2.3.4", "port": int64(22), "banner": "SSH-2.0"}},
	}

	t.Run("every column", func(t *testing.T) {
		t.Parallel()
		cmd, out, _ := bufCmd(t)
		require.NoError(t, renderRows(cmd, res, nil))
		assert.Contains(t, out.String(), "banner")
		assert.Contains(t, out.String(), "SSH-2.0")
		assert.NotContains(t, out.String(), "Showing")
	})

	t.Run("selected columns", func(t *testing.T) {
		t.Parallel()
		cmd, out, _ := bufCmd(t)
		require.NoError(t, renderRows(cmd, res, []string{"ip", "port"}))
		assert.Contains(t, out.String(), "1.2.3.4")
		assert.NotContains(t, out.String(), "SSH-2.0")
		assert.Contains(t, out.String(), "Showing 2 of 3 columns; use --json for every field")
	})
}

func TestCredentialSourceLabel(t *testing.T) {
	t.Parallel()
	tests := []struct {
		c    targetintel.Credentials
		want string
	}{
		{c: targetintel.Credentials{Source: targetintel.SourceEnv, Path: "/k.json"}, want: targetintel.EnvCredentials + " (/k.json)"},
		{c: targetintel.Credentials{Source: targetintel.SourceStored, Path: "/home/u/creds.json"}, want: "/home/u/creds.json"},
		{c: targetintel.Credentials{Source: targetintel.SourceADC}, want: "application default credentials"},
		{c: targetintel.Credentials{Source: "other"}, want: "other"},
	}
	for _, tt := range tests {
		t.Run(string(tt.c.Source), func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, credentialSourceLabel(&tt.c))
		})
	}
}

func TestGroupRunEPrintsHelp(t *testing.T) {
	t.Parallel()
	cmd := &cobra.Command{Use: "group", Short: "A group of commands", RunE: groupRunE}
	cmd.AddCommand(&cobra.Command{Use: "child", Short: "The child", Run: func(*cobra.Command, []string) {}})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{})
	require.NoError(t, cmd.ExecuteContext(t.Context()))
	assert.Contains(t, out.String(), "Usage:")
	assert.Contains(t, out.String(), "child")
}

func TestCountNoun(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "0 tables", countNoun(0, "table"))
	assert.Equal(t, "1 table", countNoun(1, "table"))
	assert.Equal(t, "2 datasets", countNoun(2, "dataset"))
}
