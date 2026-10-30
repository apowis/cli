package targetintel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"cloud.google.com/go/bigquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/option"
)

// fakeJobs is a minimal BigQuery jobs API: inserted jobs stay RUNNING
// forever, so only a cancelled context ends Run.
type fakeJobs struct {
	mu        sync.Mutex
	inserted  string
	cancelled []string
	// onInsert runs once the inserted job ID is recorded, before replying.
	onInsert func(r *http.Request)
}

func (f *fakeJobs) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodPost && parts[len(parts)-1] == "jobs":
		var body struct {
			JobReference struct {
				JobID string `json:"jobId"`
			} `json:"jobReference"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.inserted = body.JobReference.JobID
		f.mu.Unlock()
		if f.onInsert != nil {
			f.onInsert(r)
		}
		writeRunningJob(w, body.JobReference.JobID)
	case r.Method == http.MethodPost && parts[len(parts)-1] == "cancel":
		f.mu.Lock()
		f.cancelled = append(f.cancelled, parts[len(parts)-2])
		f.mu.Unlock()
		_, _ = w.Write([]byte(`{}`))
	case len(parts) >= 2 && parts[len(parts)-2] == "queries":
		_, _ = w.Write([]byte(`{"jobComplete": false}`))
	case len(parts) >= 2 && parts[len(parts)-2] == "jobs":
		writeRunningJob(w, parts[len(parts)-1])
	default:
		http.NotFound(w, r)
	}
}

func writeRunningJob(w http.ResponseWriter, id string) {
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jobReference":  map[string]string{"projectId": "p", "jobId": id, "location": "US"},
		"configuration": map[string]any{"query": map[string]any{"query": "SELECT 1"}},
		"status":        map[string]string{"state": "RUNNING"},
	})
}

func newFakeClient(t *testing.T, f *fakeJobs) *Client {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	bq, err := bigquery.NewClient(t.Context(), "p",
		option.WithEndpoint(srv.URL+"/"),
		option.WithoutAuthentication(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = bq.Close() })
	bq.Location = "US"

	return &Client{BQ: bq, Settings: Settings{Project: "p", Location: "US"}}
}

func TestRunCancelsJobWhileWaiting(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	f := &fakeJobs{}
	// Cancel once the job exists, so Run is past the insert and in Wait.
	f.onInsert = func(*http.Request) { go cancel() }
	c := newFakeClient(t, f)

	_, err := c.Run(ctx, QueryOptions{SQL: "SELECT 1"})
	require.Error(t, err)

	// The cancel must have reached the server before Run returned.
	f.mu.Lock()
	defer f.mu.Unlock()
	require.NotEmpty(t, f.inserted)
	assert.True(t, strings.HasPrefix(f.inserted, "vulncheck_cli_"))
	assert.Equal(t, []string{f.inserted}, f.cancelled)
}

func TestRunCancelsJobWhenInsertInterrupted(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	f := &fakeJobs{}
	// The server creates the job but the client gives up before the reply.
	f.onInsert = func(r *http.Request) {
		cancel()
		<-r.Context().Done()
	}
	c := newFakeClient(t, f)

	_, err := c.Run(ctx, QueryOptions{SQL: "SELECT 1"})
	require.Error(t, err)

	f.mu.Lock()
	defer f.mu.Unlock()
	require.NotEmpty(t, f.inserted)
	assert.Equal(t, []string{f.inserted}, f.cancelled)
}
