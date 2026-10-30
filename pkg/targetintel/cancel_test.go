package targetintel

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bq "google.golang.org/api/bigquery/v2"

	"github.com/vulncheck-oss/cli/internal/bqfake"
)

func TestRunCancelsJobWhileWaiting(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	s := bqfake.New(t)
	// The job stays RUNNING forever, so only the cancelled context ends Run.
	s.SetQuery(bqfake.Query{NeverComplete: true})
	// Cancel once the job exists, so Run is past the insert and in Wait.
	s.OnInsert(func(*http.Request, *bq.Job) { go cancel() })
	c := fakeClient(t, s)

	_, err := c.Run(ctx, QueryOptions{SQL: "SELECT 1"})
	require.Error(t, err)

	// The cancel must have reached the server before Run returned.
	id := s.LastJob().JobReference.JobId
	assert.True(t, strings.HasPrefix(id, "vulncheck_cli_"))
	assert.Equal(t, []string{id}, s.Cancelled())
}

func TestRunCancelsJobWhenInsertInterrupted(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	s := bqfake.New(t)
	s.SetQuery(bqfake.Query{NeverComplete: true})
	// The server creates the job but the client gives up before the reply.
	s.OnInsert(func(r *http.Request, _ *bq.Job) {
		cancel()
		<-r.Context().Done()
	})
	c := fakeClient(t, s)

	_, err := c.Run(ctx, QueryOptions{SQL: "SELECT 1"})
	require.Error(t, err)

	assert.Equal(t, []string{s.LastJob().JobReference.JobId}, s.Cancelled())
}
