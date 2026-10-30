package bqfake

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"cloud.google.com/go/bigquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/iterator"
)

// recordingTB captures Errorf so a test can assert the fake reported an
// unexpected request without failing itself.
type recordingTB struct {
	testing.TB
	mu   sync.Mutex
	errs []string
}

func (r *recordingTB) Errorf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errs = append(r.errs, fmt.Sprintf(format, args...))
}

func TestQueryRequestSequence(t *testing.T) {
	t.Parallel()
	s := New(t)
	s.SetQuery(Query{
		Schema:   []Field{{Name: "n", Type: "INTEGER"}, {Name: "tags", Type: "STRING", Mode: "REPEATED"}},
		Rows:     []Row{{"n": 1, "tags": []string{"a"}}, {"n": 2}, {"n": 3, "tags": []any{}}},
		PageSize: 2,
	})
	c := s.NewClient("p")
	q := c.Query("SELECT n, tags FROM t")
	q.JobIDConfig = bigquery.JobIDConfig{JobID: "job1"}
	job, err := q.Run(t.Context())
	require.NoError(t, err)
	_, err = job.Wait(t.Context())
	require.NoError(t, err)
	it, err := job.Read(t.Context())
	require.NoError(t, err)

	var got [][]bigquery.Value
	for {
		var row []bigquery.Value
		err := it.Next(&row)
		if errors.Is(err, iterator.Done) {
			break
		}
		require.NoError(t, err)
		got = append(got, row)
	}
	assert.Equal(t, [][]bigquery.Value{
		{int64(1), []bigquery.Value{"a"}},
		{int64(2), []bigquery.Value(nil)},
		{int64(3), []bigquery.Value(nil)},
	}, got)

	var paths []string
	for _, r := range s.Requests() {
		paths = append(paths, r.Method+" "+r.Path+" "+r.Query.Get("pageToken"))
	}
	assert.Equal(t, []string{
		"POST projects/p/jobs ",
		"GET projects/p/queries/job1 ", // Wait: completion check
		"GET projects/p/jobs/job1 ",    // Wait: final status
		"GET projects/p/queries/job1 ", // Read: completion check again
		"GET projects/p/queries/job1 ", // first page
		"GET projects/p/queries/job1 2",
	}, paths)
}

func TestUnknownRequestFailsTest(t *testing.T) {
	t.Parallel()
	tb := &recordingTB{TB: t}
	s := New(tb)
	c := s.NewClient("p")
	it := c.DatasetInProject("p", "ds").Table("t").Read(t.Context())
	var row []bigquery.Value
	require.Error(t, it.Next(&row))

	tb.mu.Lock()
	defer tb.mu.Unlock()
	require.NotEmpty(t, tb.errs)
	assert.Contains(t, tb.errs[0], "unexpected request GET")
}
