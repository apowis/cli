// Package bqfake is an in-process fake of the BigQuery REST API for tests.
//
// It serves the requests the cloud.google.com/go/bigquery client makes for a
// query job (jobs.insert, jobs.getQueryResults, jobs.get, jobs.cancel) and
// for metadata (datasets.list/get, tables.list/get). Results are configured
// per test; every inserted job is recorded so tests can assert on the job
// configuration the client sent. A request the fake does not recognise fails
// the test, so a client library upgrade that changes its request pattern is
// caught rather than silently answered with a 404.
package bqfake

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/bigquery"
	"github.com/stretchr/testify/require"
	bq "google.golang.org/api/bigquery/v2"
	"google.golang.org/api/option"
)

// Field is one column of a result or table schema. Mode is NULLABLE (the
// default when empty), REQUIRED or REPEATED; Fields holds the sub-fields of
// a RECORD.
type Field struct {
	Name   string
	Type   string
	Mode   string
	Fields []Field
}

// Row is one result row keyed by column name. Scalars may be any Go value
// (they are sent as strings, as BigQuery does); a time.Time in a TIMESTAMP
// column is sent as epoch microseconds. A REPEATED column takes a slice and
// a RECORD column takes a map[string]any keyed by sub-field name. A missing
// key or nil value is NULL (an empty array for a REPEATED column).
type Row map[string]any

// Stats are the job statistics reported for a query.
type Stats struct {
	TotalBytesBilled    int64
	TotalBytesProcessed int64
	CacheHit            bool
	// StatementType defaults to SELECT.
	StatementType string
}

// JobError makes the job fail with this reason and message, for example
// reason "bytesBilledLimitExceeded".
type JobError struct {
	Reason  string
	Message string
	// StatusOnly reports the failure only on the job resource (jobs.get
	// status.errorResult) and lets getQueryResults report completion. By
	// default getQueryResults returns the error as HTTP 400, as BigQuery
	// does for a failed job.
	StatusOnly bool
}

// Query is the outcome of every job the fake runs.
type Query struct {
	Schema []Field
	Rows   []Row
	// TotalRows is reported as the result's total row count. Zero means
	// len(Rows).
	TotalRows uint64
	// PageSize caps the rows per page when the client does not ask for
	// fewer. Zero serves everything in one page.
	PageSize int
	Stats    Stats
	Err      *JobError
	// NeverComplete leaves the job RUNNING forever, so only a cancelled
	// context ends the caller's wait.
	NeverComplete bool
}

// Table is the metadata served for tables.get.
type Table struct {
	// Type defaults to TABLE.
	Type        string
	Description string
	NumRows     uint64
	NumBytes    int64
	Schema      []Field
	// TimePartitioningType (DAY, HOUR, ...) enables time partitioning on
	// TimePartitioningField; an empty field means ingestion time.
	TimePartitioningType  string
	TimePartitioningField string
	// RangePartitioningField enables integer range partitioning.
	RangePartitioningField string
	ClusteringFields       []string
	Created                time.Time
	LastModified           time.Time
}

// Request is one request the fake received.
type Request struct {
	Method string
	Path   string
	Query  url.Values
	Body   []byte
}

type tableKey struct{ project, dataset, table string }

// Server is a running fake. Configure it with the setters before or between
// client calls; they are safe for concurrent use.
type Server struct {
	// URL is the server's base URL, for option.WithEndpoint.
	URL string

	t   testing.TB
	srv *httptest.Server

	mu        sync.Mutex
	query     Query
	handler   func(*bq.Job) Query
	onInsert  func(*http.Request, *bq.Job)
	jobs      map[string]*bq.Job
	results   map[string]Query
	inserted  []*bq.Job
	cancelled []string
	requests  []Request
	datasets  map[string][]string
	tables    map[tableKey]Table
	tableIDs  map[[2]string][]string
}

// New starts a fake that is closed when the test ends.
func New(t testing.TB) *Server {
	t.Helper()
	s := &Server{
		t:        t,
		jobs:     map[string]*bq.Job{},
		results:  map[string]Query{},
		datasets: map[string][]string{},
		tables:   map[tableKey]Table{},
		tableIDs: map[[2]string][]string{},
	}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	s.URL = s.srv.URL
	t.Cleanup(s.srv.Close)

	return s
}

// ClientOptions point a bigquery client at the fake without credentials.
func (s *Server) ClientOptions() []option.ClientOption {
	return []option.ClientOption{
		option.WithEndpoint(s.URL + "/"),
		option.WithoutAuthentication(),
	}
}

// NewClient opens a bigquery client for project against the fake, closed
// when the test ends. Its default location is US.
func (s *Server) NewClient(project string) *bigquery.Client {
	s.t.Helper()
	c, err := bigquery.NewClient(s.t.Context(), project, s.ClientOptions()...)
	require.NoError(s.t, err)
	s.t.Cleanup(func() { _ = c.Close() })
	c.Location = "US"

	return c
}

// SetQuery sets the outcome of every job inserted from now on.
func (s *Server) SetQuery(q Query) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.query = q
	s.handler = nil
}

// HandleQuery chooses each job's outcome from the inserted job, for tests
// that run several different queries. It replaces SetQuery.
func (s *Server) HandleQuery(fn func(job *bq.Job) Query) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handler = fn
}

// OnInsert runs fn for every jobs.insert after the job is recorded and before
// the reply is written. fn may block, for example on r.Context().Done().
func (s *Server) OnInsert(fn func(r *http.Request, job *bq.Job)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onInsert = fn
}

// AddDataset makes dataset appear in project's dataset list.
func (s *Server) AddDataset(project, dataset string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.datasets[project] = append(s.datasets[project], dataset)
}

// AddTable makes the table appear in its dataset's table list and serves t
// for tables.get. The dataset is added if missing.
func (s *Server) AddTable(project, dataset, table string, t Table) {
	s.mu.Lock()
	defer s.mu.Unlock()
	found := false
	for _, d := range s.datasets[project] {
		found = found || d == dataset
	}
	if !found {
		s.datasets[project] = append(s.datasets[project], dataset)
	}
	k := [2]string{project, dataset}
	s.tableIDs[k] = append(s.tableIDs[k], table)
	s.tables[tableKey{project, dataset, table}] = t
}

// Jobs returns the decoded bodies of every jobs.insert, in order.
func (s *Server) Jobs() []*bq.Job {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]*bq.Job(nil), s.inserted...)
}

// LastJob returns the most recent inserted job, failing the test if none.
func (s *Server) LastJob() *bq.Job {
	s.t.Helper()
	jobs := s.Jobs()
	require.NotEmpty(s.t, jobs, "no job was inserted")

	return jobs[len(jobs)-1]
}

// Cancelled returns the IDs of jobs cancelled through jobs.cancel.
func (s *Server) Cancelled() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]string(nil), s.cancelled...)
}

// Requests returns every request received, in order.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]Request(nil), s.requests...)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	path := strings.TrimPrefix(strings.Trim(r.URL.Path, "/"), "bigquery/v2/")
	s.mu.Lock()
	s.requests = append(s.requests, Request{Method: r.Method, Path: path, Query: r.URL.Query(), Body: body})
	s.mu.Unlock()

	p := strings.Split(path, "/")
	if len(p) < 3 || p[0] != "projects" {
		s.unknown(w, r)

		return
	}
	project := p[1]
	switch {
	case r.Method == http.MethodPost && len(p) == 3 && p[2] == "jobs":
		s.insert(w, r, project, body)
	case r.Method == http.MethodGet && len(p) == 4 && p[2] == "jobs":
		s.getJob(w, p[3])
	case r.Method == http.MethodPost && len(p) == 5 && p[2] == "jobs" && p[4] == "cancel":
		s.cancel(w, p[3])
	case r.Method == http.MethodGet && len(p) == 4 && p[2] == "queries":
		s.queryResults(w, r, p[3])
	case r.Method == http.MethodGet && len(p) == 3 && p[2] == "datasets":
		s.listDatasets(w, project)
	case r.Method == http.MethodGet && len(p) == 4 && p[2] == "datasets":
		s.getDataset(w, project, p[3])
	case r.Method == http.MethodGet && len(p) == 5 && p[2] == "datasets" && p[4] == "tables":
		s.listTables(w, project, p[3])
	case r.Method == http.MethodGet && len(p) == 6 && p[2] == "datasets" && p[4] == "tables":
		s.getTable(w, project, p[3], p[5])
	default:
		s.unknown(w, r)
	}
}

func (s *Server) unknown(w http.ResponseWriter, r *http.Request) {
	s.t.Errorf("bqfake: unexpected request %s %s", r.Method, r.URL.String())
	writeError(w, http.StatusNotImplemented, "notImplemented", "bqfake does not serve "+r.URL.Path)
}

func (s *Server) insert(w http.ResponseWriter, r *http.Request, project string, body []byte) {
	var job bq.Job
	if err := json.Unmarshal(body, &job); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())

		return
	}
	if job.JobReference == nil {
		job.JobReference = &bq.JobReference{}
	}
	if job.JobReference.JobId == "" {
		job.JobReference.JobId = fmt.Sprintf("bqfake_job_%d", len(s.Jobs())+1)
	}
	if job.JobReference.ProjectId == "" {
		job.JobReference.ProjectId = project
	}
	id := job.JobReference.JobId

	s.mu.Lock()
	recorded := job
	s.inserted = append(s.inserted, &recorded)
	q := s.query
	if s.handler != nil {
		h := s.handler
		s.mu.Unlock()
		q = h(&recorded)
		s.mu.Lock()
	}
	dry := job.Configuration != nil && job.Configuration.DryRun
	if !dry {
		s.jobs[id] = &job
		s.results[id] = q
	}
	onInsert := s.onInsert
	s.mu.Unlock()

	if onInsert != nil {
		onInsert(r, &recorded)
	}
	if dry && q.Err != nil {
		writeError(w, http.StatusBadRequest, q.Err.Reason, q.Err.Message)

		return
	}
	state := "RUNNING"
	if dry {
		state = "DONE"
	}
	writeJSON(w, jobResource(&job, q, state))
}

func (s *Server) lookup(id string) (*bq.Job, Query, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[id]

	return job, s.results[id], ok
}

func (s *Server) getJob(w http.ResponseWriter, id string) {
	job, q, ok := s.lookup(id)
	if !ok {
		writeError(w, http.StatusNotFound, "notFound", "Not found: Job "+id)

		return
	}
	state := "DONE"
	if q.NeverComplete {
		state = "RUNNING"
	}
	writeJSON(w, jobResource(job, q, state))
}

func (s *Server) cancel(w http.ResponseWriter, id string) {
	job, q, ok := s.lookup(id)
	if !ok {
		writeError(w, http.StatusNotFound, "notFound", "Not found: Job "+id)

		return
	}
	s.mu.Lock()
	s.cancelled = append(s.cancelled, id)
	s.mu.Unlock()
	writeJSON(w, &bq.JobCancelResponse{Job: jobResource(job, q, "DONE")})
}

func (s *Server) queryResults(w http.ResponseWriter, r *http.Request, id string) {
	job, q, ok := s.lookup(id)
	if !ok {
		writeError(w, http.StatusNotFound, "notFound", "Not found: Job "+id)

		return
	}
	if q.NeverComplete {
		writeJSON(w, &bq.GetQueryResultsResponse{JobReference: job.JobReference})

		return
	}
	if q.Err != nil && !q.Err.StatusOnly {
		writeError(w, http.StatusBadRequest, q.Err.Reason, q.Err.Message)

		return
	}

	start := 0
	if tok := r.URL.Query().Get("pageToken"); tok != "" {
		start, _ = strconv.Atoi(tok)
	} else if si := r.URL.Query().Get("startIndex"); si != "" {
		start, _ = strconv.Atoi(si)
	}
	size := len(q.Rows)
	if q.PageSize > 0 {
		size = q.PageSize
	}
	if mr := r.URL.Query().Get("maxResults"); mr != "" {
		n, _ := strconv.Atoi(mr)
		size = min(size, n)
	}
	start = min(start, len(q.Rows))
	end := min(start+size, len(q.Rows))

	res := &bq.GetQueryResultsResponse{
		JobComplete:  true,
		JobReference: job.JobReference,
		Schema:       toSchema(q.Schema),
		TotalRows:    totalRows(q),
	}
	for _, row := range q.Rows[start:end] {
		res.Rows = append(res.Rows, encodeRow(q.Schema, row))
	}
	if end < len(q.Rows) && size > 0 {
		res.PageToken = strconv.Itoa(end)
	}
	writeJSON(w, res)
}

func (s *Server) listDatasets(w http.ResponseWriter, project string) {
	s.mu.Lock()
	ids := append([]string(nil), s.datasets[project]...)
	s.mu.Unlock()
	res := &bq.DatasetList{}
	for _, id := range ids {
		res.Datasets = append(res.Datasets, &bq.DatasetListDatasets{
			Id:               project + ":" + id,
			DatasetReference: &bq.DatasetReference{ProjectId: project, DatasetId: id},
		})
	}
	writeJSON(w, res)
}

func (s *Server) getDataset(w http.ResponseWriter, project, dataset string) {
	s.mu.Lock()
	var found bool
	for _, id := range s.datasets[project] {
		found = found || id == dataset
	}
	s.mu.Unlock()
	if !found {
		writeError(w, http.StatusNotFound, "notFound", "Not found: Dataset "+project+":"+dataset)

		return
	}
	writeJSON(w, &bq.Dataset{
		Id:               project + ":" + dataset,
		DatasetReference: &bq.DatasetReference{ProjectId: project, DatasetId: dataset},
		Location:         "US",
	})
}

func (s *Server) listTables(w http.ResponseWriter, project, dataset string) {
	s.mu.Lock()
	ids := append([]string(nil), s.tableIDs[[2]string{project, dataset}]...)
	s.mu.Unlock()
	res := &bq.TableList{}
	for _, id := range ids {
		res.Tables = append(res.Tables, &bq.TableListTables{
			Id:             project + ":" + dataset + "." + id,
			TableReference: &bq.TableReference{ProjectId: project, DatasetId: dataset, TableId: id},
		})
	}
	writeJSON(w, res)
}

func (s *Server) getTable(w http.ResponseWriter, project, dataset, table string) {
	s.mu.Lock()
	t, ok := s.tables[tableKey{project, dataset, table}]
	s.mu.Unlock()
	if !ok {
		writeError(w, http.StatusNotFound, "notFound", "Not found: Table "+project+":"+dataset+"."+table)

		return
	}
	typ := t.Type
	if typ == "" {
		typ = "TABLE"
	}
	res := &bq.Table{
		Id:               project + ":" + dataset + "." + table,
		TableReference:   &bq.TableReference{ProjectId: project, DatasetId: dataset, TableId: table},
		Type:             typ,
		Description:      t.Description,
		NumRows:          t.NumRows,
		NumBytes:         t.NumBytes,
		Schema:           toSchema(t.Schema),
		CreationTime:     t.Created.UnixMilli(),
		LastModifiedTime: uint64(t.LastModified.UnixMilli()), //nolint:gosec // test fixture times are positive
	}
	if t.TimePartitioningType != "" {
		res.TimePartitioning = &bq.TimePartitioning{Type: t.TimePartitioningType, Field: t.TimePartitioningField}
	}
	if t.RangePartitioningField != "" {
		res.RangePartitioning = &bq.RangePartitioning{
			Field: t.RangePartitioningField,
			Range: &bq.RangePartitioningRange{Start: 0, End: 100, Interval: 10},
		}
	}
	if len(t.ClusteringFields) > 0 {
		res.Clustering = &bq.Clustering{Fields: t.ClusteringFields}
	}
	writeJSON(w, res)
}

func totalRows(q Query) uint64 {
	if q.TotalRows > 0 {
		return q.TotalRows
	}

	return uint64(len(q.Rows))
}

// jobResource renders a job as BigQuery returns it, echoing the inserted
// configuration so the client recognises it as a query job.
func jobResource(job *bq.Job, q Query, state string) *bq.Job {
	stmt := q.Stats.StatementType
	if stmt == "" {
		stmt = "SELECT"
	}
	out := &bq.Job{
		Id:            job.JobReference.ProjectId + ":" + job.JobReference.Location + "." + job.JobReference.JobId,
		JobReference:  job.JobReference,
		Configuration: job.Configuration,
		Status:        &bq.JobStatus{State: state},
		Statistics: &bq.JobStatistics{
			TotalBytesProcessed: q.Stats.TotalBytesProcessed,
			Query: &bq.JobStatistics2{
				TotalBytesBilled:    q.Stats.TotalBytesBilled,
				TotalBytesProcessed: q.Stats.TotalBytesProcessed,
				CacheHit:            q.Stats.CacheHit,
				StatementType:       stmt,
			},
		},
	}
	if state == "DONE" && q.Err != nil {
		e := &bq.ErrorProto{Reason: q.Err.Reason, Message: q.Err.Message}
		out.Status.ErrorResult = e
		out.Status.Errors = []*bq.ErrorProto{e}
	}

	return out
}

func toSchema(fields []Field) *bq.TableSchema {
	if fields == nil {
		return nil
	}

	return &bq.TableSchema{Fields: toFields(fields)}
}

func toFields(fields []Field) []*bq.TableFieldSchema {
	out := make([]*bq.TableFieldSchema, 0, len(fields))
	for _, f := range fields {
		mode := f.Mode
		if mode == "" {
			mode = "NULLABLE"
		}
		out = append(out, &bq.TableFieldSchema{Name: f.Name, Type: f.Type, Mode: mode, Fields: toFields(f.Fields)})
	}

	return out
}

func encodeRow(fields []Field, row map[string]any) *bq.TableRow {
	out := &bq.TableRow{}
	for _, f := range fields {
		out.F = append(out.F, &bq.TableCell{V: encodeField(f, row[f.Name])})
	}

	return out
}

func encodeField(f Field, v any) any {
	if f.Mode == "REPEATED" {
		// BigQuery has no NULL array: a missing one is sent empty.
		if v == nil {
			return []any{}
		}
		rv := reflect.ValueOf(v)
		if rv.Kind() != reflect.Slice {
			panic(fmt.Sprintf("bqfake: REPEATED column %q needs a slice, got %T", f.Name, v))
		}
		arr := make([]any, 0, rv.Len())
		for i := range rv.Len() {
			arr = append(arr, map[string]any{"v": encodeScalar(f, rv.Index(i).Interface())})
		}

		return arr
	}
	if v == nil {
		return nil
	}

	return encodeScalar(f, v)
}

func encodeScalar(f Field, v any) any {
	if v == nil {
		return nil
	}
	switch f.Type {
	case "RECORD", "STRUCT":
		m, ok := v.(map[string]any)
		if !ok {
			if r, isRow := v.(Row); isRow {
				m = r
			} else {
				panic(fmt.Sprintf("bqfake: RECORD column %q needs a map[string]any, got %T", f.Name, v))
			}
		}

		return encodeRow(f.Fields, m)
	case "TIMESTAMP":
		if t, ok := v.(time.Time); ok {
			return strconv.FormatInt(t.UnixMicro(), 10)
		}
	}
	if b, ok := v.([]byte); ok {
		return string(b)
	}

	return fmt.Sprint(v)
}

func writeJSON(w http.ResponseWriter, v any) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		writeError(w, http.StatusInternalServerError, "internalError", err.Error())

		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(buf.Bytes())
}

func writeError(w http.ResponseWriter, code int, reason, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": message,
			"errors":  []map[string]string{{"reason": reason, "message": message, "domain": "global"}},
		},
	})
}
