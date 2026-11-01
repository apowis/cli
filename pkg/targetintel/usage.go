package targetintel

import (
	"bufio"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/vulncheck-oss/cli/pkg/config"
)

// UsageRetentionMonths is how many whole months of usage the local log keeps
// before the current one, so any 365-day window is always covered.
const UsageRetentionMonths = 12

// UsageRecord is one billed query in the local usage log.
type UsageRecord struct {
	// Time is when the job finished, in Unix seconds.
	Time        int64   `json:"ts"`
	CostUSD     float64 `json:"cost_usd"`
	BytesBilled int64   `json:"bytes_billed"`
	CacheHit    bool    `json:"cache_hit"`
	Command     string  `json:"command,omitempty"`
	Project     string  `json:"project,omitempty"`
	JobID       string  `json:"job_id,omitempty"`
}

// UsageLog is the append-only record of every query this CLI ran on this
// machine. It is one JSON Lines file per UTC month, so appends never rewrite
// anything and expiry deletes whole files: two queries finishing at once
// cannot lose each other's line.
type UsageLog struct {
	Dir string
}

// DefaultUsageLog returns the log under the CLI's config directory.
func DefaultUsageLog() (*UsageLog, error) {
	dir, err := config.Dir()
	if err != nil {
		return nil, err
	}
	if dir == "" {
		return nil, errors.New("no home directory to keep the usage log in")
	}

	return &UsageLog{Dir: filepath.Join(dir, "target-intel", "usage")}, nil
}

const monthLayout = "2006-01"

var monthFileName = regexp.MustCompile(`^(\d{4}-\d{2})\.jsonl$`)

func monthStartUTC(t time.Time) time.Time {
	t = t.UTC()

	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
}

func (l *UsageLog) monthPath(month time.Time) string {
	return filepath.Join(l.Dir, month.Format(monthLayout)+".jsonl")
}

// Append adds rec to its month's file and then drops months older than the
// retention window.
func (l *UsageLog) Append(rec UsageRecord) error {
	if err := os.MkdirAll(l.Dir, 0o700); err != nil {
		return fmt.Errorf("create usage log directory: %w", err)
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("encode usage record: %w", err)
	}
	line = append(line, '\n')
	at := time.Unix(rec.Time, 0)
	// One write of a short line to an O_APPEND file lands whole, so
	// concurrent CLI processes do not interleave records.
	f, err := os.OpenFile(l.monthPath(monthStartUTC(at)), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open usage log: %w", err)
	}
	_, werr := f.Write(line)
	cerr := f.Close()
	if werr != nil {
		return fmt.Errorf("write usage log: %w", werr)
	}
	if cerr != nil {
		return fmt.Errorf("write usage log: %w", cerr)
	}

	return l.Prune(at)
}

// Prune deletes month files older than UsageRetentionMonths before now's
// month. A file another process already removed is not an error.
func (l *UsageLog) Prune(now time.Time) error {
	entries, err := os.ReadDir(l.Dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}

		return fmt.Errorf("read usage log directory: %w", err)
	}
	cutoff := monthStartUTC(now).AddDate(0, -UsageRetentionMonths, 0)
	var errs []error
	for _, e := range entries {
		m := monthFileName.FindStringSubmatch(e.Name())
		if m == nil || e.IsDir() {
			continue
		}
		month, err := time.Parse(monthLayout, m[1])
		if err != nil || !month.Before(cutoff) {
			continue
		}
		if err := os.Remove(filepath.Join(l.Dir, e.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("expire usage log: %w", err))
		}
	}

	return errors.Join(errs...)
}

// Records returns the records with from <= time < to, oldest first. Lines
// that do not parse (a torn write, a hand edit) are skipped rather than
// failing the whole report.
func (l *UsageLog) Records(from, to time.Time) ([]UsageRecord, error) {
	var out []UsageRecord
	if !from.Before(to) {
		return out, nil
	}
	lo, hi := from.Unix(), to.Unix()
	for month := monthStartUTC(from); month.Before(to); month = month.AddDate(0, 1, 0) {
		recs, err := readMonth(l.monthPath(month))
		if err != nil {
			return nil, err
		}
		for _, r := range recs {
			if r.Time >= lo && r.Time < hi {
				out = append(out, r)
			}
		}
	}
	slices.SortStableFunc(out, func(a, b UsageRecord) int { return cmp.Compare(a.Time, b.Time) })

	return out, nil
}

func readMonth(path string) ([]UsageRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}

		return nil, fmt.Errorf("read usage log: %w", err)
	}
	defer func() { _ = f.Close() }()

	var recs []UsageRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		var r UsageRecord
		if json.Unmarshal(sc.Bytes(), &r) == nil && r.Time > 0 {
			recs = append(recs, r)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read usage log: %w", err)
	}

	return recs, nil
}

// UsageTotals sums a set of records.
type UsageTotals struct {
	Queries     int     `json:"queries"`
	CacheHits   int     `json:"cache_hits"`
	BytesBilled int64   `json:"bytes_billed"`
	CostUSD     float64 `json:"cost_usd"`
}

func (t *UsageTotals) add(r UsageRecord) {
	t.Queries++
	if r.CacheHit {
		t.CacheHits++
	}
	t.BytesBilled += r.BytesBilled
	t.CostUSD += r.CostUSD
}

// SumUsage totals recs.
func SumUsage(recs []UsageRecord) UsageTotals {
	var t UsageTotals
	for _, r := range recs {
		t.add(r)
	}

	return t
}

// Usage bucket sizes accepted by BucketUsage.
const (
	ByDay   = "day"
	ByWeek  = "week"
	ByMonth = "month"
)

// UsageBucket is the totals for one day, week or month.
type UsageBucket struct {
	Start time.Time `json:"start"`
	UsageTotals
}

// BucketUsage splits recs into consecutive buckets of size by, in the
// location of from, covering from up to the bucket holding the earlier of to
// and now. Empty buckets are kept so a gap reads as zero, not as missing.
func BucketUsage(recs []UsageRecord, from, to, now time.Time, by string) ([]UsageBucket, error) {
	var start func(time.Time) time.Time
	var next func(time.Time) time.Time
	switch by {
	case ByDay:
		start, next = StartOfDay, func(t time.Time) time.Time { return t.AddDate(0, 0, 1) }
	case ByWeek:
		start, next = StartOfWeek, func(t time.Time) time.Time { return t.AddDate(0, 0, 7) }
	case ByMonth:
		start, next = StartOfMonth, func(t time.Time) time.Time { return t.AddDate(0, 1, 0) }
	default:
		return nil, fmt.Errorf("unknown bucket %q", by)
	}
	end := to
	if now.Before(end) {
		end = now
	}
	var buckets []UsageBucket
	for b := start(from); !b.After(end) && b.Before(to); b = next(b) {
		buckets = append(buckets, UsageBucket{Start: b})
	}
	for _, r := range recs {
		at := time.Unix(r.Time, 0).In(from.Location())
		// Buckets are sorted, so the last one starting at or before the
		// record holds it.
		i, found := slices.BinarySearchFunc(buckets, at, func(b UsageBucket, t time.Time) int { return b.Start.Compare(t) })
		if !found {
			i--
		}
		if i >= 0 && i < len(buckets) {
			buckets[i].add(r)
		}
	}

	return buckets, nil
}

// StartOfDay is local midnight on t's date.
func StartOfDay(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
}

// StartOfWeek is midnight on the Monday of t's week (ISO 8601 weeks).
func StartOfWeek(t time.Time) time.Time {
	back := (int(t.Weekday()) + 6) % 7

	return StartOfDay(t).AddDate(0, 0, -back)
}

// StartOfMonth is midnight on the first of t's month.
func StartOfMonth(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, t.Location())
}

// StartOfYear is midnight on 1 January of t's year.
func StartOfYear(t time.Time) time.Time {
	return time.Date(t.Year(), time.January, 1, 0, 0, 0, 0, t.Location())
}

var relativeSince = regexp.MustCompile(`^([1-9][0-9]{0,3})([dw])$`)

// ParseSince reads a period start: a date (YYYY-MM-DD, midnight in now's
// location) or a count of days or weeks ("7d", "2w") meaning today plus the
// days before it, so "1d" is today and "7d" is the last seven calendar days.
func ParseSince(s string, now time.Time) (time.Time, error) {
	if m := relativeSince.FindStringSubmatch(s); m != nil {
		n, _ := strconv.Atoi(m[1])
		if m[2] == "w" {
			n *= 7
		}

		return StartOfDay(now).AddDate(0, 0, -(n - 1)), nil
	}
	t, err := time.ParseInLocation(time.DateOnly, s, now.Location())
	if err != nil {
		return time.Time{}, fmt.Errorf("want a date (YYYY-MM-DD) or a count of days or weeks (7d, 2w); got %q", s)
	}

	return t, nil
}

// ParseUntil reads a period end date (YYYY-MM-DD). The day itself is
// included, so the returned bound is the following midnight.
func ParseUntil(s string, now time.Time) (time.Time, error) {
	t, err := time.ParseInLocation(time.DateOnly, s, now.Location())
	if err != nil {
		return time.Time{}, fmt.Errorf("want a date (YYYY-MM-DD); got %q", s)
	}

	return t.AddDate(0, 0, 1), nil
}
