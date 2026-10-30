package targetintel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"

	gauth "cloud.google.com/go/auth"
	"cloud.google.com/go/bigquery"
	"golang.org/x/oauth2"
	"google.golang.org/api/googleapi"

	"github.com/vulncheck-oss/cli/internal/errs"
)

// ErrReadOnly is returned when the dry run reports anything but a SELECT.
var ErrReadOnly = errs.Validation("only SELECT statements are allowed; DML, DDL and scripts are rejected")

// CostLimitError is returned when BigQuery aborted the job because it would
// have billed more than the cap. Nothing was billed.
type CostLimitError struct {
	Estimate   Estimate
	MaxCostUSD float64
	// RequiredBytes is the bytes-billed cap BigQuery reported as sufficient,
	// zero when it did not say.
	RequiredBytes int64
	PricePerTiB   float64
}

func (e *CostLimitError) Error() string {
	return fmt.Sprintf("query exceeded max cost %s", FormatCost(e.MaxCostUSD))
}

// Classified converts the error into the CLI's structured form so it exits 7
// with the cost_limit_exceeded code and a hint that names the override.
func (e *CostLimitError) Classified() *errs.Error {
	hint := "BigQuery stopped the job before billing. Select only the columns you need, filter on the partition or cluster column"
	if e.RequiredBytes > 0 {
		hint += fmt.Sprintf(", or re-run with --max-cost %.2f to allow this query (%s billed)", ceilCost(cost(e.RequiredBytes, e.PricePerTiB)), humanBytes(e.RequiredBytes))
	} else {
		hint += ", or raise --max-cost"
	}
	if e.Estimate.BytesProcessed > 0 {
		hint += fmt.Sprintf("; the dry run estimated %s", humanBytes(e.Estimate.BytesProcessed))
	}

	return errs.Wrap(errs.KindCostLimit, e, "%s", e.Error()).WithHint("%s.", hint)
}

// bytesBilledRequired parses the cap BigQuery says the job needs from its
// "Query exceeded limit for bytes billed: X. Y or higher required." message.
var bytesBilledRequired = regexp.MustCompile(`(\d+) or higher required`)

// costLimitFromJob recognises BigQuery's bytes-billed abort and converts it
// into a CostLimitError carrying the estimate and the limit; any other error
// is returned unchanged.
func costLimitFromJob(err error, est Estimate, opts QueryOptions) error {
	var berr *bigquery.Error
	var gerr *googleapi.Error
	var msg string
	switch {
	case errors.As(err, &berr) && berr.Reason == "bytesBilledLimitExceeded":
		msg = berr.Message
	case errors.As(err, &gerr):
		for _, item := range gerr.Errors {
			if item.Reason == "bytesBilledLimitExceeded" {
				msg = item.Message
			}
		}
		if msg == "" {
			return err
		}
	default:
		return err
	}
	e := &CostLimitError{Estimate: est, MaxCostUSD: opts.MaxCostUSD, PricePerTiB: opts.PricePerTiB}
	if m := bytesBilledRequired.FindStringSubmatch(msg); m != nil {
		e.RequiredBytes, _ = strconv.ParseInt(m[1], 10, 64)
	}

	return e
}

// classify maps Google API and context errors onto the CLI's error kinds so
// every target-intel command shares one exit-code contract.
func classify(err error) error {
	if err == nil {
		return nil
	}

	var already *errs.Error
	if errors.As(err, &already) {
		return err
	}

	var cost *CostLimitError
	if errors.As(err, &cost) {
		return cost.Classified()
	}

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return errs.Wrap(errs.KindCancelled, err, "cancelled")
	}

	// url.Error wraps everything from dial failures to token-refresh
	// rejections; the inner error decides the kind.
	var uerr *url.Error
	if errors.As(err, &uerr) && uerr.Err != nil {
		if inner := classify(uerr.Err); inner != uerr.Err {
			return inner
		}
	}

	// A refresh token Google no longer accepts (revoked, expired, or a
	// reauth policy) surfaces from either OAuth library depending on the
	// call path. Both mean "log in again", not "internal error".
	var rerr *oauth2.RetrieveError
	if errors.As(err, &rerr) {
		return authInvalid(err, rerr.ErrorCode, rerr.ErrorDescription)
	}
	var aerr *gauth.Error
	if errors.As(err, &aerr) {
		code, desc := tokenErrorBody(aerr.Body)

		return authInvalid(err, code, desc)
	}

	var gerr *googleapi.Error
	if errors.As(err, &gerr) {
		msg := gerr.Message
		if msg == "" {
			msg = gerr.Error()
		}
		var e *errs.Error
		switch gerr.Code {
		case 401, 403:
			e = errs.Wrap(errs.KindAuthInvalid, err, "%s", msg).WithHint(
				"run `vulncheck target-intel auth login`, or check that the account has BigQuery access in project %q", currentProjectForHint)
		case 404:
			e = errs.Wrap(errs.KindNotFound, err, "%s", msg)
		case 429:
			e = errs.Wrap(errs.KindRateLimited, err, "%s", msg)
		case 400:
			e = errs.Wrap(errs.KindBadRequest, err, "%s", msg)
		default:
			e = errs.Wrap(errs.KindInternal, err, "%s", msg)
		}
		e.HTTPStatus = gerr.Code

		return e
	}

	return err
}

func authInvalid(cause error, code, desc string) *errs.Error {
	msg := "google credential rejected"
	switch {
	case code != "" && desc != "":
		msg += ": " + code + " (" + desc + ")"
	case code != "":
		msg += ": " + code
	case desc != "":
		msg += ": " + desc
	}
	e := errs.Wrap(errs.KindAuthInvalid, cause, "%s", msg).
		WithHint("run `vulncheck target-intel auth login` to refresh the credential")
	e.HTTPStatus = 401

	return e
}

func tokenErrorBody(body []byte) (string, string) {
	var b struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &b)

	return b.Error, b.Description
}

// currentProjectForHint is set by NewClient so auth hints can name the
// project the failing call was billed to.
var currentProjectForHint = DefaultProject

func ceilCost(usd float64) float64 {
	cents := int64(usd*100) + 1

	return float64(cents) / 100
}

func humanBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.2f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}
