package targetintel

import (
	"context"

	"cloud.google.com/go/bigquery"
	"google.golang.org/api/option"

	"github.com/vulncheck-oss/cli/internal/build"
)

// Client wraps a BigQuery client with the resolved settings and credential.
type Client struct {
	BQ          *bigquery.Client
	Settings    Settings
	Credentials *Credentials
}

// NewClient resolves credentials and opens a BigQuery client against the
// billing project in s.
func NewClient(ctx context.Context, s Settings) (*Client, error) {
	creds, err := ResolveCredentials(ctx)
	if err != nil {
		return nil, err
	}
	currentProjectForHint = s.Project

	bq, err := bigquery.NewClient(ctx, s.Project,
		option.WithTokenSource(creds.TokenSource()),
		option.WithUserAgent("VulnCheck CLI "+build.Version),
	)
	if err != nil {
		return nil, classify(err)
	}
	bq.Location = s.Location

	return &Client{BQ: bq, Settings: s, Credentials: creds}, nil
}

// Close releases the underlying connection.
func (c *Client) Close() error {
	return c.BQ.Close()
}
