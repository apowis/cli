package targetintel

import (
	"context"
	"errors"
	"strings"
	"time"

	"google.golang.org/api/iterator"

	"github.com/vulncheck-oss/cli/internal/errs"
)

// Dataset is one listed dataset.
type Dataset struct {
	Project string `json:"project"`
	Dataset string `json:"dataset"`
}

// ListDatasets lists the datasets in the billing project.
func (c *Client) ListDatasets(ctx context.Context) ([]Dataset, error) {
	out := []Dataset{}
	it := c.BQ.Datasets(ctx)
	for {
		ds, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, classify(err)
		}
		out = append(out, Dataset{Project: ds.ProjectID, Dataset: ds.DatasetID})
	}

	return out, nil
}

// TableRef names a table or dataset as "[project.]dataset[.table]".
type TableRef struct {
	Project string
	Dataset string
	Table   string
}

// ParseRef splits a dotted reference, defaulting the project to the billing
// project.
func ParseRef(ref, defaultProject string, wantTable bool) (TableRef, error) {
	parts := strings.Split(strings.TrimSpace(ref), ".")
	r := TableRef{Project: defaultProject}
	switch {
	case wantTable && len(parts) == 3:
		r.Project, r.Dataset, r.Table = parts[0], parts[1], parts[2]
	case wantTable && len(parts) == 2:
		r.Dataset, r.Table = parts[0], parts[1]
	case !wantTable && len(parts) == 2:
		r.Project, r.Dataset = parts[0], parts[1]
	case !wantTable && len(parts) == 1:
		r.Dataset = parts[0]
	default:
		if wantTable {
			return r, errs.Validation("expected <dataset>.<table> or <project>.<dataset>.<table>, got %q", ref)
		}

		return r, errs.Validation("expected <dataset> or <project>.<dataset>, got %q", ref)
	}
	for _, p := range []string{r.Project, r.Dataset, r.Table} {
		if wantTable || p != r.Table {
			if p == "" {
				return r, errs.Validation("empty component in reference %q", ref)
			}
		}
	}

	return r, nil
}

// Table is one listed table. The listing call does not report the table's
// type; `tables describe` does.
type Table struct {
	Project string `json:"project"`
	Dataset string `json:"dataset"`
	Table   string `json:"table"`
}

// ListTables lists the tables and views in a dataset.
func (c *Client) ListTables(ctx context.Context, ref TableRef) ([]Table, error) {
	out := []Table{}
	it := c.BQ.DatasetInProject(ref.Project, ref.Dataset).Tables(ctx)
	for {
		t, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, classify(err)
		}
		out = append(out, Table{Project: t.ProjectID, Dataset: t.DatasetID, Table: t.TableID})
	}

	return out, nil
}

// TableInfo is the subset of table metadata that matters for writing a
// cheap query: schema, size and the partition and cluster keys.
type TableInfo struct {
	Project          string    `json:"project"`
	Dataset          string    `json:"dataset"`
	Table            string    `json:"table"`
	Type             string    `json:"type"`
	Description      string    `json:"description,omitempty"`
	NumRows          uint64    `json:"num_rows"`
	NumBytes         int64     `json:"num_bytes"`
	FullScanCostUSD  float64   `json:"full_scan_cost_usd"`
	PartitionField   string    `json:"partition_field,omitempty"`
	PartitionType    string    `json:"partition_type,omitempty"`
	ClusteringFields []string  `json:"clustering_fields,omitempty"`
	Created          time.Time `json:"created"`
	LastModified     time.Time `json:"last_modified"`
	Schema           []Column  `json:"schema"`
}

// DescribeTable fetches table metadata. Metadata reads are free.
func (c *Client) DescribeTable(ctx context.Context, ref TableRef) (*TableInfo, error) {
	md, err := c.BQ.DatasetInProject(ref.Project, ref.Dataset).Table(ref.Table).Metadata(ctx)
	if err != nil {
		return nil, classify(err)
	}
	info := &TableInfo{
		Project:         ref.Project,
		Dataset:         ref.Dataset,
		Table:           ref.Table,
		Type:            string(md.Type),
		Description:     md.Description,
		NumRows:         md.NumRows,
		NumBytes:        md.NumBytes,
		FullScanCostUSD: cost(md.NumBytes, c.Settings.PricePerTiB),
		Created:         md.CreationTime,
		LastModified:    md.LastModifiedTime,
		Schema:          columns(md.Schema),
	}
	if md.TimePartitioning != nil {
		info.PartitionField = md.TimePartitioning.Field
		if info.PartitionField == "" {
			info.PartitionField = "_PARTITIONTIME"
		}
		info.PartitionType = string(md.TimePartitioning.Type)
	}
	if md.RangePartitioning != nil {
		info.PartitionField = md.RangePartitioning.Field
		info.PartitionType = "RANGE"
	}
	if md.Clustering != nil {
		info.ClusteringFields = md.Clustering.Fields
	}

	return info, nil
}
