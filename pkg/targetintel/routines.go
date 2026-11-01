package targetintel

import (
	"context"
	"errors"
	"strings"
	"time"

	"cloud.google.com/go/bigquery"
	"google.golang.org/api/iterator"
)

// The views routines the CLI wraps in a command.
const (
	RoutineCVEs    = "observations_by_cves_scored"
	RoutineProduct = "observations_by_product"
)

// routineCommands maps a views routine to the target-intel command that
// calls it.
var routineCommands = map[string]string{
	RoutineCVEs:    "cves",
	RoutineProduct: "product",
}

// RoutineRef names a routine.
type RoutineRef struct {
	Project string
	Dataset string
	Routine string
}

// ParseRoutineRef reads [project.]dataset.routine, or a bare routine name in
// the views dataset.
func ParseRoutineRef(ref string, s Settings) (RoutineRef, error) {
	ref = strings.TrimSpace(ref)
	if ref != "" && !strings.Contains(ref, ".") {
		ref = s.ViewsDataset + "." + ref
	}
	t, err := ParseRef(ref, s.Project, true)
	if err != nil {
		return RoutineRef{}, err
	}

	return RoutineRef{Project: t.Project, Dataset: t.Dataset, Routine: t.Table}, nil
}

// Routine is one routine's summary.
type Routine struct {
	Project      string    `json:"project"`
	Dataset      string    `json:"dataset"`
	Name         string    `json:"routine"`
	Type         string    `json:"type"`
	Language     string    `json:"language,omitempty"`
	Description  string    `json:"description,omitempty"`
	LastModified time.Time `json:"last_modified"`
	// Command is the target-intel command that calls the routine, if any.
	Command string `json:"command,omitempty"`
}

// RoutineArgument is one input of a routine, or one output column of a
// table function.
type RoutineArgument struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Mode string `json:"mode,omitempty"`
}

// RoutineInfo is a routine's full signature.
type RoutineInfo struct {
	Routine
	Created       time.Time         `json:"created"`
	Arguments     []RoutineArgument `json:"arguments"`
	ReturnType    string            `json:"return_type,omitempty"`
	ReturnColumns []RoutineArgument `json:"return_columns,omitempty"`
	// Body is the routine's SQL, filled only on request.
	Body string `json:"body,omitempty"`
}

// ListRoutines lists the routines in a dataset with their type. The listing
// call returns names only, so each routine's metadata is fetched too;
// metadata reads are free.
func (c *Client) ListRoutines(ctx context.Context, ref TableRef) ([]Routine, error) {
	out := []Routine{}
	it := c.BQ.DatasetInProject(ref.Project, ref.Dataset).Routines(ctx)
	for {
		r, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, classify(err)
		}
		info, err := c.DescribeRoutine(ctx, RoutineRef{Project: r.ProjectID, Dataset: r.DatasetID, Routine: r.RoutineID}, false)
		if err != nil {
			return nil, err
		}
		out = append(out, info.Routine)
	}

	return out, nil
}

// DescribeRoutine fetches a routine's signature, with its SQL body when
// withBody is set.
func (c *Client) DescribeRoutine(ctx context.Context, ref RoutineRef, withBody bool) (*RoutineInfo, error) {
	md, err := c.BQ.DatasetInProject(ref.Project, ref.Dataset).Routine(ref.Routine).Metadata(ctx)
	if err != nil {
		return nil, classify(err)
	}
	info := &RoutineInfo{
		Routine: Routine{
			Project:      ref.Project,
			Dataset:      ref.Dataset,
			Name:         ref.Routine,
			Type:         md.Type,
			Language:     md.Language,
			Description:  md.Description,
			LastModified: md.LastModifiedTime,
		},
		Created:   md.CreationTime,
		Arguments: []RoutineArgument{},
	}
	if ref.Dataset == c.Settings.ViewsDataset {
		info.Command = routineCommands[ref.Routine]
	}
	for _, a := range md.Arguments {
		arg := RoutineArgument{Name: a.Name, Type: SQLType(a.DataType)}
		if a.Kind == "ANY_TYPE" {
			arg.Type = "ANY TYPE"
		}
		if a.Mode != "" && a.Mode != "MODE_UNSPECIFIED" {
			arg.Mode = a.Mode
		}
		info.Arguments = append(info.Arguments, arg)
	}
	if md.ReturnType != nil {
		info.ReturnType = SQLType(md.ReturnType)
	}
	if md.ReturnTableType != nil {
		for _, col := range md.ReturnTableType.Columns {
			info.ReturnColumns = append(info.ReturnColumns, RoutineArgument{Name: col.Name, Type: SQLType(col.Type)})
		}
	}
	if withBody {
		info.Body = md.Body
	}

	return info, nil
}

// SQLType renders a type the way it is written in SQL: INT64,
// ARRAY<STRING>, STRUCT<a INT64, b STRING>. An absent type is empty.
func SQLType(t *bigquery.StandardSQLDataType) string {
	if t == nil {
		return ""
	}
	switch t.TypeKind {
	case "ARRAY":
		return "ARRAY<" + SQLType(t.ArrayElementType) + ">"
	case "RANGE":
		return "RANGE<" + SQLType(t.RangeElementType) + ">"
	case "STRUCT":
		if t.StructType == nil {
			return "STRUCT"
		}
		fields := make([]string, 0, len(t.StructType.Fields))
		for _, f := range t.StructType.Fields {
			fields = append(fields, strings.TrimSpace(f.Name+" "+SQLType(f.Type)))
		}

		return "STRUCT<" + strings.Join(fields, ", ") + ">"
	default:
		return t.TypeKind
	}
}

// RoutineKind renders a routine type for people.
func RoutineKind(t string) string {
	switch t {
	case "TABLE_VALUED_FUNCTION":
		return "table function"
	case "SCALAR_FUNCTION":
		return "function"
	case "AGGREGATE_FUNCTION":
		return "aggregate function"
	case "PROCEDURE":
		return "procedure"
	default:
		return strings.ToLower(t)
	}
}
