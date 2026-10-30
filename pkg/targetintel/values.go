package targetintel

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"time"

	"cloud.google.com/go/bigquery"
	"cloud.google.com/go/civil"
)

// toJSONRow converts a BigQuery row into values encoding/json can emit:
// timestamps as RFC 3339, bytes as base64, numerics as decimal strings,
// records as objects and repeated fields as arrays.
func toJSONRow(row map[string]bigquery.Value) map[string]any {
	out := make(map[string]any, len(row))
	for k, v := range row {
		out[k] = toJSONValue(v)
	}

	return out
}

func toJSONValue(v bigquery.Value) any {
	switch x := v.(type) {
	case nil:
		return nil
	case time.Time:
		return x.UTC().Format(time.RFC3339Nano)
	case []byte:
		return base64.StdEncoding.EncodeToString(x)
	case *big.Rat:
		return x.FloatString(9)
	case civil.Date, civil.Time, civil.DateTime:
		return fmt.Sprint(x)
	case map[string]bigquery.Value:
		return toJSONRow(x)
	case []bigquery.Value:
		arr := make([]any, 0, len(x))
		for _, e := range x {
			arr = append(arr, toJSONValue(e))
		}

		return arr
	case float64:
		// encoding/json cannot encode NaN or an infinity, so emit them
		// the way BigQuery spells them.
		switch {
		case math.IsNaN(x):
			return "NaN"
		case math.IsInf(x, 1):
			return "Infinity"
		case math.IsInf(x, -1):
			return "-Infinity"
		}

		return x
	case string, int64, bool:
		return x
	default:
		return fmt.Sprint(x)
	}
}

// CellString renders a converted value for a text table. Arrays and records
// are shown as JSON so they read the same as in --json output.
func CellString(v any) string {
	switch x := v.(type) {
	case nil:
		return "NULL"
	case string:
		return x
	case []any, map[string]any:
		if b, err := json.Marshal(x); err == nil {
			return string(b)
		}

		return fmt.Sprint(x)
	default:
		return fmt.Sprint(x)
	}
}
