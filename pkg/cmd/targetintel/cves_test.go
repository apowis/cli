package targetintel

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMissingCVEs(t *testing.T) {
	ids := []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"}
	rows := []map[string]any{
		{"cve_id": "CVE-2024-0002", "hosts": int64(5)},
		{"cve_id": int64(7)},
		{"hosts": int64(1)},
	}

	assert.Equal(t, []string{"CVE-2024-0001", "CVE-2024-0003"}, missingCVEs(ids, rows))
	assert.Equal(t, []string{}, missingCVEs(nil, rows), "never nil, so JSON renders []")
	assert.Equal(t, ids, missingCVEs(ids, nil))
	assert.Equal(t, []string{}, missingCVEs(ids[:1], []map[string]any{{"cve_id": "CVE-2024-0001"}}))
}
