package report

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseEPSS(t *testing.T) {
	input := `{
		"model_version": "v2023.03.01",
		"score_date": "2026-04-04",
		"scores": {
			"CVE-2021-44228": 0.975,
			"CVE-2022-32149": 0.42
		}
	}`

	data, err := ParseEPSS(strings.NewReader(input))
	require.NoError(t, err)
	assert.Equal(t, "v2023.03.01", data.ModelVersion)
	assert.Equal(t, "2026-04-04", data.ScoreDate)
	assert.InDelta(t, 0.975, data.Scores["CVE-2021-44228"], 0.001)
	assert.InDelta(t, 0.42, data.Scores["CVE-2022-32149"], 0.001)
}

func TestParseEPSS_Empty(t *testing.T) {
	input := `{"model_version": "v1", "score_date": "2026-01-01", "scores": {}}`
	data, err := ParseEPSS(strings.NewReader(input))
	require.NoError(t, err)
	assert.Empty(t, data.Scores)
}

func TestParseEPSS_InvalidJSON(t *testing.T) {
	_, err := ParseEPSS(strings.NewReader("not json"))
	require.Error(t, err)
}

func TestLoadEPSS_FromFile(t *testing.T) {
	// Use the real EPSS fixture from integration tests (created in Task 10)
	// For now test with nil path returns nil
	data, err := LoadEPSS("")
	require.NoError(t, err)
	assert.Nil(t, data)
}
