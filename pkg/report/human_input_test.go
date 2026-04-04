package report

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadHumanInput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "human-input.yaml")
	err := os.WriteFile(path, []byte(`
vulnerabilities:
  CVE-2021-44228:
    corrective_measure_date: "2021-12-12"
    root_cause: "Insufficient input validation in JNDI lookup functionality"
    threat_actor_info: "Multiple APT groups"
    security_update: "Log4j 2.17.0 disables JNDI by default"
    preventive_measures:
      - "Implemented input validation for all JNDI lookups"
      - "Added runtime protection against recursive lookups"
`), 0o600)
	require.NoError(t, err)

	hi, err := LoadHumanInput(path)
	require.NoError(t, err)
	require.Contains(t, hi.Vulnerabilities, "CVE-2021-44228")

	vuln := hi.Vulnerabilities["CVE-2021-44228"]
	assert.Equal(t, "2021-12-12", vuln.CorrectiveMeasureDate)
	assert.Equal(t, "Insufficient input validation in JNDI lookup functionality", vuln.RootCause)
	assert.Equal(t, "Multiple APT groups", vuln.ThreatActorInfo)
	assert.Equal(t, "Log4j 2.17.0 disables JNDI by default", vuln.SecurityUpdate)
	assert.Len(t, vuln.PreventiveMeasures, 2)
}

func TestLoadHumanInput_Empty(t *testing.T) {
	hi, err := LoadHumanInput("")
	require.NoError(t, err)
	assert.Nil(t, hi)
}
