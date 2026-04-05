// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package report

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadReportConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "product-config.yaml")
	err := os.WriteFile(path, []byte(`
product:
  name: "SUSE Linux Enterprise Server"
  version: "15-SP5"
  support_period: "2028-12-31"
  update_mechanism: "automatic"

manufacturer:
  name: "SUSE LLC"
  member_state: "DE"
  contact_email: "security@suse.com"
  website: "https://suse.com"
  member_states_available:
    - DE
    - FR
    - NL

exploitation_overrides:
  - cve: "CVE-2026-XXXX"
    source: "manual"
    reason: "Internal threat intel confirmed active exploitation"
`), 0o600)
	require.NoError(t, err)

	cfg, err := LoadReportConfig(path)
	require.NoError(t, err)

	assert.Equal(t, "SUSE Linux Enterprise Server", cfg.Product.Name)
	assert.Equal(t, "15-SP5", cfg.Product.Version)
	assert.Equal(t, "SUSE LLC", cfg.Manufacturer.Name)
	assert.Equal(t, "DE", cfg.Manufacturer.MemberState)
	assert.Equal(t, "security@suse.com", cfg.Manufacturer.ContactEmail)
	assert.Equal(t, []string{"DE", "FR", "NL"}, cfg.Manufacturer.MemberStatesAvailable)
	require.Len(t, cfg.ExploitationOverrides, 1)
	assert.Equal(t, "CVE-2026-XXXX", cfg.ExploitationOverrides[0].CVE)
	assert.Equal(t, "manual", cfg.ExploitationOverrides[0].Source)
}

func TestLoadReportConfig_MissingManufacturer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "product-config.yaml")
	err := os.WriteFile(path, []byte(`
product:
  name: "test"
  version: "1.0"
`), 0o600)
	require.NoError(t, err)

	_, err = LoadReportConfig(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "manufacturer")
}

func TestLoadReportConfig_MissingMemberState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "product-config.yaml")
	err := os.WriteFile(path, []byte(`
product:
  name: "test"
  version: "1.0"
manufacturer:
  name: "SUSE LLC"
  contact_email: "sec@suse.com"
`), 0o600)
	require.NoError(t, err)

	_, err = LoadReportConfig(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "member_state")
}
