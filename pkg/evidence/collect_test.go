// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package evidence_test

import (
	"path/filepath"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/evidence"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fixtureBase = "../../testdata/integration"

func TestLoadEvidenceConfig(t *testing.T) {
	path := filepath.Join(fixtureBase, "evidence-minimal", "product-config.yaml")
	cfg, err := evidence.LoadEvidenceConfig(path)
	require.NoError(t, err)

	assert.Equal(t, "suse-cra-toolkit", cfg.Product.Name)
	assert.Equal(t, "1.0.0", cfg.Product.Version)
	assert.Equal(t, "SUSE", cfg.Product.Manufacturer)
	assert.Equal(t, "DE", cfg.Product.MemberState)
	assert.Equal(t, "2031-12-31", cfg.Product.SupportPeriodEnd)

	assert.Equal(t, "CLI toolkit for CRA compliance automation", cfg.Evidence.IntendedPurpose)
	assert.Equal(t, "default", cfg.Evidence.ProductClass)
	assert.Equal(t, "module-A", cfg.Evidence.ConformityProcedure)
	assert.Equal(t, "security@suse.com", cfg.Evidence.SecurityContact)
	assert.Equal(t, "https://www.suse.com/support/security/", cfg.Evidence.CVDPolicyURL)
	assert.Equal(t, []string{"ISO/IEC 27001:2022"}, cfg.Evidence.StandardsApplied)
}

func TestBuildProductIdentity(t *testing.T) {
	path := filepath.Join(fixtureBase, "evidence-minimal", "product-config.yaml")
	cfg, err := evidence.LoadEvidenceConfig(path)
	require.NoError(t, err)

	pid := evidence.BuildProductIdentity(cfg)
	assert.Equal(t, "suse-cra-toolkit", pid.Name)
	assert.Equal(t, "1.0.0", pid.Version)
	assert.Equal(t, "SUSE", pid.Manufacturer)
	assert.Equal(t, "CLI toolkit for CRA compliance automation", pid.IntendedPurpose)
	assert.Equal(t, "default", pid.ProductClass)
	assert.Equal(t, "module-A", pid.ConformityProcedure)
	assert.Equal(t, "security@suse.com", pid.SecurityContact)
	assert.Equal(t, "https://www.suse.com/support/security/", pid.CVDPolicyURL)
	assert.Equal(t, "2031-12-31", pid.SupportPeriodEnd)
}

func TestResolveArtifacts_MinimalPaths(t *testing.T) {
	dir := filepath.Join(fixtureBase, "evidence-minimal")
	opts := &evidence.Options{
		SBOMPath:      filepath.Join(dir, "sbom.cdx.json"),
		ScanPaths:     []string{filepath.Join(dir, "grype.json")},
		ProductConfig: filepath.Join(dir, "product-config.yaml"),
		OutputDir:     t.TempDir(),
	}

	artifacts, err := evidence.ResolveArtifacts(opts)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(artifacts), 2) // SBOM + scan
}

func TestResolveArtifacts_MissingFile(t *testing.T) {
	opts := &evidence.Options{
		SBOMPath:      "/nonexistent/sbom.json",
		ProductConfig: filepath.Join(fixtureBase, "evidence-minimal", "product-config.yaml"),
		OutputDir:     t.TempDir(),
	}

	_, err := evidence.ResolveArtifacts(opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sbom")
}
