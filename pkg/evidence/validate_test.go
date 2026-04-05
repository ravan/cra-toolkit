// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package evidence_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/evidence"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateArtifacts_ValidSBOM(t *testing.T) {
	dir := filepath.Join(fixtureBase, "evidence-minimal")
	opts := &evidence.Options{
		SBOMPath:      filepath.Join(dir, "sbom.cdx.json"),
		ProductConfig: filepath.Join(dir, "product-config.yaml"),
		OutputDir:     t.TempDir(),
	}

	checks, err := evidence.ValidateArtifacts(opts)
	require.NoError(t, err)
	require.NotEmpty(t, checks)

	for _, c := range checks {
		assert.Equal(t, "pass", c.Status, "check %s failed: %s", c.CheckID, c.Details)
	}
}

func TestValidateArtifacts_InvalidFile(t *testing.T) {
	dir := t.TempDir()
	invalidPath := filepath.Join(dir, "bad.json")
	require.NoError(t, os.WriteFile(invalidPath, []byte("not json"), 0o600))

	arts := []evidence.TestArtifactInput{
		{SourcePath: invalidPath, Format: "unknown", AnnexVIIRef: "6", Source: "toolkit", Description: "Bad file"},
	}

	checks := evidence.ValidateTestArtifacts(arts)
	require.Len(t, checks, 1)
	assert.Equal(t, "fail", checks[0].Status)
}
