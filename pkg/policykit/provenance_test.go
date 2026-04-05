// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package policykit_test

import (
	"os"
	"strings"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/policykit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseProvenance_SLSA_V1(t *testing.T) {
	f, err := os.Open("../../testdata/policykit/slsa-provenance-v1.json")
	require.NoError(t, err)
	defer func() { _ = f.Close() }() //nolint:errcheck // read-only test file

	prov, err := policykit.ParseProvenance(f)
	require.NoError(t, err)

	assert.True(t, prov.Exists)
	assert.Equal(t, "https://github.com/actions/runner", prov.BuilderID)
	assert.Equal(t, "https://github.com/acme/my-product", prov.SourceRepo)
	assert.Contains(t, prov.BuildType, "slsa.dev/provenance")
}

func TestParseProvenance_InvalidJSON(t *testing.T) {
	r := strings.NewReader("not json at all {{{")

	_, err := policykit.ParseProvenance(r)
	assert.Error(t, err)
}
