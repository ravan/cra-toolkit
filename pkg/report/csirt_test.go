// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package report

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLookupCSIRT_Germany(t *testing.T) {
	info, err := LookupCSIRT("DE")
	require.NoError(t, err)
	assert.Equal(t, "BSI (CERT-Bund)", info.Name)
	assert.Equal(t, "DE", info.Country)
	assert.Equal(t, SubmissionChannelENISA, info.SubmissionChannel)
}

func TestLookupCSIRT_France(t *testing.T) {
	info, err := LookupCSIRT("FR")
	require.NoError(t, err)
	assert.Equal(t, "CERT-FR (ANSSI)", info.Name)
	assert.Equal(t, "FR", info.Country)
}

func TestLookupCSIRT_AllEUMembers(t *testing.T) {
	euCodes := []string{
		"AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
		"DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
		"PL", "PT", "RO", "SK", "SI", "ES", "SE",
	}
	for _, code := range euCodes {
		t.Run(code, func(t *testing.T) {
			info, err := LookupCSIRT(code)
			require.NoError(t, err, "missing CSIRT for EU member %s", code)
			assert.NotEmpty(t, info.Name)
			assert.Equal(t, code, info.Country)
			assert.Equal(t, SubmissionChannelENISA, info.SubmissionChannel)
		})
	}
}

func TestLookupCSIRT_EEAMembers(t *testing.T) {
	eeaCodes := []string{"NO", "IS", "LI"}
	for _, code := range eeaCodes {
		t.Run(code, func(t *testing.T) {
			info, err := LookupCSIRT(code)
			require.NoError(t, err, "missing CSIRT for EEA member %s", code)
			assert.NotEmpty(t, info.Name)
		})
	}
}

func TestLookupCSIRT_Unknown(t *testing.T) {
	_, err := LookupCSIRT("XX")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "XX")
}

func TestLookupCSIRT_CaseInsensitive(t *testing.T) {
	info, err := LookupCSIRT("de")
	require.NoError(t, err)
	assert.Equal(t, "BSI (CERT-Bund)", info.Name)
}
