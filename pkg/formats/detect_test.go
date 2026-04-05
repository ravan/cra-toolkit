// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package formats_test

import (
	"os"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
)

func TestDetectFormat(t *testing.T) {
	const base = "../../testdata/integration/"

	tests := []struct {
		name     string
		path     string
		expected formats.Format
	}{
		{
			name:     "CycloneDX SBOM",
			path:     base + "go-reachable/sbom.cdx.json",
			expected: formats.FormatCycloneDX,
		},
		{
			name:     "SPDX SBOM",
			path:     base + "go-reachable/sbom.spdx.json",
			expected: formats.FormatSPDX,
		},
		{
			name:     "Grype scan result",
			path:     base + "go-reachable/grype.json",
			expected: formats.FormatGrype,
		},
		{
			name:     "Trivy scan result",
			path:     base + "go-reachable/trivy.json",
			expected: formats.FormatTrivy,
		},
		{
			name:     "OpenVEX document",
			path:     base + "upstream-vex/openvex.json",
			expected: formats.FormatOpenVEX,
		},
		{
			name:     "OpenVEX v0.2.0 document",
			path:     base + "upstream-vex/openvex-v020.json",
			expected: formats.FormatOpenVEX,
		},
		{
			name:     "CSAF VEX advisory",
			path:     base + "upstream-vex/csaf-rhsa.json",
			expected: formats.FormatCSAF,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.Open(tc.path)
			if err != nil {
				t.Fatalf("open %s: %v", tc.path, err)
			}
			defer f.Close() //nolint:errcheck // test file

			got, err := formats.DetectFormat(f)
			if err != nil {
				t.Fatalf("DetectFormat: %v", err)
			}
			if got != tc.expected {
				t.Errorf("DetectFormat(%s) = %v, want %v", tc.path, got, tc.expected)
			}
		})
	}
}

func TestDetectFormat_Unknown(t *testing.T) {
	// Create a minimal JSON file that doesn't match any known format
	const unknownJSON = `{"foo": "bar", "baz": 42}`
	r := mustStringReader(unknownJSON)

	got, err := formats.DetectFormat(r)
	if err != nil {
		t.Fatalf("DetectFormat: %v", err)
	}
	if got != formats.FormatUnknown {
		t.Errorf("DetectFormat = %v, want FormatUnknown", got)
	}
}

func mustStringReader(s string) *os.File {
	// Write to a temp file and return
	f, err := os.CreateTemp("", "detect-test-*.json")
	if err != nil {
		panic(err)
	}
	if _, err := f.WriteString(s); err != nil {
		panic(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		panic(err)
	}
	return f
}
