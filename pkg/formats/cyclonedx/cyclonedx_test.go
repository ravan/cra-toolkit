// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package cyclonedx_test

import (
	"os"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/formats/cyclonedx"
)

func TestParse_RealCycloneDXSBOM(t *testing.T) {
	f, err := os.Open("../../../testdata/integration/go-reachable/sbom.cdx.json")
	if err != nil {
		t.Fatalf("failed to open test data: %v", err)
	}
	defer f.Close() //nolint:errcheck // test file

	parser := cyclonedx.Parser{}
	components, err := parser.Parse(f)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if len(components) == 0 {
		t.Fatal("expected at least one component, got 0")
	}

	// Verify we can find the vulnerable component
	found := false
	for _, c := range components {
		if c.Name != "golang.org/x/text" {
			continue
		}
		found = true
		if c.Version == "" {
			t.Error("expected version to be populated for golang.org/x/text")
		}
		if c.PURL == "" {
			t.Error("expected PURL to be populated for golang.org/x/text")
		}
		if c.Type != "golang" {
			t.Errorf("expected Type 'golang', got %q", c.Type)
		}
		break
	}
	if !found {
		t.Error("expected to find component 'golang.org/x/text' in SBOM")
	}
}
