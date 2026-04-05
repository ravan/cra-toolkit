// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package spdx_test

import (
	"os"
	"testing"

	spdxparser "github.com/ravan/cra-toolkit/pkg/formats/spdx"
)

func TestParse_RealSPDXSBOM(t *testing.T) {
	f, err := os.Open("../../../testdata/integration/go-reachable/sbom.spdx.json")
	if err != nil {
		t.Fatalf("failed to open test data: %v", err)
	}
	defer f.Close() //nolint:errcheck // test file

	parser := spdxparser.Parser{}
	components, err := parser.Parse(f)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if len(components) == 0 {
		t.Fatal("expected at least one component, got 0")
	}

	found := false
	for _, c := range components {
		if c.Name == "golang.org/x/text" || c.Name == "text" {
			found = true
			if c.Version == "" {
				t.Error("expected version to be populated")
			}
			break
		}
	}
	if !found {
		t.Error("expected to find golang.org/x/text component in SPDX SBOM")
	}
}
