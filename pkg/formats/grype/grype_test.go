// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package grype_test

import (
	"os"
	"strings"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/formats/grype"
)

func TestParser_Parse(t *testing.T) {
	f, err := os.Open("../../../testdata/integration/go-reachable/grype.json")
	if err != nil {
		t.Fatalf("open test data: %v", err)
	}
	defer f.Close() //nolint:errcheck // test file

	p := grype.Parser{}
	findings, err := p.Parse(f)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected at least one finding, got none")
	}

	for i, f := range findings {
		if f.CVE == "" {
			t.Errorf("finding[%d]: CVE is empty", i)
		}
		if f.AffectedPURL == "" {
			t.Errorf("finding[%d]: AffectedPURL is empty", i)
		}
		if f.DataSource != "grype" {
			t.Errorf("finding[%d]: DataSource = %q, want %q", i, f.DataSource, "grype")
		}
	}
}

func TestParser_VulnerableFunctionsToSymbols(t *testing.T) {
	const doc = `{
		"matches": [
			{
				"vulnerability": {
					"id": "CVE-2021-44228",
					"severity": "Critical",
					"description": "Log4Shell RCE vulnerability",
					"vulnerableFunctions": ["org.apache.logging.log4j.core.net.JndiManager.lookup", "org.apache.logging.log4j.core.lookup.JndiLookup.lookup"]
				},
				"relatedVulnerabilities": [],
				"artifact": {
					"name": "log4j-core",
					"version": "2.14.1",
					"purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
					"language": "java"
				}
			},
			{
				"vulnerability": {
					"id": "CVE-2022-32149",
					"severity": "High",
					"description": "No vulnerable functions listed"
				},
				"relatedVulnerabilities": [],
				"artifact": {
					"name": "golang.org/x/text",
					"version": "0.3.7",
					"purl": "pkg:golang/golang.org/x/text@v0.3.7",
					"language": "go"
				}
			}
		]
	}`

	p := grype.Parser{}
	findings, err := p.Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	// First finding has vulnerableFunctions — Symbols must be populated.
	f0 := findings[0]
	if f0.CVE != "CVE-2021-44228" {
		t.Errorf("finding[0]: CVE = %q, want %q", f0.CVE, "CVE-2021-44228")
	}
	if len(f0.Symbols) != 2 {
		t.Errorf("finding[0]: len(Symbols) = %d, want 2", len(f0.Symbols))
	} else {
		want := "org.apache.logging.log4j.core.net.JndiManager.lookup"
		if f0.Symbols[0] != want {
			t.Errorf("finding[0]: Symbols[0] = %q, want %q", f0.Symbols[0], want)
		}
		want2 := "org.apache.logging.log4j.core.lookup.JndiLookup.lookup"
		if f0.Symbols[1] != want2 {
			t.Errorf("finding[0]: Symbols[1] = %q, want %q", f0.Symbols[1], want2)
		}
	}

	// Second finding has no vulnerableFunctions — Symbols must be nil or empty.
	f1 := findings[1]
	if f1.CVE != "CVE-2022-32149" {
		t.Errorf("finding[1]: CVE = %q, want %q", f1.CVE, "CVE-2022-32149")
	}
	if len(f1.Symbols) != 0 {
		t.Errorf("finding[1]: len(Symbols) = %d, want 0", len(f1.Symbols))
	}
}
