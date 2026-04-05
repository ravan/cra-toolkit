// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package csaf_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/csaf"
)

const fixtureBase = "../../testdata/integration"

type expectedCSAF struct {
	Description string `json:"description"`
	Assertions  struct {
		DocumentCategory      string   `json:"document_category"`
		CSAFVersion           string   `json:"csaf_version"`
		VulnerabilityCount    int      `json:"vulnerability_count"`
		CVEs                  []string `json:"cves"`
		HasProductTree        bool     `json:"has_product_tree"`
		HasScores             bool     `json:"has_scores"`
		HasRemediations       bool     `json:"has_remediations"`
		HasThreats            bool     `json:"has_threats"`
		HasNotes              bool     `json:"has_notes"`
		HasDocumentReferences bool     `json:"has_document_references,omitempty"`
		HasVulnReferences     bool     `json:"has_vuln_references,omitempty"`
	} `json:"assertions"`
}

type csafDoc struct {
	Document struct {
		Category    string `json:"category"`
		CSAFVersion string `json:"csaf_version"`
		Notes       []struct {
			Category string `json:"category"`
		} `json:"notes"`
		References []json.RawMessage `json:"references"`
	} `json:"document"`
	ProductTree struct {
		Branches []json.RawMessage `json:"branches"`
	} `json:"product_tree"`
	Vulnerabilities []struct {
		CVE          string            `json:"cve"`
		Scores       []json.RawMessage `json:"scores"`
		References   []json.RawMessage `json:"references"`
		Remediations []json.RawMessage `json:"remediations"`
		Threats      []json.RawMessage `json:"threats"`
		Notes        []json.RawMessage `json:"notes"`
	} `json:"vulnerabilities"`
}

func TestIntegration_CSAFSingleCVE(t *testing.T) {
	runCSAFIntegration(t, "csaf-single-cve")
}

func TestIntegration_CSAFMultiCVE(t *testing.T) {
	runCSAFIntegration(t, "csaf-multi-cve")
}

func TestIntegration_CSAFMultiComponent(t *testing.T) {
	runCSAFIntegration(t, "csaf-multi-component")
}

func TestIntegration_CSAFMixedStatus(t *testing.T) {
	runCSAFIntegration(t, "csaf-mixed-status")
}

func runCSAFIntegration(t *testing.T, scenario string) { //nolint:gocognit,gocyclo // integration test validates many assertions
	t.Helper()
	dir := filepath.Join(fixtureBase, scenario)

	expected := loadExpectedCSAF(t, dir)

	vexPath := filepath.Join(dir, "vex-results.json")
	if _, err := os.Stat(vexPath); os.IsNotExist(err) {
		vexPath = ""
	}

	opts := &csaf.Options{
		SBOMPath:           filepath.Join(dir, "sbom.cdx.json"),
		ScanPaths:          []string{filepath.Join(dir, "grype.json")},
		VEXPath:            vexPath,
		PublisherName:      "SUSE CRA Test",
		PublisherNamespace: "https://suse.com",
		TrackingID:         "TEST-" + scenario,
	}

	var buf bytes.Buffer
	err := csaf.Run(opts, &buf)
	if err != nil {
		t.Fatalf("csaf.Run() error: %v", err)
	}

	var doc csafDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, buf.String())
	}

	if expected.Assertions.DocumentCategory != "" {
		if doc.Document.Category != expected.Assertions.DocumentCategory {
			t.Errorf("category: expected %q, got %q", expected.Assertions.DocumentCategory, doc.Document.Category)
		}
	}

	if expected.Assertions.CSAFVersion != "" {
		if doc.Document.CSAFVersion != expected.Assertions.CSAFVersion {
			t.Errorf("csaf_version: expected %q, got %q", expected.Assertions.CSAFVersion, doc.Document.CSAFVersion)
		}
	}

	if expected.Assertions.VulnerabilityCount > 0 {
		if len(doc.Vulnerabilities) != expected.Assertions.VulnerabilityCount {
			t.Errorf("vulnerability count: expected %d, got %d", expected.Assertions.VulnerabilityCount, len(doc.Vulnerabilities))
		}
	}

	if len(expected.Assertions.CVEs) > 0 {
		cveSet := make(map[string]bool)
		for i := range doc.Vulnerabilities {
			cveSet[doc.Vulnerabilities[i].CVE] = true
		}
		for _, expectedCVE := range expected.Assertions.CVEs {
			if !cveSet[expectedCVE] {
				t.Errorf("expected CVE %s not found in output", expectedCVE)
			}
		}
	}

	if expected.Assertions.HasProductTree {
		if len(doc.ProductTree.Branches) == 0 {
			t.Error("expected non-empty product_tree branches")
		}
	}

	// Check document-level presence of scores, remediations, threats, notes.
	var hasAnyScores, hasAnyRemediations, hasAnyThreats, hasAnyNotes bool
	for i := range doc.Vulnerabilities {
		v := &doc.Vulnerabilities[i]
		if len(v.Scores) > 0 {
			hasAnyScores = true
		}
		if len(v.Remediations) > 0 {
			hasAnyRemediations = true
		}
		if len(v.Threats) > 0 {
			hasAnyThreats = true
		}
		if len(v.Notes) > 0 {
			hasAnyNotes = true
		}
	}
	if expected.Assertions.HasScores && !hasAnyScores {
		t.Error("expected at least one vulnerability with scores")
	}
	if expected.Assertions.HasRemediations && !hasAnyRemediations {
		t.Error("expected at least one vulnerability with remediations")
	}
	if expected.Assertions.HasThreats && !hasAnyThreats {
		t.Error("expected at least one vulnerability with threats")
	}
	if expected.Assertions.HasNotes && !hasAnyNotes {
		t.Error("expected at least one vulnerability with notes")
	}

	if expected.Assertions.HasDocumentReferences && len(doc.Document.References) == 0 {
		t.Error("expected non-empty document references")
	}

	if expected.Assertions.HasVulnReferences {
		hasAnyVulnRefs := false
		for i := range doc.Vulnerabilities {
			if len(doc.Vulnerabilities[i].References) > 0 {
				hasAnyVulnRefs = true
				break
			}
		}
		if !hasAnyVulnRefs {
			t.Error("expected at least one vulnerability with references")
		}
	}

	t.Logf("%s: %d vulnerabilities, all assertions passed", scenario, len(doc.Vulnerabilities))
}

func loadExpectedCSAF(t *testing.T, dir string) expectedCSAF {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "expected.json")) //nolint:gosec // test fixture path
	if err != nil {
		t.Fatalf("failed to read expected.json: %v", err)
	}
	var expected expectedCSAF
	if err := json.Unmarshal(data, &expected); err != nil {
		t.Fatalf("failed to parse expected.json: %v", err)
	}
	return expected
}
