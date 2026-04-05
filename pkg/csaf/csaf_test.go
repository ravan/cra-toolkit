// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package csaf

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestRun_ProducesValidCSAFSecurityAdvisory(t *testing.T) {
	opts := &Options{
		SBOMPath:           "../../testdata/integration/go-reachable/sbom.cdx.json",
		ScanPaths:          []string{"../../testdata/integration/go-reachable/grype.json"},
		VEXPath:            "",
		PublisherName:      "ACME Corp",
		PublisherNamespace: "https://acme.com",
	}

	var buf bytes.Buffer
	err := Run(opts, &buf)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	out := buf.String()
	if out == "" {
		t.Fatal("expected non-empty output")
	}

	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, out)
	}

	docMeta := doc["document"].(map[string]interface{})
	if docMeta["category"] != "csaf_security_advisory" {
		t.Errorf("expected csaf_security_advisory, got %v", docMeta["category"])
	}
	if docMeta["csaf_version"] != "2.0" {
		t.Errorf("expected csaf_version 2.0, got %v", docMeta["csaf_version"])
	}

	pub := docMeta["publisher"].(map[string]interface{})
	if pub["name"] != "ACME Corp" {
		t.Errorf("expected ACME Corp, got %v", pub["name"])
	}

	if _, ok := doc["product_tree"]; !ok {
		t.Error("missing product_tree")
	}

	vulns, ok := doc["vulnerabilities"].([]interface{})
	if !ok || len(vulns) == 0 {
		t.Error("expected at least one vulnerability")
	}

	t.Logf("CSAF advisory output: %s", out)
}

func TestRun_MissingSBOM_ReturnsError(t *testing.T) {
	opts := &Options{
		SBOMPath:           "/nonexistent/sbom.json",
		ScanPaths:          []string{"../../testdata/integration/go-reachable/grype.json"},
		PublisherName:      "Test",
		PublisherNamespace: "https://test.com",
	}

	var buf bytes.Buffer
	err := Run(opts, &buf)
	if err == nil {
		t.Fatal("expected error for missing SBOM")
	}
}

func TestRun_MissingScan_ReturnsError(t *testing.T) {
	opts := &Options{
		SBOMPath:           "../../testdata/integration/go-reachable/sbom.cdx.json",
		ScanPaths:          []string{"/nonexistent/scan.json"},
		PublisherName:      "Test",
		PublisherNamespace: "https://test.com",
	}

	var buf bytes.Buffer
	err := Run(opts, &buf)
	if err == nil {
		t.Fatal("expected error for missing scan")
	}
}
