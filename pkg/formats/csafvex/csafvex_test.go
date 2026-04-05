// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package csafvex_test

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
	"github.com/ravan/suse-cra-toolkit/pkg/formats/csafvex"
)

const testdataDir = "../../../testdata/integration/upstream-vex/"

//nolint:gocognit,gocyclo // integration test with thorough assertions
func TestParser_Parse_RealCSAF(t *testing.T) {
	f, err := os.Open(testdataDir + "csaf-rhsa.json")
	if err != nil {
		t.Fatalf("open test file: %v", err)
	}
	defer f.Close() //nolint:errcheck // test file

	p := csafvex.Parser{}
	stmts, err := p.Parse(f)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(stmts) == 0 {
		t.Fatal("expected at least one statement, got 0")
	}

	// Find CVE-2020-1711 statements
	var cve1711 []formats.VEXStatement
	for _, s := range stmts {
		if s.CVE == "CVE-2020-1711" {
			cve1711 = append(cve1711, s)
		}
	}

	if len(cve1711) == 0 {
		t.Fatal("expected to find statements for CVE-2020-1711")
	}

	// All should have status fixed (the advisory fixes these CVEs)
	for _, s := range cve1711 {
		if s.Status != formats.StatusFixed {
			t.Errorf("expected status fixed for CVE-2020-1711, got %q", s.Status)
		}
	}

	// Find CVE-2020-7039 statements
	var cve7039 []formats.VEXStatement
	for _, s := range stmts {
		if s.CVE == "CVE-2020-7039" {
			cve7039 = append(cve7039, s)
		}
	}
	if len(cve7039) == 0 {
		t.Fatal("expected to find statements for CVE-2020-7039")
	}
}

//nolint:gocognit,gocyclo // integration test with thorough assertions
func TestWriter_RoundTrip(t *testing.T) {
	results := []formats.VEXResult{
		{
			CVE:           "CVE-2023-1234",
			ComponentPURL: "pkg:rpm/redhat/libfoo@1.0.0",
			Status:        formats.StatusNotAffected,
			Justification: formats.JustificationVulnerableCodeNotPresent,
			Evidence:      "The vulnerable code path is not included in this build",
		},
		{
			CVE:           "CVE-2023-5678",
			ComponentPURL: "pkg:rpm/redhat/libbar@2.0.0",
			Status:        formats.StatusFixed,
		},
		{
			CVE:           "CVE-2023-9999",
			ComponentPURL: "pkg:rpm/redhat/libbaz@3.0.0",
			Status:        formats.StatusAffected,
		},
	}

	var buf bytes.Buffer
	w := csafvex.Writer{}
	if err := w.Write(&buf, results); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Verify it's valid JSON
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// Verify CSAF document structure
	document, ok := doc["document"].(map[string]any)
	if !ok {
		t.Fatal("expected 'document' field")
	}
	category, ok := document["category"].(string)
	if !ok || !strings.Contains(category, "csaf") {
		t.Errorf("expected document.category to contain 'csaf', got %v", document["category"])
	}

	// Parse back and verify
	p := csafvex.Parser{}
	stmts, err := p.Parse(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Parse round-trip: %v", err)
	}

	if len(stmts) != 3 {
		t.Fatalf("expected 3 statements, got %d", len(stmts))
	}

	found := map[string]formats.VEXStatement{}
	for _, s := range stmts {
		found[s.CVE] = s
	}

	s1, ok := found["CVE-2023-1234"]
	if !ok {
		t.Fatal("CVE-2023-1234 not found in round-trip output")
	}
	if s1.Status != formats.StatusNotAffected {
		t.Errorf("expected not_affected, got %q", s1.Status)
	}

	s2, ok := found["CVE-2023-5678"]
	if !ok {
		t.Fatal("CVE-2023-5678 not found in round-trip output")
	}
	if s2.Status != formats.StatusFixed {
		t.Errorf("expected fixed, got %q", s2.Status)
	}

	s3, ok := found["CVE-2023-9999"]
	if !ok {
		t.Fatal("CVE-2023-9999 not found in round-trip output")
	}
	if s3.Status != formats.StatusAffected {
		t.Errorf("expected affected, got %q", s3.Status)
	}
}
