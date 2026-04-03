package openvex_test

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
	"github.com/ravan/suse-cra-toolkit/pkg/formats/openvex"
)

const testdataDir = "../../../testdata/integration/upstream-vex/"

func TestParser_Parse_RealFile(t *testing.T) {
	f, err := os.Open(testdataDir + "openvex.json")
	if err != nil {
		t.Fatalf("open test file: %v", err)
	}
	defer f.Close() //nolint:errcheck // test file

	p := openvex.Parser{}
	stmts, err := p.Parse(f)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(stmts) == 0 {
		t.Fatal("expected at least one statement, got 0")
	}

	stmt := stmts[0]
	if stmt.CVE == "" {
		t.Error("expected CVE to be populated")
	}
	if stmt.Status == "" {
		t.Error("expected Status to be populated")
	}

	// The test fixture has CVE-2022-32149 with not_affected status
	if stmt.CVE != "CVE-2022-32149" {
		t.Errorf("expected CVE-2022-32149, got %q", stmt.CVE)
	}
	if stmt.Status != formats.StatusNotAffected {
		t.Errorf("expected status not_affected, got %q", stmt.Status)
	}
	if stmt.Justification != formats.JustificationVulnerableCodeNotPresent {
		t.Errorf("expected justification vulnerable_code_not_present, got %q", stmt.Justification)
	}
	if stmt.ProductPURL == "" {
		t.Error("expected ProductPURL to be populated")
	}
}

func TestParser_Parse_MultipleStatements(t *testing.T) {
	f, err := os.Open(testdataDir + "openvex-v020.json")
	if err != nil {
		t.Fatalf("open test file: %v", err)
	}
	defer f.Close() //nolint:errcheck // test file

	p := openvex.Parser{}
	stmts, err := p.Parse(f)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(stmts) != 5 {
		t.Fatalf("expected 5 statements, got %d", len(stmts))
	}

	// First three should be "fixed"
	for i := 0; i < 3; i++ {
		if stmts[i].Status != formats.StatusFixed {
			t.Errorf("stmt[%d]: expected status fixed, got %q", i, stmts[i].Status)
		}
	}

	// Last two should be "not_affected"
	for i := 3; i < 5; i++ {
		if stmts[i].Status != formats.StatusNotAffected {
			t.Errorf("stmt[%d]: expected status not_affected, got %q", i, stmts[i].Status)
		}
	}
}

func TestWriter_RoundTrip(t *testing.T) {
	results := []formats.VEXResult{
		{
			CVE:           "CVE-2023-9999",
			ComponentPURL: "pkg:golang/example.com/lib@v1.0.0",
			Status:        formats.StatusNotAffected,
			Justification: formats.JustificationVulnerableCodeNotPresent,
			Evidence:      "The vulnerable function is not called",
		},
		{
			CVE:           "CVE-2023-8888",
			ComponentPURL: "pkg:golang/example.com/other@v2.0.0",
			Status:        formats.StatusFixed,
		},
	}

	var buf bytes.Buffer
	w := openvex.Writer{}
	if err := w.Write(&buf, results); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Verify the output is valid JSON and parses back
	p := openvex.Parser{}
	stmts, err := p.Parse(&buf)
	if err != nil {
		t.Fatalf("Parse round-trip: %v", err)
	}

	if len(stmts) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(stmts))
	}

	found := map[string]formats.VEXStatement{}
	for _, s := range stmts {
		found[s.CVE] = s
	}

	s1, ok := found["CVE-2023-9999"]
	if !ok {
		t.Fatal("CVE-2023-9999 not found in round-trip output")
	}
	if s1.Status != formats.StatusNotAffected {
		t.Errorf("expected not_affected, got %q", s1.Status)
	}
	if s1.Justification != formats.JustificationVulnerableCodeNotPresent {
		t.Errorf("expected vulnerable_code_not_present, got %q", s1.Justification)
	}

	s2, ok := found["CVE-2023-8888"]
	if !ok {
		t.Fatal("CVE-2023-8888 not found in round-trip output")
	}
	if s2.Status != formats.StatusFixed {
		t.Errorf("expected fixed, got %q", s2.Status)
	}
}

func TestWriter_OutputHasOpenVEXContext(t *testing.T) {
	results := []formats.VEXResult{
		{
			CVE:           "CVE-2023-1111",
			ComponentPURL: "pkg:golang/example.com/lib@v1.0.0",
			Status:        formats.StatusAffected,
		},
	}

	var buf bytes.Buffer
	w := openvex.Writer{}
	if err := w.Write(&buf, results); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Verify it contains the OpenVEX context
	output := buf.String()
	if !strings.Contains(output, "openvex") {
		t.Errorf("expected output to contain 'openvex' in @context, got: %s", output)
	}

	// Verify it's valid JSON with expected structure
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if _, ok := doc["@context"]; !ok {
		t.Error("expected @context field in output")
	}
	if _, ok := doc["statements"]; !ok {
		t.Error("expected statements field in output")
	}
	if author, ok := doc["author"].(string); !ok || author != "SUSE CRA Toolkit" {
		t.Errorf("expected author 'SUSE CRA Toolkit', got %v", doc["author"])
	}
}
