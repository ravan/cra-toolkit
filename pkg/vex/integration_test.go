package vex_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/vex"
)

const fixtureBase = "../../testdata/integration"

// expectedJSON is the structure of the expected.json fixture files.
type expectedJSON struct {
	Description string `json:"description"`
	Findings    []struct {
		CVE                string `json:"cve"`
		ComponentPURL      string `json:"component_purl"`
		ExpectedStatus     string `json:"expected_status"`
		ExpectedConfidence string `json:"expected_confidence"`
		ExpectedResolvedBy string `json:"expected_resolved_by"`
	} `json:"findings"`
}

// openvexDoc is a minimal OpenVEX document for parsing output.
type openvexDoc struct {
	Context    string             `json:"@context"`
	Statements []openvexStatement `json:"statements"`
}

type openvexStatement struct {
	Vulnerability struct {
		Name string `json:"name"`
	} `json:"vulnerability"`
	Products []struct {
		ID string `json:"@id"`
	} `json:"products"`
	Status        string `json:"status"`
	Justification string `json:"justification,omitempty"`
}

func TestIntegration_GoFixtures(t *testing.T) {
	tests := []struct {
		name string
		dir  string
		scan string
	}{
		{"go-reachable", "go-reachable", "grype.json"},
		{"go-not-reachable", "go-not-reachable", "grype.json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := filepath.Join(fixtureBase, tt.dir)
			expected := loadExpected(t, dir)

			opts := &vex.Options{
				SBOMPath:     filepath.Join(dir, "sbom.cdx.json"),
				ScanPaths:    []string{filepath.Join(dir, tt.scan)},
				SourceDir:    filepath.Join(dir, "source"),
				OutputFormat: "openvex",
			}

			doc := runPipeline(t, opts)
			verifyExpectations(t, doc, expected, tt.name)
		})
	}
}

func TestIntegration_PythonFixtures(t *testing.T) {
	if _, err := exec.LookPath("rg"); err != nil {
		t.Skip("ripgrep (rg) not available, skipping generic reachability test")
	}

	tests := []struct {
		name string
		dir  string
	}{
		{"python-reachable", "python-reachable"},
		{"python-not-reachable", "python-not-reachable"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := filepath.Join(fixtureBase, tt.dir)
			expected := loadExpected(t, dir)

			opts := &vex.Options{
				SBOMPath:     filepath.Join(dir, "sbom.cdx.json"),
				ScanPaths:    []string{filepath.Join(dir, "trivy.json")},
				SourceDir:    filepath.Join(dir, "source"),
				OutputFormat: "openvex",
			}

			doc := runPipeline(t, opts)
			verifyExpectations(t, doc, expected, tt.name)
		})
	}
}

func TestIntegration_UpstreamVEX(t *testing.T) {
	dir := filepath.Join(fixtureBase, "upstream-vex")
	expected := loadExpected(t, dir)

	opts := &vex.Options{
		SBOMPath:         filepath.Join(dir, "sbom.cdx.json"),
		ScanPaths:        []string{filepath.Join(dir, "grype.json")},
		UpstreamVEXPaths: []string{filepath.Join(dir, "openvex.json")},
		OutputFormat:     "openvex",
	}

	doc := runPipeline(t, opts)
	verifyExpectations(t, doc, expected, "upstream-vex")
}

// verifyExpectations checks that each expected finding's CVE has the right status.
func verifyExpectations(t *testing.T, doc openvexDoc, expected expectedJSON, label string) {
	t.Helper()
	for _, ef := range expected.Findings {
		stmt := findStatement(t, doc, ef.CVE)
		if stmt.Status != ef.ExpectedStatus {
			t.Errorf("CVE %s: expected status %q, got %q", ef.CVE, ef.ExpectedStatus, stmt.Status)
		}
	}
	t.Logf("%s: %d findings processed, all matched expected status", label, len(expected.Findings))
}

// runPipeline runs the VEX pipeline and returns the parsed OpenVEX document.
func runPipeline(t *testing.T, opts *vex.Options) openvexDoc {
	t.Helper()

	var buf bytes.Buffer
	err := vex.Run(opts, &buf)
	if err != nil {
		t.Fatalf("vex.Run() error: %v", err)
	}

	out := buf.String()
	if out == "" {
		t.Fatal("expected non-empty output")
	}

	// Verify valid JSON.
	var doc openvexDoc
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, out)
	}

	t.Logf("Pipeline output (%d statements): %s", len(doc.Statements), out)
	return doc
}

// findStatement finds the statement for the given CVE in the OpenVEX document.
func findStatement(t *testing.T, doc openvexDoc, cve string) openvexStatement {
	t.Helper()
	for _, s := range doc.Statements {
		if s.Vulnerability.Name == cve {
			return s
		}
	}
	t.Fatalf("no statement found for CVE %s in output", cve)
	return openvexStatement{}
}

// loadExpected loads and parses the expected.json fixture file.
func loadExpected(t *testing.T, dir string) expectedJSON {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "expected.json")) //nolint:gosec // test fixture path
	if err != nil {
		t.Fatalf("failed to read expected.json: %v", err)
	}
	var expected expectedJSON
	if err := json.Unmarshal(data, &expected); err != nil {
		t.Fatalf("failed to parse expected.json: %v", err)
	}
	return expected
}
