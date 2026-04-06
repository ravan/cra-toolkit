// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package vex_test

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/vex"
)

func TestRun_GoReachable_ProducesOpenVEXOutput(t *testing.T) {
	opts := vex.Options{
		SBOMPath:     "../../testdata/integration/go-reachable/sbom.cdx.json",
		ScanPaths:    []string{"../../testdata/integration/go-reachable/grype.json"},
		SourceDir:    "../../testdata/integration/go-reachable/source",
		OutputFormat: "openvex",
	}

	var buf bytes.Buffer
	err := vex.Run(&opts, &buf)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	out := buf.String()
	if out == "" {
		t.Fatal("expected non-empty output")
	}

	// Verify it's valid JSON.
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, out)
	}

	// Verify it's OpenVEX format (has @context with openvex).
	ctx, ok := doc["@context"].(string)
	if !ok || !strings.Contains(ctx, "openvex") {
		t.Errorf("expected OpenVEX context, got %v", doc["@context"])
	}

	t.Logf("OpenVEX output: %s", out)
}

func TestRun_UpstreamVEX_ResolvesFindings(t *testing.T) {
	opts := vex.Options{
		SBOMPath:         "../../testdata/integration/upstream-vex/sbom.cdx.json",
		ScanPaths:        []string{"../../testdata/integration/upstream-vex/grype.json"},
		UpstreamVEXPaths: []string{"../../testdata/integration/upstream-vex/openvex.json"},
		OutputFormat:     "openvex",
	}

	var buf bytes.Buffer
	err := vex.Run(&opts, &buf)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "not_affected") {
		t.Errorf("expected upstream VEX to resolve finding as not_affected, output: %s", out)
	}

	t.Logf("Upstream VEX output: %s", out)
}

func TestRun_CSAFOutputFormat(t *testing.T) {
	opts := vex.Options{
		SBOMPath:     "../../testdata/integration/go-reachable/sbom.cdx.json",
		ScanPaths:    []string{"../../testdata/integration/go-reachable/grype.json"},
		OutputFormat: "csaf",
	}

	var buf bytes.Buffer
	err := vex.Run(&opts, &buf)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	out := buf.String()

	// Verify it's valid JSON.
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, out)
	}

	// Verify it's CSAF format (has document key).
	if _, ok := doc["document"]; !ok {
		t.Errorf("expected CSAF document key in output, got keys: %v", keysOf(doc))
	}

	t.Logf("CSAF output: %s", out)
}

func TestRun_MissingSBOM_ReturnsError(t *testing.T) {
	opts := vex.Options{
		SBOMPath:  "/nonexistent/sbom.json",
		ScanPaths: []string{"../../testdata/integration/go-reachable/grype.json"},
	}

	var buf bytes.Buffer
	err := vex.Run(&opts, &buf)
	if err == nil {
		t.Fatal("expected error for missing SBOM, got nil")
	}
}

func TestRun_MissingScan_ReturnsError(t *testing.T) {
	opts := vex.Options{
		SBOMPath:  "../../testdata/integration/go-reachable/sbom.cdx.json",
		ScanPaths: []string{"/nonexistent/scan.json"},
	}

	var buf bytes.Buffer
	err := vex.Run(&opts, &buf)
	if err == nil {
		t.Fatal("expected error for missing scan, got nil")
	}
}

func keysOf(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func TestRun_WithExtraFilter_CatchesUnresolved(t *testing.T) {
	// Extra filters run AFTER built-in filters. They catch findings that
	// built-in filters left as under_investigation.
	opts := vex.Options{
		SBOMPath:     "../../testdata/integration/go-reachable/sbom.cdx.json",
		ScanPaths:    []string{"../../testdata/integration/go-reachable/grype.json"},
		OutputFormat: "openvex",
	}

	var buf bytes.Buffer
	err := vex.Run(&opts, &buf, vex.WithExtraFilters([]vex.Filter{
		&alwaysNotAffectedFilter{},
	}))
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	var doc openvexDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// With the custom filter, no finding should remain as under_investigation.
	// Findings resolved by built-in filters keep their status; the rest get
	// caught by the custom filter as not_affected.
	for i, stmt := range doc.Statements {
		if stmt.Status == "under_investigation" {
			t.Errorf("statement[%d]: status=under_investigation, expected custom filter to catch it", i)
		}
	}
}

type alwaysNotAffectedFilter struct{}

func (f *alwaysNotAffectedFilter) Name() string { return "custom-always-not-affected" }
func (f *alwaysNotAffectedFilter) Evaluate(finding *formats.Finding, _ []formats.Component) (vex.Result, bool) {
	return vex.Result{
		CVE:           finding.CVE,
		ComponentPURL: finding.AffectedPURL,
		Status:        formats.StatusNotAffected,
		Justification: "custom_filter",
		ResolvedBy:    "custom-always-not-affected",
		Evidence:      "Resolved by custom extension filter",
	}, true
}

func TestRun_WithExtraVEXWriter(t *testing.T) {
	opts := vex.Options{
		SBOMPath:     "../../testdata/integration/go-reachable/sbom.cdx.json",
		ScanPaths:    []string{"../../testdata/integration/go-reachable/grype.json"},
		OutputFormat: "custom-writer",
	}

	customWriter := &countingWriter{}

	var buf bytes.Buffer
	err := vex.Run(&opts, &buf, vex.WithExtraVEXWriters(map[string]formats.VEXWriter{
		"custom-writer": customWriter,
	}))
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	if customWriter.count == 0 {
		t.Error("custom writer was not called")
	}
	if buf.Len() == 0 {
		t.Error("expected non-empty output from custom writer")
	}
}

type countingWriter struct{ count int }

func (w *countingWriter) Write(out io.Writer, results []formats.VEXResult) error {
	w.count = len(results)
	return json.NewEncoder(out).Encode(map[string]int{"count": len(results)})
}

func TestRun_ZeroRunOptions_IdenticalToBaseline(t *testing.T) {
	opts := vex.Options{
		SBOMPath:     "../../testdata/integration/go-reachable/sbom.cdx.json",
		ScanPaths:    []string{"../../testdata/integration/go-reachable/grype.json"},
		OutputFormat: "openvex",
	}

	var buf1 bytes.Buffer
	err := vex.Run(&opts, &buf1)
	if err != nil {
		t.Fatalf("Run() baseline error: %v", err)
	}

	var buf2 bytes.Buffer
	err = vex.Run(&opts, &buf2)
	if err != nil {
		t.Fatalf("Run() second call error: %v", err)
	}

	if buf1.String() != buf2.String() {
		t.Error("output differs between two identical calls with no RunOptions")
	}
}
