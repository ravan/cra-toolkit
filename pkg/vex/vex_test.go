// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package vex_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/vex"
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
