// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package cli_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/ravan/suse-cra-toolkit/internal/cli"
)

func TestVexCmd_MissingSBOM_ReturnsError(t *testing.T) {
	cmd := cli.New("test")
	err := cmd.Run(context.Background(), []string{"cra", "vex"})
	if err == nil {
		t.Fatal("expected error when --sbom is missing, got nil")
	}
	if !strings.Contains(err.Error(), "sbom") {
		t.Errorf("expected error mentioning sbom, got %q", err.Error())
	}
}

//nolint:gocyclo // integration test with thorough assertions
func TestVexCmd_WithOutputFile(t *testing.T) {
	tmpFile := t.TempDir() + "/output.json"

	cmd := cli.New("test")
	err := cmd.Run(context.Background(), []string{
		"cra", "vex",
		"--sbom", "../../testdata/integration/upstream-vex/sbom.cdx.json",
		"--scan", "../../testdata/integration/upstream-vex/grype.json",
		"--upstream-vex", "../../testdata/integration/upstream-vex/openvex.json",
		"--output", tmpFile,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Read output file and verify it's valid JSON.
	data, err := os.ReadFile(tmpFile) //nolint:gosec // test file path is controlled
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// Verify it's OpenVEX format.
	ctx, ok := doc["@context"].(string)
	if !ok || !strings.Contains(ctx, "openvex") {
		t.Errorf("expected OpenVEX context, got %v", doc["@context"])
	}

	// Verify upstream resolution.
	stmts, ok := doc["statements"].([]interface{})
	if !ok || len(stmts) == 0 {
		t.Fatal("expected at least one statement in output")
	}

	stmt, ok := stmts[0].(map[string]interface{})
	if !ok {
		t.Fatal("expected statement to be a JSON object")
	}
	if status, ok := stmt["status"].(string); !ok || status != "not_affected" {
		t.Errorf("expected status not_affected, got %v", stmt["status"])
	}
}
