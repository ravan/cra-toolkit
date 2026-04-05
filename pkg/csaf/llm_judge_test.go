// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

//go:build llmjudge

package csaf_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/csaf"
)

const referenceBase = "../../testdata/csaf-references"

type llmScores struct {
	SchemaCompliance    int    `json:"schema_compliance"`
	ProductTreeQuality  int    `json:"product_tree_quality"`
	VulnerabilityDetail int    `json:"vulnerability_detail"`
	RemediationClarity  int    `json:"remediation_clarity"`
	NotesQuality        int    `json:"notes_quality"`
	OverallQuality      int    `json:"overall_quality"`
	Reasoning           string `json:"reasoning"`
}

func TestLLMJudge_CSAFSingleCVE_VsSUSE(t *testing.T) {
	geminiPath, err := exec.LookPath("gemini")
	if err != nil {
		t.Skip("gemini CLI not available, skipping LLM judge test")
	}

	// Generate our advisory
	dir := filepath.Join(fixtureBase, "csaf-single-cve")
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
		TrackingID:         "TEST-llm-judge",
	}

	var buf bytes.Buffer
	if err := csaf.Run(opts, &buf); err != nil {
		t.Fatalf("csaf.Run() error: %v", err)
	}
	// Write generated advisory to temp file for Gemini to read
	generatedFile, err := os.CreateTemp("", "csaf-generated-*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(generatedFile.Name()) //nolint:errcheck // cleanup
	if _, err := generatedFile.Write(buf.Bytes()); err != nil {
		t.Fatalf("failed to write generated advisory: %v", err)
	}
	generatedFile.Close()

	// Get absolute paths for Gemini file access
	absRef, err := filepath.Abs(filepath.Join(referenceBase, "suse-su-2021_4111-1.json"))
	if err != nil {
		t.Fatalf("failed to get absolute path: %v", err)
	}

	// Tell Gemini where to find the files — it can read them directly
	prompt := fmt.Sprintf(`You are a CSAF 2.0 security advisory quality judge.

Read the REFERENCE ADVISORY (SUSE) from: %s
Read the GENERATED ADVISORY (our tool) from: %s

Compare the generated advisory against the reference and score the generated advisory on these dimensions (1-10 each):
1. schema_compliance: Is it valid CSAF 2.0 csaf_security_advisory profile?
2. product_tree_quality: Proper hierarchy, PURL identification, completeness?
3. vulnerability_detail: CVSS scores, descriptions present and accurate?
4. remediation_clarity: Actionable fix information, correct categories?
5. notes_quality: Clear summary, useful detail notes?
6. overall_quality: Would a security team trust and act on this advisory?

Respond ONLY with valid JSON in this exact format, no other text:
{"schema_compliance": N, "product_tree_quality": N, "vulnerability_detail": N, "remediation_clarity": N, "notes_quality": N, "overall_quality": N, "reasoning": "brief explanation"}`,
		absRef, generatedFile.Name())

	cmd := exec.Command(geminiPath, "--yolo", "-p", prompt) //nolint:gosec // test-only
	var geminiOut bytes.Buffer
	cmd.Stdout = &geminiOut
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("gemini CLI error: %v", err)
	}

	// Parse scores from LLM response
	responseText := geminiOut.String()
	jsonStart := strings.Index(responseText, "{")
	jsonEnd := strings.LastIndex(responseText, "}")
	if jsonStart == -1 || jsonEnd == -1 {
		t.Fatalf("no JSON found in gemini response: %s", responseText)
	}
	jsonStr := responseText[jsonStart : jsonEnd+1]

	var scores llmScores
	if err := json.Unmarshal([]byte(jsonStr), &scores); err != nil {
		t.Fatalf("failed to parse LLM scores: %v\nresponse: %s", err, responseText)
	}

	t.Logf("LLM Judge Scores: schema=%d, product_tree=%d, vuln_detail=%d, remediation=%d, notes=%d, overall=%d",
		scores.SchemaCompliance, scores.ProductTreeQuality, scores.VulnerabilityDetail,
		scores.RemediationClarity, scores.NotesQuality, scores.OverallQuality)
	t.Logf("LLM Reasoning: %s", scores.Reasoning)

	// Assert minimum quality threshold
	threshold := 8
	dimensions := map[string]int{
		"schema_compliance":    scores.SchemaCompliance,
		"product_tree_quality": scores.ProductTreeQuality,
		"vulnerability_detail": scores.VulnerabilityDetail,
		"remediation_clarity":  scores.RemediationClarity,
		"notes_quality":        scores.NotesQuality,
		"overall_quality":      scores.OverallQuality,
	}

	for dim, score := range dimensions {
		if score < threshold {
			t.Errorf("%s: score %d < threshold %d", dim, score, threshold)
		}
	}
}
