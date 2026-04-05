// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

//go:build llmjudge

package policykit_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/policykit"
)

type policykitLLMScores struct {
	RegulatoryAccuracy int    `json:"regulatory_accuracy"`
	EvidenceQuality    int    `json:"evidence_quality"`
	Completeness       int    `json:"completeness"`
	ReportClarity      int    `json:"report_clarity"`
	Accuracy           int    `json:"accuracy"`
	OverallQuality     int    `json:"overall_quality"`
	Reasoning          string `json:"reasoning"`
}

func TestLLMJudge_PolicykitAllPass(t *testing.T) {
	geminiPath, err := exec.LookPath("gemini")
	if err != nil {
		t.Skip("gemini CLI not available, skipping LLM judge test")
	}

	dir := filepath.Join(fixtureBase, "policykit-all-pass")
	opts := &policykit.Options{
		SBOMPath:       filepath.Join(dir, "sbom.cdx.json"),
		ScanPaths:      []string{filepath.Join(dir, "grype.json")},
		VEXPath:        filepath.Join(dir, "vex-results.json"),
		KEVPath:        filepath.Join(dir, "kev.json"),
		ProvenancePath: filepath.Join(dir, "provenance.json"),
		SignaturePaths: []string{filepath.Join(dir, "signature.json")},
		ProductConfig:  filepath.Join(dir, "product-config.yaml"),
		OutputFormat:   "json",
	}

	var buf bytes.Buffer
	if err := policykit.Run(opts, &buf); err != nil {
		t.Fatalf("policykit.Run() error: %v", err)
	}

	// Write report to current directory so it is within Gemini's workspace.
	reportFile, err := os.CreateTemp(".", "policykit-report-*.json")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	defer os.Remove(reportFile.Name()) //nolint:errcheck // test cleanup
	if _, err := reportFile.Write(buf.Bytes()); err != nil {
		t.Fatalf("failed to write report: %v", err)
	}
	reportFile.Close()

	prompt := fmt.Sprintf(`You are a CRA (EU Cyber Resilience Act) compliance report quality judge.

The CRA Annex I defines requirements for products with digital elements. Key machine-checkable requirements include:
- Annex I Part II.1: SBOM must exist, have valid format (cyclonedx/spdx), non-empty metadata and components
- Annex I Part I.2(a): No known exploited vulnerabilities (CISA KEV); all critical/high CVEs must have VEX assessment
- Art. 13: Build provenance (SLSA L1+) and cryptographic signatures present
- Annex I Part II: Support period >= 5 years declared; secure update mechanism documented (automatic/manual/hybrid)

Human-reviewable requirements (CRA-HU-*) cover: cybersecurity level, secure defaults, access control,
encryption, data integrity, data minimisation, attack surface minimisation, and risk assessment.

Read the GENERATED REPORT from: %s

Score the generated report on these dimensions (1-10 each):
1. regulatory_accuracy: Do rule IDs (CRA-AI-* / CRA-HU-*) and CRA references correctly cite Annex I / Art. 13?
2. evidence_quality: Is evidence specific, verifiable, and actionable?
3. completeness: Are all 7 machine-checkable policies and 8 human-review items present?
4. report_clarity: Would a compliance officer understand this without CRA expertise?
5. accuracy: Are PASS/FAIL/SKIP statuses consistent with the evidence in the report?
6. overall_quality: Would a market surveillance authority accept this as part of Annex VII?

Respond ONLY with valid JSON, no other text:
{"regulatory_accuracy": N, "evidence_quality": N, "completeness": N, "report_clarity": N, "accuracy": N, "overall_quality": N, "reasoning": "brief explanation"}`,
		reportFile.Name())

	cmd := exec.Command(geminiPath, "--approval-mode", "plan", "-p", prompt) //nolint:gosec
	var geminiOut bytes.Buffer
	cmd.Stdout = &geminiOut
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("gemini error: %v", err)
	}

	responseText := geminiOut.String()
	jsonStart := strings.Index(responseText, "{")
	jsonEnd := strings.LastIndex(responseText, "}")
	if jsonStart == -1 || jsonEnd == -1 {
		t.Fatalf("no JSON in response: %s", responseText)
	}

	var scores policykitLLMScores
	if err := json.Unmarshal([]byte(responseText[jsonStart:jsonEnd+1]), &scores); err != nil {
		t.Fatalf("parse scores: %v\nresponse: %s", err, responseText)
	}

	t.Logf("LLM Scores: regulatory=%d evidence=%d completeness=%d clarity=%d accuracy=%d overall=%d",
		scores.RegulatoryAccuracy, scores.EvidenceQuality, scores.Completeness,
		scores.ReportClarity, scores.Accuracy, scores.OverallQuality)
	t.Logf("Reasoning: %s", scores.Reasoning)

	threshold := 8
	dims := map[string]int{
		"regulatory_accuracy": scores.RegulatoryAccuracy,
		"evidence_quality":    scores.EvidenceQuality,
		"completeness":        scores.Completeness,
		"report_clarity":      scores.ReportClarity,
		"accuracy":            scores.Accuracy,
		"overall_quality":     scores.OverallQuality,
	}
	for dim, score := range dims {
		if score < threshold {
			t.Errorf("%s: score %d < threshold %d", dim, score, threshold)
		}
	}
}
