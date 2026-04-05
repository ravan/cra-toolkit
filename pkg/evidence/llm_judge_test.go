// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

//go:build llmjudge

package evidence_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/evidence"
)

type evidenceLLMScores struct {
	AnnexVIICoverage     int    `json:"annex_vii_coverage"`
	CrossValidationRigor int    `json:"cross_validation_rigor"`
	CompletenessAccuracy int    `json:"completeness_accuracy"`
	SummaryAccuracy      int    `json:"summary_accuracy"`
	RegulatoryHonesty    int    `json:"regulatory_honesty"`
	OverallQuality       int    `json:"overall_quality"`
	Reasoning            string `json:"reasoning"`
}

func TestLLMJudge_EvidenceFullBundle(t *testing.T) {
	geminiPath, err := exec.LookPath("gemini")
	if err != nil {
		t.Skip("gemini CLI not available, skipping LLM judge test")
	}

	dir := filepath.Join(fixtureBase, "evidence-full-bundle")
	outputDir := t.TempDir()

	opts := &evidence.Options{
		SBOMPath:          filepath.Join(dir, "sbom.cdx.json"),
		VEXPath:           filepath.Join(dir, "vex-results.json"),
		ScanPaths:         []string{filepath.Join(dir, "grype.json")},
		PolicyReport:      filepath.Join(dir, "policy-report.json"),
		RiskAssessment:    filepath.Join(dir, "risk-assessment.txt"),
		ArchitectureDocs:  filepath.Join(dir, "architecture.txt"),
		EUDeclaration:     filepath.Join(dir, "eu-declaration.txt"),
		CVDPolicy:         filepath.Join(dir, "cvd-policy.md"),
		StandardsDoc:      filepath.Join(dir, "standards.md"),
		ProductionProcess: filepath.Join(dir, "production-process.txt"),
		ProductConfig:     filepath.Join(dir, "product-config.yaml"),
		OutputDir:         outputDir,
		OutputFormat:      "json",
	}

	var buf bytes.Buffer
	if err := evidence.Run(opts, &buf); err != nil {
		t.Fatalf("evidence.Run() error: %v", err)
	}

	bundleFile, err := os.CreateTemp(".", "evidence-bundle-*.json")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	defer os.Remove(bundleFile.Name()) //nolint:errcheck // test cleanup
	if _, err := bundleFile.Write(buf.Bytes()); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	bundleFile.Close()

	completenessPath := filepath.Join(outputDir, "completeness.md")
	summaryPath := filepath.Join(outputDir, "annex-vii-summary.md")

	prompt := fmt.Sprintf(`You are a CRA (EU Cyber Resilience Act) Annex VII technical documentation quality judge.

CRA Annex VII requires technical documentation containing:
1. General description (purpose, versions, user info)
2. Design/development description (architecture, vulnerability handling incl. SBOM, CVD, updates, production)
3. Cybersecurity risk assessment
4. Support period information
5. Harmonised standards applied
6. Test/verification reports
7. EU declaration of conformity
8. SBOM (for market surveillance)

The tool is an evidence BUNDLER — it collects artifacts, cross-validates consistency, and generates
a completeness report. It should NOT fabricate data or overstate its role.

Read the GENERATED BUNDLE JSON from: %s
Read the COMPLETENESS REPORT from: %s
Read the ANNEX VII SUMMARY from: %s

Score on these dimensions (1-10 each):
1. annex_vii_coverage: Does the bundle structure correctly map to all 8 Annex VII sections?
2. cross_validation_rigor: Are cross-validation checks meaningful and correctly reported?
3. completeness_accuracy: Does the completeness report honestly reflect what is present vs missing?
4. summary_accuracy: Are Annex VII summary stats derived from real data, not fabricated?
5. regulatory_honesty: Does the output avoid overstating compliance or the tool's role?
6. overall_quality: Would a compliance officer trust this for conformity assessment preparation?

Respond ONLY with valid JSON, no other text:
{"annex_vii_coverage": N, "cross_validation_rigor": N, "completeness_accuracy": N, "summary_accuracy": N, "regulatory_honesty": N, "overall_quality": N, "reasoning": "brief explanation"}`,
		bundleFile.Name(), completenessPath, summaryPath)

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

	var scores evidenceLLMScores
	if err := json.Unmarshal([]byte(responseText[jsonStart:jsonEnd+1]), &scores); err != nil {
		t.Fatalf("parse scores: %v\nresponse: %s", err, responseText)
	}

	t.Logf("LLM Scores: coverage=%d rigor=%d completeness=%d summary=%d honesty=%d overall=%d",
		scores.AnnexVIICoverage, scores.CrossValidationRigor, scores.CompletenessAccuracy,
		scores.SummaryAccuracy, scores.RegulatoryHonesty, scores.OverallQuality)
	t.Logf("Reasoning: %s", scores.Reasoning)

	threshold := 8
	dims := map[string]int{
		"annex_vii_coverage":     scores.AnnexVIICoverage,
		"cross_validation_rigor": scores.CrossValidationRigor,
		"completeness_accuracy":  scores.CompletenessAccuracy,
		"summary_accuracy":       scores.SummaryAccuracy,
		"regulatory_honesty":     scores.RegulatoryHonesty,
		"overall_quality":        scores.OverallQuality,
	}
	for dim, score := range dims {
		if score < threshold {
			t.Errorf("%s: score %d < threshold %d", dim, score, threshold)
		}
	}
}
