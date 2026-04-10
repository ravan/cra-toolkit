// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

//go:build llmjudge

package python_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/python"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive"
)

type reachabilityScores struct {
	PathAccuracy          int    `json:"path_accuracy"`
	ConfidenceCalibration int    `json:"confidence_calibration"`
	EvidenceQuality       int    `json:"evidence_quality"`
	FalsePositiveRate     int    `json:"false_positive_rate"`
	SymbolResolution      int    `json:"symbol_resolution"`
	OverallQuality        int    `json:"overall_quality"`
	Reasoning             string `json:"reasoning"`
}

func TestLLMJudge_PythonReachability(t *testing.T) {
	geminiPath, err := exec.LookPath("gemini")
	if err != nil {
		t.Skip("gemini CLI not available, skipping LLM judge test")
	}

	_, f, _, _ := runtime.Caller(0)
	fixtureBase := filepath.Join(filepath.Dir(f), "..", "..", "..", "..", "testdata", "integration")

	reachableDir := filepath.Join(fixtureBase, "python-treesitter-reachable", "source")
	analyzer := python.New()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2020-1747",
		AffectedPURL: "pkg:pypi/PyYAML@5.3",
		AffectedName: "PyYAML",
		Symbols:      []string{"load"},
		Language:     "python",
	}

	reachableResult, err := analyzer.Analyze(ctx, reachableDir, &finding)
	if err != nil {
		t.Fatalf("Analyze reachable: %v", err)
	}

	notReachableDir := filepath.Join(fixtureBase, "python-treesitter-not-reachable", "source")
	notReachableResult, err := analyzer.Analyze(ctx, notReachableDir, &finding)
	if err != nil {
		t.Fatalf("Analyze not-reachable: %v", err)
	}

	var pathStrs []string
	for _, p := range reachableResult.Paths {
		pathStrs = append(pathStrs, p.String())
	}

	reachableSrcFile, _ := os.CreateTemp("", "python-reachable-*.txt")
	defer os.Remove(reachableSrcFile.Name())
	writeSourceFiles(t, reachableDir, reachableSrcFile)
	reachableSrcFile.Close()

	notReachableSrcFile, _ := os.CreateTemp("", "python-not-reachable-*.txt")
	defer os.Remove(notReachableSrcFile.Name())
	writeSourceFiles(t, notReachableDir, notReachableSrcFile)
	notReachableSrcFile.Close()

	prompt := fmt.Sprintf(`You are a security engineering judge evaluating a tree-sitter-based Python reachability analyzer for CRA (Cyber Resilience Act) compliance.

VULNERABILITY: CVE-2020-1747 — PyYAML arbitrary code execution via yaml.load() without safe Loader.
VULNERABLE SYMBOL: yaml.load

REACHABLE PROJECT (read source from: %s):
Analysis result: Reachable=%v, Confidence=%s, Symbols=%v
Call paths found: %s
Evidence: %s

NOT-REACHABLE PROJECT (read source from: %s):
Analysis result: Reachable=%v, Confidence=%s
Evidence: %s

Score the analyzer on these dimensions (1-10 each):
1. path_accuracy: Are the reported call paths real and verifiable against the source code?
2. confidence_calibration: Does the confidence level correctly reflect certainty?
3. evidence_quality: Would a security engineer trust this evidence to make a VEX determination?
4. false_positive_rate: Is the not-reachable case correctly identified as not-affected?
5. symbol_resolution: Is yaml.load correctly identified and distinguished from yaml.safe_load?
6. overall_quality: Would this analysis pass a CRA market surveillance authority's review?

Respond ONLY with valid JSON:
{"path_accuracy": N, "confidence_calibration": N, "evidence_quality": N, "false_positive_rate": N, "symbol_resolution": N, "overall_quality": N, "reasoning": "brief explanation"}`,
		reachableSrcFile.Name(),
		reachableResult.Reachable, reachableResult.Confidence, reachableResult.Symbols,
		strings.Join(pathStrs, "; "),
		reachableResult.Evidence,
		notReachableSrcFile.Name(),
		notReachableResult.Reachable, notReachableResult.Confidence,
		notReachableResult.Evidence,
	)

	cmd := exec.Command(geminiPath, "--yolo", "-p", prompt) //nolint:gosec
	var geminiOut bytes.Buffer
	cmd.Stdout = &geminiOut
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("gemini CLI error: %v", err)
	}

	responseText := geminiOut.String()
	jsonStart := strings.Index(responseText, "{")
	jsonEnd := strings.LastIndex(responseText, "}")
	if jsonStart == -1 || jsonEnd == -1 {
		t.Fatalf("no JSON in gemini response: %s", responseText)
	}

	var scores reachabilityScores
	if err := json.Unmarshal([]byte(responseText[jsonStart:jsonEnd+1]), &scores); err != nil {
		t.Fatalf("parse scores: %v\nresponse: %s", err, responseText)
	}

	t.Logf("LLM Scores: path=%d, confidence=%d, evidence=%d, fp=%d, symbol=%d, overall=%d",
		scores.PathAccuracy, scores.ConfidenceCalibration, scores.EvidenceQuality,
		scores.FalsePositiveRate, scores.SymbolResolution, scores.OverallQuality)
	t.Logf("Reasoning: %s", scores.Reasoning)

	threshold := 8
	dimensions := map[string]int{
		"path_accuracy":          scores.PathAccuracy,
		"confidence_calibration": scores.ConfidenceCalibration,
		"evidence_quality":       scores.EvidenceQuality,
		"false_positive_rate":    scores.FalsePositiveRate,
		"symbol_resolution":      scores.SymbolResolution,
		"overall_quality":        scores.OverallQuality,
	}
	for dim, score := range dimensions {
		if score < threshold {
			t.Errorf("%s: score %d < threshold %d", dim, score, threshold)
		}
	}
}

func TestLLMJudge_PythonTransitiveReachability(t *testing.T) {
	geminiPath, err := exec.LookPath("gemini")
	if err != nil {
		t.Skip("gemini CLI not available, skipping LLM judge test")
	}

	_, f, _, _ := runtime.Caller(0)
	fixtureBase := filepath.Join(filepath.Dir(f), "..", "..", "..", "..", "testdata", "integration")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	reachableDir := filepath.Join(fixtureBase, "python-realworld-cross-package")
	notReachableDir := filepath.Join(fixtureBase, "python-realworld-cross-package-safe")

	// Build a minimal SBOMSummary from the fixture's SBOM.
	sbomData, err := os.ReadFile(filepath.Join(reachableDir, "sbom.cdx.json"))
	if err != nil {
		t.Fatalf("read sbom: %v", err)
	}
	var sbomDoc struct {
		Components []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			PURL    string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal(sbomData, &sbomDoc); err != nil {
		t.Fatalf("parse sbom: %v", err)
	}
	var pkgs []transitive.Package
	var roots []string
	for _, c := range sbomDoc.Components {
		if strings.HasPrefix(c.PURL, "pkg:pypi/") {
			pkgs = append(pkgs, transitive.Package{Name: c.Name, Version: c.Version})
			roots = append(roots, c.Name)
		}
	}
	summary := &transitive.SBOMSummary{Packages: pkgs, Roots: roots}

	cache := transitive.NewCache(t.TempDir())
	fetcher := &transitive.PyPIFetcher{Cache: cache}
	ta := &transitive.Analyzer{
		Config:    transitive.DefaultConfig(),
		Language:  "python",
		Ecosystem: "pypi",
		Fetchers:  map[string]transitive.Fetcher{"pypi": fetcher},
	}

	finding := &formats.Finding{
		AffectedName:    "urllib3",
		AffectedVersion: "2.0.5",
	}

	reachableResult, err := ta.Analyze(ctx, summary, finding, filepath.Join(reachableDir, "source"))
	if err != nil {
		t.Fatalf("Analyze reachable: %v", err)
	}

	notReachableResult, err := ta.Analyze(ctx, summary, finding, filepath.Join(notReachableDir, "source"))
	if err != nil {
		t.Fatalf("Analyze not-reachable: %v", err)
	}

	var pathStrs []string
	for _, p := range reachableResult.Paths {
		pathStrs = append(pathStrs, p.String())
	}

	prompt := fmt.Sprintf(`You are a security engineering judge evaluating a transitive dependency reachability analyzer for CRA compliance.

VULNERABILITY: CVE-2023-43804 — urllib3 cookie leakage via improper redirect handling.
VULNERABLE PACKAGE: urllib3@2.0.5 (transitive dependency reached through requests@2.31.0)
CHAIN: app → requests.get → HTTPAdapter → urllib3.PoolManager → Retry

REACHABLE PROJECT (source: %s):
Analysis result: Reachable=%v, Confidence=%s, Degradations=%v
Call paths found: %s
Evidence: %s

NOT-REACHABLE PROJECT (source: %s):
Analysis result: Reachable=%v, Confidence=%s, Degradations=%v
Evidence: %s

Score the transitive analyzer (1-10 each):
1. path_accuracy: Are the reported cross-package call paths real?
2. confidence_calibration: Does confidence reflect the uncertainty of transitive analysis?
3. evidence_quality: Is the stitched call path evidence sufficient for a VEX determination?
4. false_positive_rate: Is the not-reachable case correctly identified?
5. symbol_resolution: Are the cross-package symbols correctly resolved?
6. overall_quality: Would this analysis pass a CRA market surveillance authority review?

Respond ONLY with valid JSON:
{"path_accuracy": N, "confidence_calibration": N, "evidence_quality": N, "false_positive_rate": N, "symbol_resolution": N, "overall_quality": N, "reasoning": "brief explanation"}`,
		filepath.Join(reachableDir, "source"),
		reachableResult.Reachable, reachableResult.Confidence, reachableResult.Degradations,
		strings.Join(pathStrs, "; "),
		reachableResult.Evidence,
		filepath.Join(notReachableDir, "source"),
		notReachableResult.Reachable, notReachableResult.Confidence, notReachableResult.Degradations,
		notReachableResult.Evidence,
	)

	cmd := exec.Command(geminiPath, "--yolo", "-p", prompt) //nolint:gosec
	var geminiOut bytes.Buffer
	cmd.Stdout = &geminiOut
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("gemini CLI error: %v", err)
	}

	responseText := geminiOut.String()
	jsonStart := strings.Index(responseText, "{")
	jsonEnd := strings.LastIndex(responseText, "}")
	if jsonStart == -1 || jsonEnd == -1 {
		t.Fatalf("no JSON in gemini response: %s", responseText)
	}

	var scores reachabilityScores
	if err := json.Unmarshal([]byte(responseText[jsonStart:jsonEnd+1]), &scores); err != nil {
		t.Fatalf("parse scores: %v\nresponse: %s", err, responseText)
	}

	t.Logf("Transitive LLM Scores: path=%d, confidence=%d, evidence=%d, fp=%d, symbol=%d, overall=%d",
		scores.PathAccuracy, scores.ConfidenceCalibration, scores.EvidenceQuality,
		scores.FalsePositiveRate, scores.SymbolResolution, scores.OverallQuality)
	t.Logf("Reasoning: %s", scores.Reasoning)

	threshold := 6 // lower threshold for transitive (harder problem)
	dimensions := map[string]int{
		"path_accuracy":          scores.PathAccuracy,
		"confidence_calibration": scores.ConfidenceCalibration,
		"evidence_quality":       scores.EvidenceQuality,
		"false_positive_rate":    scores.FalsePositiveRate,
		"symbol_resolution":      scores.SymbolResolution,
		"overall_quality":        scores.OverallQuality,
	}
	for dim, score := range dimensions {
		if score < threshold {
			t.Errorf("%s: score %d < threshold %d", dim, score, threshold)
		}
	}
}

func writeSourceFiles(t *testing.T, dir string, out *os.File) {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(dir, "*.py"))
	for _, f := range files {
		data, err := os.ReadFile(f) //nolint:gosec
		if err != nil {
			continue
		}
		rel, _ := filepath.Rel(dir, f)
		fmt.Fprintf(out, "=== %s ===\n%s\n\n", rel, string(data))
	}
}
