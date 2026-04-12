// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

//go:build llmjudge

package csharp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/csharp"
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

func TestLLMJudge_CSharpReachability(t *testing.T) {
	geminiPath, err := exec.LookPath("gemini")
	if err != nil {
		t.Skip("gemini CLI not available, skipping LLM judge test")
	}

	_, f, _, _ := runtime.Caller(0)
	fixtureBase := filepath.Join(filepath.Dir(f), "..", "..", "..", "..", "testdata", "integration")

	reachableDir := filepath.Join(fixtureBase, "csharp-treesitter-reachable", "source")
	analyzer := csharp.New()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2024-21907",
		AffectedPURL: "pkg:nuget/Newtonsoft.Json@13.0.1",
		AffectedName: "Newtonsoft.Json",
		Symbols:      []string{"JsonConvert.DeserializeObject"},
		Language:     "csharp",
	}

	reachableResult, err := analyzer.Analyze(ctx, reachableDir, &finding)
	if err != nil {
		t.Fatalf("Analyze reachable: %v", err)
	}

	notReachableDir := filepath.Join(fixtureBase, "csharp-treesitter-not-reachable", "source")
	notReachableResult, err := analyzer.Analyze(ctx, notReachableDir, &finding)
	if err != nil {
		t.Fatalf("Analyze not-reachable: %v", err)
	}

	var pathStrs []string
	for _, p := range reachableResult.Paths {
		pathStrs = append(pathStrs, p.String())
	}

	reachableSrcFile, _ := os.CreateTemp("", "csharp-reachable-*.txt")
	defer os.Remove(reachableSrcFile.Name())
	writeSourceFiles(t, reachableDir, reachableSrcFile)
	reachableSrcFile.Close()

	notReachableSrcFile, _ := os.CreateTemp("", "csharp-not-reachable-*.txt")
	defer os.Remove(notReachableSrcFile.Name())
	writeSourceFiles(t, notReachableDir, notReachableSrcFile)
	notReachableSrcFile.Close()

	prompt := fmt.Sprintf(`You are a security engineering judge evaluating a tree-sitter-based C# reachability analyzer for CRA (Cyber Resilience Act) compliance.

VULNERABILITY: CVE-2024-21907 — Newtonsoft.Json ReDoS/unsafe deserialization via JsonConvert.DeserializeObject() when TypeNameHandling is enabled.
VULNERABLE SYMBOL: JsonConvert.DeserializeObject

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
4. false_positive_rate: Is the not-reachable case correctly identified as not-affected (only SerializeObject, never DeserializeObject)?
5. symbol_resolution: Is JsonConvert.DeserializeObject correctly identified and distinguished from JsonConvert.SerializeObject?
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

func writeSourceFiles(t *testing.T, dir string, out *os.File) {
	t.Helper()
	if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".cs" {
			return nil
		}
		data, readErr := os.ReadFile(path) //nolint:gosec
		if readErr != nil {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		fmt.Fprintf(out, "=== %s ===\n%s\n\n", rel, string(data))
		return nil
	}); err != nil {
		t.Logf("walk source files: %v", err)
	}
}

func TestLLMJudge_CSharpTransitiveReachability(t *testing.T) {
	geminiPath, err := exec.LookPath("gemini")
	if err != nil {
		t.Skip("gemini CLI not available, skipping LLM judge test")
	}

	_, f, _, _ := runtime.Caller(0)
	fixtureBase := filepath.Join(filepath.Dir(f), "..", "..", "..", "..", "testdata", "integration")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	reachableDir := filepath.Join(fixtureBase, "csharp-realworld-cross-package")
	notReachableDir := filepath.Join(fixtureBase, "csharp-realworld-cross-package-safe")

	summary := parseSBOMForCSharpJudge(t, reachableDir)

	cache := transitive.NewCache(t.TempDir())
	fetcher := &transitive.NuGetFetcher{Cache: cache}
	lang, langErr := transitive.LanguageFor("csharp")
	if langErr != nil {
		t.Fatalf("LanguageFor(csharp): %v", langErr)
	}
	ta := &transitive.Analyzer{
		Config:   transitive.DefaultConfig(),
		Language: lang,
		Fetchers: map[string]transitive.Fetcher{"nuget": fetcher},
	}

	finding := &formats.Finding{
		AffectedName:    "Newtonsoft.Json",
		AffectedVersion: "13.0.1",
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

	prompt := fmt.Sprintf(`You are a security engineering judge evaluating a transitive dependency reachability analyzer for CRA (Cyber Resilience Act) compliance. The analyzer uses tree-sitter AST parsing for C# source code.

VULNERABILITY: CVE-2024-21907 in Newtonsoft.Json@13.0.1.
VULNERABLE PACKAGE: Newtonsoft.Json@13.0.1 (direct dependency)
EXPECTED REACHABLE CHAIN: App.Main() → JsonConvert.DeserializeObject()
EXPECTED SAFE CHAIN: App.Main() → Console.WriteLine() [does NOT call Newtonsoft.Json — no JSON library usage at all]

REACHABLE PROJECT (source: %s):
Analysis result: Reachable=%%v, Confidence=%%s, Degradations=%%v
Call paths found: %s
Evidence: %s

NOT-REACHABLE PROJECT (source: %s):
Analysis result: Reachable=%%v, Confidence=%%s, Degradations=%%v
Evidence: %s

Score the transitive C# analyzer (1-10 each):
1. path_accuracy: Are the reported cross-package call paths real and correctly tracing through to JsonConvert.DeserializeObject?
2. confidence_calibration: Does the confidence level correctly reflect the certainty of transitive C# analysis?
3. evidence_quality: Is the stitched call path evidence sufficient for a VEX determination under CRA Article 14?
4. false_positive_rate: Is the not-reachable case (no JSON usage) correctly identified as not-affected?
5. symbol_resolution: Are the cross-package symbols correctly resolved (JsonConvert.DeserializeObject)?
6. overall_quality: Would this analysis pass a CRA market surveillance authority's review?

Respond ONLY with valid JSON:
{"path_accuracy": N, "confidence_calibration": N, "evidence_quality": N, "false_positive_rate": N, "symbol_resolution": N, "overall_quality": N, "reasoning": "brief explanation"}`,
		filepath.Join(reachableDir, "source"),
		strings.Join(pathStrs, "; "),
		reachableResult.Evidence,
		filepath.Join(notReachableDir, "source"),
		notReachableResult.Evidence,
	)

	prompt = fmt.Sprintf(prompt,
		reachableResult.Reachable, reachableResult.Confidence, reachableResult.Degradations,
		notReachableResult.Reachable, notReachableResult.Confidence, notReachableResult.Degradations,
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

	t.Logf("C# Transitive LLM Scores: path=%d, confidence=%d, evidence=%d, fp=%d, symbol=%d, overall=%d",
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

// parseSBOMForCSharpJudge builds a minimal SBOMSummary from the fixture's SBOM file.
func parseSBOMForCSharpJudge(t *testing.T, fixtureDir string) *transitive.SBOMSummary {
	t.Helper()
	sbomPath := filepath.Join(fixtureDir, "sbom.cdx.json")
	data, err := os.ReadFile(sbomPath)
	if err != nil {
		t.Fatalf("read sbom: %v", err)
	}

	var doc struct {
		Metadata struct {
			Component struct {
				BOMRef string `json:"bom-ref"`
			} `json:"component"`
		} `json:"metadata"`
		Components []struct {
			BOMRef  string `json:"bom-ref"`
			Name    string `json:"name"`
			Version string `json:"version"`
			PURL    string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse sbom: %v", err)
	}

	prefix := "pkg:nuget/"
	var pkgs []transitive.Package
	for _, c := range doc.Components {
		if !strings.HasPrefix(c.PURL, prefix) {
			continue
		}
		pkgs = append(pkgs, transitive.Package{Name: c.Name, Version: c.Version})
	}

	var roots []string
	for _, p := range pkgs {
		roots = append(roots, p.Name)
	}

	return &transitive.SBOMSummary{Packages: pkgs, Roots: roots}
}
