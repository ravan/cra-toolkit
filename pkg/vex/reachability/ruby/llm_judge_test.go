// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

//go:build llmjudge

package ruby_test

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
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/ruby"
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

func TestLLMJudge_RubyReachability(t *testing.T) {
	geminiPath, err := exec.LookPath("gemini")
	if err != nil {
		t.Skip("gemini CLI not available, skipping LLM judge test")
	}

	_, f, _, _ := runtime.Caller(0)
	fixtureBase := filepath.Join(filepath.Dir(f), "..", "..", "..", "..", "testdata", "integration")

	reachableDir := filepath.Join(fixtureBase, "ruby-treesitter-reachable", "source")
	analyzer := ruby.New()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2022-24836",
		AffectedPURL: "pkg:gem/nokogiri@1.13.3",
		AffectedName: "nokogiri",
		Symbols:      []string{"Nokogiri::HTML"},
		Language:     "ruby",
	}

	reachableResult, err := analyzer.Analyze(ctx, reachableDir, &finding)
	if err != nil {
		t.Fatalf("Analyze reachable: %v", err)
	}

	notReachableDir := filepath.Join(fixtureBase, "ruby-treesitter-not-reachable", "source")
	notReachableResult, err := analyzer.Analyze(ctx, notReachableDir, &finding)
	if err != nil {
		t.Fatalf("Analyze not-reachable: %v", err)
	}

	var pathStrs []string
	for _, p := range reachableResult.Paths {
		pathStrs = append(pathStrs, p.String())
	}

	reachableSrcFile, _ := os.CreateTemp("", "ruby-reachable-*.txt")
	defer os.Remove(reachableSrcFile.Name())
	writeSourceFiles(t, reachableDir, reachableSrcFile)
	reachableSrcFile.Close()

	notReachableSrcFile, _ := os.CreateTemp("", "ruby-not-reachable-*.txt")
	defer os.Remove(notReachableSrcFile.Name())
	writeSourceFiles(t, notReachableDir, notReachableSrcFile)
	notReachableSrcFile.Close()

	prompt := fmt.Sprintf(`You are a security engineering judge evaluating a tree-sitter-based Ruby reachability analyzer for CRA (Cyber Resilience Act) compliance.

VULNERABILITY: CVE-2022-24836 — Nokogiri ReDoS vulnerability in HTML parsing. The vulnerable entry point is Nokogiri::HTML() when called with untrusted input.
VULNERABLE SYMBOL: Nokogiri::HTML

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
4. false_positive_rate: Is the not-reachable case correctly identified (no Nokogiri::HTML usage)?
5. symbol_resolution: Is Nokogiri::HTML correctly identified as the vulnerable call?
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
		if ext != ".rb" {
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
