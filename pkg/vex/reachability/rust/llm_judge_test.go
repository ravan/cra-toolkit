// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

//go:build llmjudge

package rust_test

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
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive"
)

type rustReachabilityScores struct {
	PathAccuracy          int    `json:"path_accuracy"`
	ConfidenceCalibration int    `json:"confidence_calibration"`
	EvidenceQuality       int    `json:"evidence_quality"`
	FalsePositiveRate     int    `json:"false_positive_rate"`
	SymbolResolution      int    `json:"symbol_resolution"`
	OverallQuality        int    `json:"overall_quality"`
	Reasoning             string `json:"reasoning"`
}

func TestLLMJudge_RustTransitiveReachability(t *testing.T) {
	geminiPath, err := exec.LookPath("gemini")
	if err != nil {
		t.Skip("gemini CLI not available, skipping LLM judge test")
	}

	_, f, _, _ := runtime.Caller(0)
	fixtureBase := filepath.Join(filepath.Dir(f), "..", "..", "..", "..", "testdata", "integration")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	reachableDir := filepath.Join(fixtureBase, "rust-realworld-cross-package")
	notReachableDir := filepath.Join(fixtureBase, "rust-realworld-cross-package-safe")

	// Parse the SBOM to build a SBOMSummary for the reachable fixture.
	summary := parseSBOMForRustJudge(t, reachableDir, "crates.io")

	cache := transitive.NewCache(t.TempDir())
	fetcher := &transitive.CratesFetcher{Cache: cache}
	lang, langErr := transitive.LanguageFor("rust")
	if langErr != nil {
		t.Fatalf("LanguageFor(rust): %v", langErr)
	}
	ta := &transitive.Analyzer{
		Config:   transitive.DefaultConfig(),
		Language: lang,
		Fetchers: map[string]transitive.Fetcher{"crates.io": fetcher},
	}

	finding := &formats.Finding{
		AffectedName:    "getrandom",
		AffectedVersion: "0.2.11",
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

	prompt := fmt.Sprintf(`You are a security engineering judge evaluating a transitive dependency reachability analyzer for CRA (Cyber Resilience Act) compliance. The analyzer uses tree-sitter AST parsing for Rust source code.

VULNERABILITY: hypothetical-vuln-in-getrandom — a hypothetical vulnerability in getrandom@0.2.11.
VULNERABLE PACKAGE: getrandom@0.2.11 (transitive dependency through uuid@1.6.1)
EXPECTED REACHABLE CHAIN: app::generate_id() → uuid::Uuid::new_v4() → uuid::rng::bytes() → getrandom::getrandom()
EXPECTED SAFE CHAIN: app::is_valid_id() → uuid::Uuid::parse_str() [parse_str does NOT call getrandom — it requires no entropy]

REACHABLE PROJECT (source: %s):
Analysis result: Reachable=%v, Confidence=%s, Degradations=%v
Call paths found: %s
Evidence: %s

NOT-REACHABLE PROJECT (source: %s):
Analysis result: Reachable=%v, Confidence=%s, Degradations=%v
Evidence: %s

Score the transitive Rust analyzer (1-10 each):
1. path_accuracy: Are the reported cross-package call paths real and correctly tracing through uuid's rng module to getrandom?
2. confidence_calibration: Does the confidence level correctly reflect the certainty of transitive Rust analysis?
3. evidence_quality: Is the stitched call path evidence sufficient for a VEX determination under CRA Article 14?
4. false_positive_rate: Is the not-reachable case (parse_str) correctly identified as not-affected — no false positive for getrandom?
5. symbol_resolution: Are the cross-crate symbols correctly resolved (Uuid::new_v4 → rng::bytes → getrandom::getrandom)?
6. overall_quality: Would this analysis pass a CRA market surveillance authority's review?

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

	var scores rustReachabilityScores
	if err := json.Unmarshal([]byte(responseText[jsonStart:jsonEnd+1]), &scores); err != nil {
		t.Fatalf("parse scores: %v\nresponse: %s", err, responseText)
	}

	t.Logf("Rust Transitive LLM Scores: path=%d, confidence=%d, evidence=%d, fp=%d, symbol=%d, overall=%d",
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

// parseSBOMForRustJudge builds a minimal SBOMSummary from the fixture's SBOM
// file. Only cargo (crates.io) packages are included.
func parseSBOMForRustJudge(t *testing.T, fixtureDir, ecosystem string) *transitive.SBOMSummary {
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
		Dependencies []struct {
			Ref       string   `json:"ref"`
			DependsOn []string `json:"dependsOn"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse sbom: %v", err)
	}

	prefix := "pkg:cargo/"
	refToName := make(map[string]string)
	var pkgs []transitive.Package
	pkgNameSet := make(map[string]bool)
	for _, c := range doc.Components {
		if c.BOMRef != "" {
			refToName[c.BOMRef] = c.Name
		}
		if !strings.HasPrefix(c.PURL, prefix) {
			continue
		}
		pkgs = append(pkgs, transitive.Package{Name: c.Name, Version: c.Version})
		pkgNameSet[c.Name] = true
	}

	appRef := doc.Metadata.Component.BOMRef
	var roots []string
	for _, dep := range doc.Dependencies {
		if dep.Ref != appRef {
			continue
		}
		for _, childRef := range dep.DependsOn {
			name := refToName[childRef]
			if name == "" {
				// Extract from PURL-style ref
				if slash := strings.LastIndex(childRef, "/"); slash >= 0 {
					nameVer := childRef[slash+1:]
					if at := strings.IndexByte(nameVer, '@'); at >= 0 {
						name = nameVer[:at]
					}
				}
			}
			if pkgNameSet[name] {
				roots = append(roots, name)
			}
		}
		break
	}
	if len(roots) == 0 {
		for _, p := range pkgs {
			roots = append(roots, p.Name)
		}
	}

	return &transitive.SBOMSummary{Packages: pkgs, Roots: roots}
}
