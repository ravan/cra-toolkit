// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

//go:build integration

package vex_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex"
)

// realworldExpectedJSON extends expectedJSON with provenance and richer expectations.
type realworldExpectedJSON struct {
	Description string `json:"description"`
	Provenance  struct {
		SourceProject    string `json:"source_project"`
		SourceURL        string `json:"source_url"`
		Commit           string `json:"commit"`
		CVE              string `json:"cve"`
		CVEURL           string `json:"cve_url"`
		Language         string `json:"language"`
		Pattern          string `json:"pattern"`
		GroundTruthNotes string `json:"ground_truth_notes"`
	} `json:"provenance"`
	Findings []struct {
		CVE                   string   `json:"cve"`
		ComponentPURL         string   `json:"component_purl"`
		ExpectedStatus        string   `json:"expected_status"`
		ExpectedJustification string   `json:"expected_justification,omitempty"`
		ExpectedResolvedBy    string   `json:"expected_resolved_by,omitempty"`
		ExpectedCallDepthMin  int      `json:"expected_call_depth_min,omitempty"`
		ExpectedSymbols       []string `json:"expected_symbols,omitempty"`
	} `json:"findings"`
}

// languageStats tracks pass/fail counts per language.
type languageStats struct {
	total        int
	pass         int
	fail         int
	reachableOK  int
	reachableExp int
	notReachOK   int
	notReachExp  int
}

func TestIntegration_RealWorldReachability(t *testing.T) {
	base := fixtureBase

	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatalf("failed to read fixture directory: %v", err)
	}

	type fixture struct {
		name     string
		dir      string
		language string
		pattern  string
	}

	var fixtures []fixture
	for _, e := range entries {
		if !e.IsDir() || !strings.Contains(e.Name(), "-realworld-") {
			continue
		}
		parts := strings.SplitN(e.Name(), "-realworld-", 2)
		if len(parts) != 2 {
			continue
		}
		fixtures = append(fixtures, fixture{
			name:     e.Name(),
			dir:      filepath.Join(base, e.Name()),
			language: parts[0],
			pattern:  parts[1],
		})
	}

	if len(fixtures) == 0 {
		t.Fatal("no realworld fixtures found")
	}

	byLang := map[string][]fixture{}
	for _, fx := range fixtures {
		byLang[fx.language] = append(byLang[fx.language], fx)
	}

	stats := map[string]*languageStats{}

	langs := make([]string, 0, len(byLang))
	for lang := range byLang {
		langs = append(langs, lang)
	}
	sort.Strings(langs)

	for _, lang := range langs {
		langFixtures := byLang[lang]
		stats[lang] = &languageStats{}

		t.Run(lang, func(t *testing.T) {
			for _, fx := range langFixtures {
				fx := fx
				t.Run(fx.pattern, func(t *testing.T) {
					stats[lang].total++

					expected := loadRealworldExpected(t, fx.dir)
					requireProvenance(t, expected)

					scanFile := detectScanFile(t, fx.dir)

					opts := &vex.Options{
						SBOMPath:     filepath.Join(fx.dir, "sbom.cdx.json"),
						ScanPaths:    []string{filepath.Join(fx.dir, scanFile)},
						SourceDir:    filepath.Join(fx.dir, "source"),
						OutputFormat: "openvex",
					}

					doc := runPipeline(t, opts)

					allPassed := true
					for _, ef := range expected.Findings {
						stmt := findStatement(t, doc, ef.CVE)

						if stmt.Status != ef.ExpectedStatus {
							t.Errorf("CVE %s: expected status %q, got %q (evidence: %s)",
								ef.CVE, ef.ExpectedStatus, stmt.Status, stmt.ImpactStatement)
							allPassed = false
						}

						if stmt.ImpactStatement == "" {
							t.Errorf("CVE %s: impact_statement is empty; expected non-empty evidence", ef.CVE)
							allPassed = false
						}

						if ef.ExpectedStatus == "affected" {
							stats[lang].reachableExp++
							if stmt.Status == "affected" {
								stats[lang].reachableOK++
							}
						} else if ef.ExpectedStatus == "not_affected" {
							stats[lang].notReachExp++
							if stmt.Status == "not_affected" {
								stats[lang].notReachOK++
							}
						}
					}

					if allPassed {
						stats[lang].pass++
					} else {
						stats[lang].fail++
					}
				})
			}
		})
	}

	// Print consistency report.
	t.Log("")
	t.Log("=== Real-World Reachability Consistency Report ===")
	t.Logf("%-12s | %5s | %4s | %4s | %12s | %13s |",
		"Language", "Total", "Pass", "Fail", "Reachable", "NotReachable")
	t.Log(strings.Repeat("-", 70))

	totalAll, passAll, failAll := 0, 0, 0
	reachOKAll, reachExpAll, notReachOKAll, notReachExpAll := 0, 0, 0, 0

	for _, lang := range langs {
		s := stats[lang]
		t.Logf("%-12s | %5d | %4d | %4d | %10s | %11s |",
			lang, s.total, s.pass, s.fail,
			fmt.Sprintf("%d/%d", s.reachableOK, s.reachableExp),
			fmt.Sprintf("%d/%d", s.notReachOK, s.notReachExp))
		totalAll += s.total
		passAll += s.pass
		failAll += s.fail
		reachOKAll += s.reachableOK
		reachExpAll += s.reachableExp
		notReachOKAll += s.notReachOK
		notReachExpAll += s.notReachExp
	}

	t.Log(strings.Repeat("-", 70))
	t.Logf("%-12s | %5d | %4d | %4d | %10s | %11s |",
		"TOTAL", totalAll, passAll, failAll,
		fmt.Sprintf("%d/%d", reachOKAll, reachExpAll),
		fmt.Sprintf("%d/%d", notReachOKAll, notReachExpAll))

	if failAll > 0 {
		t.Errorf("FAIL: %d/%d fixtures failed — 100%% pass rate required", failAll, totalAll)
	}
}

func loadRealworldExpected(t *testing.T, dir string) realworldExpectedJSON {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "expected.json")) //nolint:gosec
	if err != nil {
		t.Fatalf("failed to read expected.json: %v", err)
	}
	var expected realworldExpectedJSON
	if err := json.Unmarshal(data, &expected); err != nil {
		t.Fatalf("failed to parse expected.json: %v", err)
	}
	return expected
}

func requireProvenance(t *testing.T, expected realworldExpectedJSON) {
	t.Helper()
	if expected.Provenance.SourceProject == "" {
		t.Error("provenance.source_project is required")
	}
	if expected.Provenance.CVE == "" {
		t.Error("provenance.cve is required")
	}
	if expected.Provenance.Language == "" {
		t.Error("provenance.language is required")
	}
	if expected.Provenance.Pattern == "" {
		t.Error("provenance.pattern is required")
	}
	if expected.Provenance.GroundTruthNotes == "" {
		t.Error("provenance.ground_truth_notes is required")
	}
}

func detectScanFile(t *testing.T, dir string) string {
	t.Helper()
	for _, name := range []string{"grype.json", "trivy.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return name
		}
	}
	t.Fatalf("no scan file (grype.json or trivy.json) found in %s", dir)
	return ""
}
