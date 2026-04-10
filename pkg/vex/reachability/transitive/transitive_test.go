// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/formats"
)

func TestAnalyzer_NotApplicable_WhenNoSBOM(t *testing.T) {
	a := &Analyzer{Config: DefaultConfig()}
	res, err := a.Analyze(context.Background(), nil, &formats.Finding{AffectedName: "urllib3"}, "/app")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(res.Degradations) == 0 || res.Degradations[0] != ReasonTransitiveNotApplicable {
		t.Errorf("expected transitive_not_applicable, got %v", res.Degradations)
	}
}

func TestAnalyzer_NotApplicable_WhenPackageNotInGraph(t *testing.T) {
	// fakeFetcher is declared in sbom_graph_test.go (same package).
	sbom := &SBOMSummary{
		Packages: []Package{{Name: "flask", Version: "2.0.1"}},
		Roots:    []string{"flask"},
	}
	a := &Analyzer{
		Config: DefaultConfig(),
		Fetchers: map[string]Fetcher{"pypi": &fakeFetcher{
			eco:       "pypi",
			manifests: map[string]map[string]string{"flask@2.0.1": {}},
		}},
		Language:  "python",
		Ecosystem: "pypi",
	}
	res, err := a.Analyze(context.Background(), sbom, &formats.Finding{AffectedName: "unknown"}, "/app")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(res.Degradations) == 0 || res.Degradations[0] != ReasonTransitiveNotApplicable {
		t.Errorf("expected transitive_not_applicable, got %v", res.Degradations)
	}
}
