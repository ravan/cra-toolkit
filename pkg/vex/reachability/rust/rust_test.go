// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package rust_test

import (
	"context"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/rust"
)

// Compile-time interface check.
var _ reachability.Analyzer = (*rust.Analyzer)(nil)

func TestAnalyzer_Language(t *testing.T) {
	a := rust.New()
	if lang := a.Language(); lang != "rust" {
		t.Fatalf("expected language 'rust', got %q", lang)
	}
}

func TestAnalyze_ReachableFixture(t *testing.T) {
	a := rust.New()

	finding := &formats.Finding{
		CVE:          "CVE-2023-26964",
		AffectedPURL: "pkg:cargo/hyper@0.14.10",
		AffectedName: "hyper",
		Language:     "rust",
		Symbols:      []string{"http2_only", "serve_connection"},
	}

	result, err := a.Analyze(context.Background(), "../../../../testdata/integration/rust-reachable/source", finding)
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}

	if !result.Reachable {
		t.Errorf("expected Reachable=true, got false; evidence: %s", result.Evidence)
	}
	if result.Confidence != formats.ConfidenceHigh {
		t.Errorf("expected ConfidenceHigh, got %v", result.Confidence)
	}
	if result.Evidence == "" {
		t.Error("expected non-empty evidence")
	}
	if len(result.Paths) == 0 {
		t.Error("expected non-empty Paths")
	}
}

func TestAnalyze_NotReachableFixture(t *testing.T) {
	a := rust.New()

	finding := &formats.Finding{
		CVE:          "CVE-2023-26964",
		AffectedPURL: "pkg:cargo/hyper@0.14.10",
		AffectedName: "hyper",
		Language:     "rust",
		Symbols:      []string{"http2_only", "serve_connection"},
	}

	result, err := a.Analyze(context.Background(), "../../../../testdata/integration/rust-not-reachable/source", finding)
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}

	if result.Reachable {
		t.Errorf("expected Reachable=false, got true; evidence: %s", result.Evidence)
	}
	if result.Confidence != formats.ConfidenceHigh {
		t.Errorf("expected ConfidenceHigh, got %v", result.Confidence)
	}
}
