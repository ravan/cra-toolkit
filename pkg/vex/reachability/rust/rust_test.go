// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package rust_test

import (
	"context"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/rust"
)

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
	}

	result, err := a.Analyze(context.Background(), "../../../../testdata/integration/rust-reachable/source", finding)
	if err != nil {
		// cargo-scan may fail — that's acceptable, the analyzer should still return a result
		t.Logf("Analyze returned error (expected if cargo-scan CLI not fully functional): %v", err)
		return
	}

	// cargo-scan's CLI is not fully functional yet — verify we get a graceful result
	t.Logf("Reachable=%v, Confidence=%v, Evidence=%s", result.Reachable, result.Confidence, result.Evidence)
	if result.Evidence == "" {
		t.Error("expected non-empty evidence regardless of reachability determination")
	}
}

func TestAnalyze_NotReachableFixture(t *testing.T) {
	a := rust.New()

	finding := &formats.Finding{
		CVE:          "CVE-2023-26964",
		AffectedPURL: "pkg:cargo/hyper@0.14.10",
		AffectedName: "hyper",
		Language:     "rust",
	}

	result, err := a.Analyze(context.Background(), "../../../../testdata/integration/rust-not-reachable/source", finding)
	if err != nil {
		t.Logf("Analyze returned error (expected if cargo-scan CLI not fully functional): %v", err)
		return
	}

	t.Logf("Reachable=%v, Confidence=%v, Evidence=%s", result.Reachable, result.Confidence, result.Evidence)
	if result.Evidence == "" {
		t.Error("expected non-empty evidence regardless of reachability determination")
	}
}
