// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package vex_test

import (
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
	"github.com/ravan/suse-cra-toolkit/pkg/vex"
)

func TestUpstreamFilter_MatchingStatement(t *testing.T) {
	statements := []formats.VEXStatement{
		{
			CVE:           "CVE-2023-1234",
			ProductPURL:   "pkg:golang/github.com/foo/bar@1.0.0",
			Status:        formats.StatusNotAffected,
			Justification: formats.JustificationVulnerableCodeNotPresent,
			StatusNotes:   "The vulnerable function is not compiled in this build.",
		},
	}

	f := vex.NewUpstreamFilter(statements)

	finding := formats.Finding{
		CVE:          "CVE-2023-1234",
		AffectedPURL: "pkg:golang/github.com/foo/bar@1.0.0",
	}

	result, resolved := f.Evaluate(&finding, nil)

	if !resolved {
		t.Fatal("expected resolved=true for matching upstream statement")
	}
	if result.Status != formats.StatusNotAffected {
		t.Errorf("expected not_affected, got %s", result.Status)
	}
	if result.Justification != formats.JustificationVulnerableCodeNotPresent {
		t.Errorf("expected vulnerable_code_not_present justification, got %s", result.Justification)
	}
	if result.Confidence != formats.ConfidenceHigh {
		t.Errorf("expected high confidence, got %v", result.Confidence)
	}
	if result.ResolvedBy != "upstream" {
		t.Errorf("expected ResolvedBy=upstream, got %s", result.ResolvedBy)
	}
}

func TestUpstreamFilter_NonMatchingStatement(t *testing.T) {
	statements := []formats.VEXStatement{
		{
			CVE:         "CVE-2023-9999",
			ProductPURL: "pkg:golang/github.com/other/pkg@2.0.0",
			Status:      formats.StatusFixed,
		},
	}

	f := vex.NewUpstreamFilter(statements)

	finding := formats.Finding{
		CVE:          "CVE-2023-1234",
		AffectedPURL: "pkg:golang/github.com/foo/bar@1.0.0",
	}

	_, resolved := f.Evaluate(&finding, nil)

	if resolved {
		t.Error("expected resolved=false for non-matching upstream statement")
	}
}

func TestUpstreamFilter_EmptyStatements(t *testing.T) {
	f := vex.NewUpstreamFilter(nil)

	finding := formats.Finding{
		CVE:          "CVE-2023-1234",
		AffectedPURL: "pkg:golang/github.com/foo/bar@1.0.0",
	}

	_, resolved := f.Evaluate(&finding, nil)

	if resolved {
		t.Error("expected resolved=false for empty statement list")
	}
}
