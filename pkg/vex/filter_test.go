// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package vex_test

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/vex"
)

// stubFilter is a test double for Filter.
type stubFilter struct {
	name     string
	resolved bool
	result   vex.Result
}

func (s *stubFilter) Name() string { return s.name }
func (s *stubFilter) Evaluate(_ *formats.Finding, _ []formats.Component) (vex.Result, bool) {
	return s.result, s.resolved
}

func TestRunChain_FirstFilterWins(t *testing.T) {
	finding := formats.Finding{
		CVE:          "CVE-2022-1234",
		AffectedPURL: "pkg:golang/example.com/foo@0.1.0",
	}

	first := &stubFilter{
		name:     "first",
		resolved: true,
		result: vex.Result{
			CVE:        "CVE-2022-1234",
			Status:     formats.StatusNotAffected,
			ResolvedBy: "first",
			Confidence: formats.ConfidenceHigh,
		},
	}
	second := &stubFilter{
		name:     "second",
		resolved: true,
		result: vex.Result{
			CVE:        "CVE-2022-1234",
			Status:     formats.StatusAffected,
			ResolvedBy: "second",
			Confidence: formats.ConfidenceHigh,
		},
	}

	result := vex.RunChain([]vex.Filter{first, second}, &finding, nil)

	if result.ResolvedBy != "first" {
		t.Errorf("expected ResolvedBy=first, got %s", result.ResolvedBy)
	}
	if result.Status != formats.StatusNotAffected {
		t.Errorf("expected status not_affected, got %s", result.Status)
	}
}

func TestRunChain_DefaultUnderInvestigation(t *testing.T) {
	finding := formats.Finding{
		CVE:          "CVE-2022-9999",
		AffectedPURL: "pkg:golang/example.com/bar@0.2.0",
	}

	noResolve := &stubFilter{
		name:     "noop",
		resolved: false,
	}

	result := vex.RunChain([]vex.Filter{noResolve}, &finding, nil)

	if result.Status != formats.StatusUnderInvestigation {
		t.Errorf("expected under_investigation, got %s", result.Status)
	}
	if result.ResolvedBy != "default" {
		t.Errorf("expected ResolvedBy=default, got %s", result.ResolvedBy)
	}
	if result.CVE != "CVE-2022-9999" {
		t.Errorf("expected CVE=CVE-2022-9999, got %s", result.CVE)
	}
	if result.ComponentPURL != "pkg:golang/example.com/bar@0.2.0" {
		t.Errorf("expected correct PURL, got %s", result.ComponentPURL)
	}
}

func TestRunChain_EmptyFilters(t *testing.T) {
	finding := formats.Finding{
		CVE:          "CVE-2022-0001",
		AffectedPURL: "pkg:npm/lodash@4.17.21",
	}

	result := vex.RunChain(nil, &finding, nil)

	if result.Status != formats.StatusUnderInvestigation {
		t.Errorf("expected under_investigation for empty chain, got %s", result.Status)
	}
}
