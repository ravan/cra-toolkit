// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package vex_test

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/vex"
)

func TestVersionFilter_InstalledAboveFixVersion(t *testing.T) {
	f := vex.NewVersionFilter()

	finding := formats.Finding{
		CVE:          "CVE-2023-1111",
		AffectedPURL: "pkg:golang/github.com/example/lib@0.3.7",
		FixVersion:   "0.3.8",
	}

	components := []formats.Component{
		{
			PURL:    "pkg:golang/github.com/example/lib@0.4.0",
			Version: "0.4.0",
		},
	}

	result, resolved := f.Evaluate(&finding, components)

	if !resolved {
		t.Fatal("expected resolved=true: installed v0.4.0 >= fix v0.3.8")
	}
	if result.Status != formats.StatusNotAffected {
		t.Errorf("expected not_affected, got %s", result.Status)
	}
	if result.Justification != formats.JustificationVulnerableCodeNotPresent {
		t.Errorf("expected vulnerable_code_not_present, got %s", result.Justification)
	}
}

func TestVersionFilter_InstalledBelowFixVersion(t *testing.T) {
	f := vex.NewVersionFilter()

	finding := formats.Finding{
		CVE:          "CVE-2023-1111",
		AffectedPURL: "pkg:golang/github.com/example/lib@0.3.7",
		FixVersion:   "0.3.8",
	}

	components := []formats.Component{
		{
			PURL:    "pkg:golang/github.com/example/lib@0.3.7",
			Version: "0.3.7",
		},
	}

	_, resolved := f.Evaluate(&finding, components)

	if resolved {
		t.Error("expected resolved=false: installed v0.3.7 < fix v0.3.8")
	}
}

func TestVersionFilter_NoFixVersion(t *testing.T) {
	f := vex.NewVersionFilter()

	finding := formats.Finding{
		CVE:          "CVE-2023-1111",
		AffectedPURL: "pkg:golang/github.com/example/lib@0.3.7",
		FixVersion:   "",
	}

	components := []formats.Component{
		{
			PURL:    "pkg:golang/github.com/example/lib@0.4.0",
			Version: "0.4.0",
		},
	}

	_, resolved := f.Evaluate(&finding, components)

	if resolved {
		t.Error("expected resolved=false when no fix version provided")
	}
}

func TestVersionFilter_InvalidVersion(t *testing.T) {
	f := vex.NewVersionFilter()

	finding := formats.Finding{
		CVE:          "CVE-2023-1111",
		AffectedPURL: "pkg:golang/github.com/example/lib@not-semver",
		FixVersion:   "not-semver",
	}

	_, resolved := f.Evaluate(&finding, nil)

	if resolved {
		t.Error("expected resolved=false when version cannot be parsed")
	}
}

func TestVersionFilter_InstalledEqualToFixVersion(t *testing.T) {
	f := vex.NewVersionFilter()

	finding := formats.Finding{
		CVE:          "CVE-2023-1111",
		AffectedPURL: "pkg:golang/github.com/example/lib@0.3.7",
		FixVersion:   "0.3.8",
	}

	components := []formats.Component{
		{
			PURL:    "pkg:golang/github.com/example/lib@0.3.8",
			Version: "0.3.8",
		},
	}

	result, resolved := f.Evaluate(&finding, components)

	if !resolved {
		t.Fatal("expected resolved=true: installed v0.3.8 == fix v0.3.8")
	}
	if result.Status != formats.StatusNotAffected {
		t.Errorf("expected not_affected, got %s", result.Status)
	}
}
