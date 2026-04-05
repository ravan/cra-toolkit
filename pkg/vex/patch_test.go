// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package vex_test

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/vex"
)

func TestPatchFilter_InstalledAtFixVersion(t *testing.T) {
	f := vex.NewPatchFilter()

	finding := formats.Finding{
		CVE:          "CVE-2023-3333",
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
		t.Fatal("expected resolved=true: installed v0.3.8 >= fix v0.3.8")
	}
	if result.Status != formats.StatusFixed {
		t.Errorf("expected fixed status, got %s", result.Status)
	}
	if result.Confidence != formats.ConfidenceHigh {
		t.Errorf("expected high confidence, got %v", result.Confidence)
	}
	if result.ResolvedBy != "patch" {
		t.Errorf("expected ResolvedBy=patch, got %s", result.ResolvedBy)
	}
}

func TestPatchFilter_InstalledAboveFixVersion(t *testing.T) {
	f := vex.NewPatchFilter()

	finding := formats.Finding{
		CVE:          "CVE-2023-3333",
		AffectedPURL: "pkg:golang/github.com/example/lib@0.3.7",
		FixVersion:   "0.3.8",
	}

	components := []formats.Component{
		{
			PURL:    "pkg:golang/github.com/example/lib@1.0.0",
			Version: "1.0.0",
		},
	}

	result, resolved := f.Evaluate(&finding, components)

	if !resolved {
		t.Fatal("expected resolved=true: installed v1.0.0 >= fix v0.3.8")
	}
	if result.Status != formats.StatusFixed {
		t.Errorf("expected fixed status, got %s", result.Status)
	}
}

func TestPatchFilter_InstalledBelowFixVersion(t *testing.T) {
	f := vex.NewPatchFilter()

	finding := formats.Finding{
		CVE:          "CVE-2023-3333",
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

func TestPatchFilter_NoFixVersion(t *testing.T) {
	f := vex.NewPatchFilter()

	finding := formats.Finding{
		CVE:          "CVE-2023-3333",
		AffectedPURL: "pkg:golang/github.com/example/lib@0.3.7",
		FixVersion:   "",
	}

	components := []formats.Component{
		{
			PURL:    "pkg:golang/github.com/example/lib@1.0.0",
			Version: "1.0.0",
		},
	}

	_, resolved := f.Evaluate(&finding, components)

	if resolved {
		t.Error("expected resolved=false when no fix version provided")
	}
}

func TestPatchFilter_StatusIsFixed_NotNotAffected(t *testing.T) {
	// Verify that the patch filter returns StatusFixed, not StatusNotAffected,
	// distinguishing it from the version filter.
	pf := vex.NewPatchFilter()
	vf := vex.NewVersionFilter()

	finding := formats.Finding{
		CVE:          "CVE-2023-3333",
		AffectedPURL: "pkg:golang/github.com/example/lib@0.3.7",
		FixVersion:   "0.3.8",
	}

	components := []formats.Component{
		{
			PURL:    "pkg:golang/github.com/example/lib@0.3.8",
			Version: "0.3.8",
		},
	}

	patchResult, _ := pf.Evaluate(&finding, components)
	versionResult, _ := vf.Evaluate(&finding, components)

	if patchResult.Status != formats.StatusFixed {
		t.Errorf("patch filter: expected fixed, got %s", patchResult.Status)
	}
	if versionResult.Status != formats.StatusNotAffected {
		t.Errorf("version filter: expected not_affected, got %s", versionResult.Status)
	}
}
