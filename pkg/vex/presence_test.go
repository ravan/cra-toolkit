// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package vex_test

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/vex"
)

func TestPresenceFilter_ComponentNotInSBOM(t *testing.T) {
	f := vex.NewPresenceFilter()

	finding := formats.Finding{
		CVE:          "CVE-2023-5678",
		AffectedPURL: "pkg:golang/github.com/absent/pkg@1.0.0",
	}

	components := []formats.Component{
		{PURL: "pkg:golang/github.com/present/other@2.0.0"},
		{PURL: "pkg:npm/lodash@4.17.21"},
	}

	result, resolved := f.Evaluate(&finding, components)

	if !resolved {
		t.Fatal("expected resolved=true when component is absent from SBOM")
	}
	if result.Status != formats.StatusNotAffected {
		t.Errorf("expected not_affected, got %s", result.Status)
	}
	if result.Justification != formats.JustificationComponentNotPresent {
		t.Errorf("expected component_not_present justification, got %s", result.Justification)
	}
	if result.Confidence != formats.ConfidenceHigh {
		t.Errorf("expected high confidence, got %v", result.Confidence)
	}
}

func TestPresenceFilter_ComponentInSBOM(t *testing.T) {
	f := vex.NewPresenceFilter()

	finding := formats.Finding{
		CVE:          "CVE-2023-5678",
		AffectedPURL: "pkg:golang/github.com/foo/bar@1.0.0",
	}

	// Component present in SBOM with different version — version is ignored.
	components := []formats.Component{
		{PURL: "pkg:golang/github.com/foo/bar@0.9.0"},
	}

	_, resolved := f.Evaluate(&finding, components)

	if resolved {
		t.Error("expected resolved=false when component exists in SBOM (even at different version)")
	}
}

func TestPresenceFilter_ComponentInSBOMExactVersion(t *testing.T) {
	f := vex.NewPresenceFilter()

	finding := formats.Finding{
		CVE:          "CVE-2023-5678",
		AffectedPURL: "pkg:golang/github.com/foo/bar@1.0.0",
	}

	components := []formats.Component{
		{PURL: "pkg:golang/github.com/foo/bar@1.0.0"},
	}

	_, resolved := f.Evaluate(&finding, components)

	if resolved {
		t.Error("expected resolved=false when component exists in SBOM at exact version")
	}
}

func TestPresenceFilter_UnparsableFindingPURL(t *testing.T) {
	f := vex.NewPresenceFilter()

	finding := formats.Finding{
		CVE:          "CVE-2023-5678",
		AffectedPURL: "not-a-valid-purl",
	}

	_, resolved := f.Evaluate(&finding, nil)

	if resolved {
		t.Error("expected resolved=false when PURL cannot be parsed")
	}
}
