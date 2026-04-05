// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package vex_test

import (
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
	"github.com/ravan/suse-cra-toolkit/pkg/vex"
)

func TestPlatformFilter_WrongPlatform(t *testing.T) {
	f := vex.NewPlatformFilter()

	// CVE only affects windows; our component targets linux.
	finding := formats.Finding{
		CVE:          "CVE-2023-2222",
		AffectedPURL: "pkg:golang/github.com/example/lib@1.0.0",
		Platforms:    []string{"windows"},
	}

	components := []formats.Component{
		{
			PURL:     "pkg:golang/github.com/example/lib@1.0.0",
			Platform: "linux",
		},
	}

	result, resolved := f.Evaluate(&finding, components)

	if !resolved {
		t.Fatal("expected resolved=true: component is linux but CVE only affects windows")
	}
	if result.Status != formats.StatusNotAffected {
		t.Errorf("expected not_affected, got %s", result.Status)
	}
	if result.ResolvedBy != "platform" {
		t.Errorf("expected ResolvedBy=platform, got %s", result.ResolvedBy)
	}
}

func TestPlatformFilter_MatchingPlatform(t *testing.T) {
	f := vex.NewPlatformFilter()

	// CVE affects linux; our component targets linux too.
	finding := formats.Finding{
		CVE:          "CVE-2023-2222",
		AffectedPURL: "pkg:golang/github.com/example/lib@1.0.0",
		Platforms:    []string{"linux", "windows"},
	}

	components := []formats.Component{
		{
			PURL:     "pkg:golang/github.com/example/lib@1.0.0",
			Platform: "linux",
		},
	}

	_, resolved := f.Evaluate(&finding, components)

	if resolved {
		t.Error("expected resolved=false when component platform matches CVE affected platform")
	}
}

func TestPlatformFilter_NoPlatformInfo(t *testing.T) {
	f := vex.NewPlatformFilter()

	// No platform info in the finding.
	finding := formats.Finding{
		CVE:          "CVE-2023-2222",
		AffectedPURL: "pkg:golang/github.com/example/lib@1.0.0",
		Platforms:    nil,
	}

	components := []formats.Component{
		{
			PURL:     "pkg:golang/github.com/example/lib@1.0.0",
			Platform: "linux",
		},
	}

	_, resolved := f.Evaluate(&finding, components)

	if resolved {
		t.Error("expected resolved=false when no platform info in finding")
	}
}

func TestPlatformFilter_NoComponentPlatform(t *testing.T) {
	f := vex.NewPlatformFilter()

	finding := formats.Finding{
		CVE:          "CVE-2023-2222",
		AffectedPURL: "pkg:golang/github.com/example/lib@1.0.0",
		Platforms:    []string{"windows"},
	}

	// Component has no platform info.
	components := []formats.Component{
		{
			PURL:     "pkg:golang/github.com/example/lib@1.0.0",
			Platform: "",
		},
	}

	_, resolved := f.Evaluate(&finding, components)

	if resolved {
		t.Error("expected resolved=false when component has no platform info")
	}
}
