// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package csaf

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/formats"
)

func TestAddThreats_MapsImpactSeverity(t *testing.T) {
	purl := "pkg:golang/golang.org/x/text@v0.3.7"
	vulns := []vulnerability{
		{
			CVE: "CVE-2022-32149",
			ProductStatus: productStatus{
				KnownAffected: []string{purl},
			},
		},
	}
	findings := []formats.Finding{
		{
			CVE:          "CVE-2022-32149",
			AffectedPURL: purl,
			Severity:     "high",
		},
	}

	got := addThreats(vulns, findings)

	if len(got) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(got))
	}
	if len(got[0].Threats) != 1 {
		t.Fatalf("expected 1 threat, got %d", len(got[0].Threats))
	}
	th := got[0].Threats[0]
	if th.Category != "impact" {
		t.Errorf("expected category impact, got %s", th.Category)
	}
	if th.Details != "High" {
		t.Errorf("expected details High, got %s", th.Details)
	}
}

func TestAddThreats_SeverityTitleCase(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"critical", "Critical"},
		{"high", "High"},
		{"medium", "Medium"},
		{"low", "Low"},
		{"unknown", "Unknown"},
	}
	for _, tt := range tests {
		got := severityToThreatDetail(tt.input)
		if got != tt.want {
			t.Errorf("severityToThreatDetail(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
