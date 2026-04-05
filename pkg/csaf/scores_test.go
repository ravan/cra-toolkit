// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package csaf

import (
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
)

func TestEnrichScores_HighSeverity(t *testing.T) {
	vulns := []vulnerability{
		{
			CVE: "CVE-2022-32149",
			ProductStatus: productStatus{
				KnownAffected: []string{"pkg:golang/golang.org/x/text@v0.3.7"},
			},
		},
	}
	findings := []formats.Finding{
		{
			CVE:          "CVE-2022-32149",
			AffectedPURL: "pkg:golang/golang.org/x/text@v0.3.7",
			CVSS:         7.5,
			Severity:     "high",
		},
	}

	got := enrichScores(vulns, findings)

	if len(got) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(got))
	}
	if len(got[0].Scores) != 1 {
		t.Fatalf("expected 1 score, got %d", len(got[0].Scores))
	}
	s := got[0].Scores[0]
	if s.CVSS3 == nil {
		t.Fatal("expected CVSS3 to be non-nil")
	}
	if s.CVSS3.BaseScore != 7.5 {
		t.Errorf("expected baseScore 7.5, got %f", s.CVSS3.BaseScore)
	}
	if s.CVSS3.BaseSeverity != "HIGH" {
		t.Errorf("expected baseSeverity HIGH, got %s", s.CVSS3.BaseSeverity)
	}
	if s.CVSS3.Version != "3.1" {
		t.Errorf("expected version 3.1, got %s", s.CVSS3.Version)
	}
	if len(s.Products) != 1 || s.Products[0] != "pkg:golang/golang.org/x/text@v0.3.7" {
		t.Errorf("expected products to contain the PURL, got %v", s.Products)
	}
}

func TestEnrichScores_SeverityMapping(t *testing.T) {
	tests := []struct {
		score    float64
		severity string
	}{
		{9.5, "CRITICAL"},
		{9.0, "CRITICAL"},
		{8.0, "HIGH"},
		{7.0, "HIGH"},
		{5.5, "MEDIUM"},
		{4.0, "MEDIUM"},
		{2.0, "LOW"},
		{0.1, "LOW"},
		{0.0, "NONE"},
	}
	for _, tt := range tests {
		got := cvssToSeverity(tt.score)
		if got != tt.severity {
			t.Errorf("cvssToSeverity(%v) = %q, want %q", tt.score, got, tt.severity)
		}
	}
}

func TestEnrichScores_ZeroCVSS_OmitsScore(t *testing.T) {
	vulns := []vulnerability{
		{
			CVE: "CVE-2023-00001",
			ProductStatus: productStatus{
				KnownAffected: []string{"pkg:golang/example.com/foo@v1.0.0"},
			},
		},
	}
	findings := []formats.Finding{
		{
			CVE:          "CVE-2023-00001",
			AffectedPURL: "pkg:golang/example.com/foo@v1.0.0",
			CVSS:         0,
		},
	}

	got := enrichScores(vulns, findings)

	if len(got[0].Scores) != 0 {
		t.Errorf("expected 0 scores for zero CVSS, got %d", len(got[0].Scores))
	}
}

func TestEnrichScores_MultipleProducts_SameCVE(t *testing.T) {
	purl1 := "pkg:golang/example.com/foo@v1.0.0"
	purl2 := "pkg:golang/example.com/bar@v2.0.0"
	vulns := []vulnerability{
		{
			CVE: "CVE-2023-99999",
			ProductStatus: productStatus{
				KnownAffected: []string{purl1, purl2},
			},
		},
	}
	findings := []formats.Finding{
		{CVE: "CVE-2023-99999", AffectedPURL: purl1, CVSS: 10.0},
		{CVE: "CVE-2023-99999", AffectedPURL: purl2, CVSS: 10.0},
	}

	got := enrichScores(vulns, findings)

	if len(got[0].Scores) != 2 {
		t.Fatalf("expected 2 score entries, got %d", len(got[0].Scores))
	}
	for i, s := range got[0].Scores {
		if s.CVSS3 == nil {
			t.Errorf("score[%d]: expected CVSS3 to be non-nil", i)
		}
		if s.CVSS3.BaseScore != 10.0 {
			t.Errorf("score[%d]: expected baseScore 10.0, got %f", i, s.CVSS3.BaseScore)
		}
		if s.CVSS3.BaseSeverity != "CRITICAL" {
			t.Errorf("score[%d]: expected baseSeverity CRITICAL, got %s", i, s.CVSS3.BaseSeverity)
		}
	}
}
