// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package csaf

import (
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
)

func TestAddRemediations_VendorFix(t *testing.T) {
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
			AffectedName: "golang.org/x/text",
			FixVersion:   "0.3.8",
		},
	}

	got := addRemediations(vulns, findings)

	if len(got) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(got))
	}
	if len(got[0].Remediations) != 1 {
		t.Fatalf("expected 1 remediation, got %d", len(got[0].Remediations))
	}
	r := got[0].Remediations[0]
	if r.Category != "vendor_fix" {
		t.Errorf("expected category vendor_fix, got %s", r.Category)
	}
	if len(r.ProductIDs) != 1 || r.ProductIDs[0] != purl {
		t.Errorf("expected product IDs to contain %s, got %v", purl, r.ProductIDs)
	}
	if r.Details == "" {
		t.Fatal("expected non-empty details")
	}
	if !containsSubstring(r.Details, "0.3.8") {
		t.Errorf("expected details to mention fix version 0.3.8, got %s", r.Details)
	}
}

func TestAddRemediations_NoFixVersion_NoneAvailable(t *testing.T) {
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
			AffectedName: "golang.org/x/text",
			FixVersion:   "",
		},
	}

	got := addRemediations(vulns, findings)

	if len(got[0].Remediations) != 1 {
		t.Fatalf("expected 1 remediation, got %d", len(got[0].Remediations))
	}
	r := got[0].Remediations[0]
	if r.Category != "none_available" {
		t.Errorf("expected category none_available, got %s", r.Category)
	}
}

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || s != "" && findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
