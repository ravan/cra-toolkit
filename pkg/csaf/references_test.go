package csaf

import (
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
)

func TestBuildDocumentReferences_NVDLinksPerCVE(t *testing.T) {
	findings := []formats.Finding{
		{CVE: "CVE-2022-32149"},
		{CVE: "CVE-2023-45283"},
		{CVE: "CVE-2022-32149"}, // duplicate — should be deduplicated
	}

	got := buildDocumentReferences(findings)

	if len(got) != 2 {
		t.Fatalf("expected 2 references, got %d: %v", len(got), got)
	}

	for _, ref := range got {
		if ref.Category != "external" {
			t.Errorf("expected category external, got %q", ref.Category)
		}
		if ref.Summary == "" {
			t.Error("expected non-empty summary")
		}
		if ref.URL == "" {
			t.Error("expected non-empty URL")
		}
	}

	if got[0].URL != "https://nvd.nist.gov/vuln/detail/CVE-2022-32149" {
		t.Errorf("unexpected URL: %s", got[0].URL)
	}
	if got[1].URL != "https://nvd.nist.gov/vuln/detail/CVE-2023-45283" {
		t.Errorf("unexpected URL: %s", got[1].URL)
	}
}

func TestBuildDocumentReferences_Empty(t *testing.T) {
	got := buildDocumentReferences(nil)
	if len(got) != 0 {
		t.Fatalf("expected 0 references for nil findings, got %d", len(got))
	}
}

func TestBuildVulnReferences_NVDAndMITRE(t *testing.T) {
	got := buildVulnReferences("CVE-2022-32149")

	if len(got) != 2 {
		t.Fatalf("expected 2 references, got %d: %v", len(got), got)
	}

	// NVD reference
	if got[0].Category != "external" {
		t.Errorf("NVD ref category: expected external, got %q", got[0].Category)
	}
	if got[0].URL != "https://nvd.nist.gov/vuln/detail/CVE-2022-32149" {
		t.Errorf("NVD ref URL: %s", got[0].URL)
	}

	// MITRE reference
	if got[1].Category != "external" {
		t.Errorf("MITRE ref category: expected external, got %q", got[1].Category)
	}
	if got[1].URL != "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32149" {
		t.Errorf("MITRE ref URL: %s", got[1].URL)
	}
}
