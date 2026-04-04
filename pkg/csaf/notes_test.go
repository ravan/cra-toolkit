package csaf

import (
	"strings"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
)

func TestBuildDocumentNotes_SummarizesAllCVEs(t *testing.T) {
	findings := []formats.Finding{
		{CVE: "CVE-2022-32149"},
		{CVE: "CVE-2023-45283"},
	}

	got := buildDocumentNotes(findings)

	if len(got) != 1 {
		t.Fatalf("expected 1 note, got %d", len(got))
	}
	n := got[0]
	if n.Category != "summary" {
		t.Errorf("expected category summary, got %s", n.Category)
	}
	if !strings.Contains(n.Text, "CVE-2022-32149") {
		t.Errorf("expected text to contain CVE-2022-32149, got %s", n.Text)
	}
	if !strings.Contains(n.Text, "CVE-2023-45283") {
		t.Errorf("expected text to contain CVE-2023-45283, got %s", n.Text)
	}
}

func TestBuildVulnNotes_IncludesDescription(t *testing.T) {
	finding := formats.Finding{
		CVE:         "CVE-2022-32149",
		Description: "DoS via crafted Accept-Language header",
	}
	vexResult := formats.VEXResult{}

	got := buildVulnNotes(&finding, &vexResult)

	if len(got) < 1 {
		t.Fatal("expected at least 1 note")
	}
	found := false
	for _, n := range got {
		if n.Category == "description" && strings.Contains(n.Text, "DoS via crafted Accept-Language header") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a description note with the finding description, got %v", got)
	}
}

func TestBuildVulnNotes_HighConfidenceVEX_IncludesEvidence(t *testing.T) {
	finding := formats.Finding{
		CVE: "CVE-2022-32149",
	}
	vexResult := formats.VEXResult{
		CVE:        "CVE-2022-32149",
		Confidence: formats.ConfidenceHigh,
		Evidence:   "govulncheck confirmed vulnerable symbols are not reachable",
	}

	got := buildVulnNotes(&finding, &vexResult)

	found := false
	for _, n := range got {
		if n.Category == "details" && strings.Contains(n.Text, "govulncheck") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a details note with govulncheck evidence, got %v", got)
	}
}

func TestBuildVulnNotes_LowConfidence_NoEvidenceNote(t *testing.T) {
	finding := formats.Finding{
		CVE: "CVE-2022-32149",
	}
	vexResult := formats.VEXResult{
		CVE:        "CVE-2022-32149",
		Confidence: formats.ConfidenceLow,
		Evidence:   "some evidence",
	}

	got := buildVulnNotes(&finding, &vexResult)

	for _, n := range got {
		if n.Category == "details" {
			t.Errorf("expected no details note for low confidence, but found one: %v", n)
		}
	}
}
