// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package csaf

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
)

func TestBuildDocumentNotes_SummarizesAllCVEs(t *testing.T) {
	findings := []formats.Finding{
		{CVE: "CVE-2022-32149", AffectedName: "golang.org/x/text", Description: "DoS via crafted Accept-Language header"},
		{CVE: "CVE-2023-45283", AffectedName: "golang.org/x/text", Description: "Path traversal on Windows"},
	}

	got := buildDocumentNotes(findings)

	if len(got) < 3 {
		t.Fatalf("expected at least 3 notes (summary, description, legal_disclaimer), got %d", len(got))
	}

	// Find notes by category.
	notesByCategory := make(map[string]note)
	for _, n := range got {
		notesByCategory[n.Category] = n
	}

	// Summary note references component names.
	summary, ok := notesByCategory["summary"]
	if !ok {
		t.Fatal("missing summary note")
	}
	if !strings.Contains(summary.Text, "golang.org/x/text") {
		t.Errorf("summary should reference component name, got %s", summary.Text)
	}

	// Description note lists CVEs.
	desc, ok := notesByCategory["description"]
	if !ok {
		t.Fatal("missing description note")
	}
	if !strings.Contains(desc.Text, "CVE-2022-32149") {
		t.Errorf("description should contain CVE-2022-32149, got %s", desc.Text)
	}
	if !strings.Contains(desc.Text, "CVE-2023-45283") {
		t.Errorf("description should contain CVE-2023-45283, got %s", desc.Text)
	}

	// Legal disclaimer note.
	legal, ok := notesByCategory["legal_disclaimer"]
	if !ok {
		t.Fatal("missing legal_disclaimer note")
	}
	if !strings.Contains(legal.Text, "CC-BY-4.0") {
		t.Errorf("legal_disclaimer should mention CC-BY-4.0, got %s", legal.Text)
	}
}

func TestBuildDocumentNotes_DescriptionIncludesFindingDetails(t *testing.T) {
	findings := []formats.Finding{
		{
			CVE:          "CVE-2022-32149",
			AffectedName: "golang.org/x/text",
			Description:  "DoS via crafted Accept-Language header",
			FixVersion:   "0.3.8",
		},
	}

	got := buildDocumentNotes(findings)

	var desc *note
	for i := range got {
		if got[i].Category == "description" {
			desc = &got[i]
			break
		}
	}
	if desc == nil {
		t.Fatal("missing description note")
		return //nolint:govet // unreachable, satisfies staticcheck SA5011
	}
	if !strings.Contains(desc.Text, "DoS via crafted Accept-Language header") {
		t.Errorf("description should include finding description, got %s", desc.Text)
	}
	if !strings.Contains(desc.Text, "0.3.8") {
		t.Errorf("description should include fix version, got %s", desc.Text)
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

func reachabilityVEXResult() (formats.Finding, formats.VEXResult) {
	finding := formats.Finding{CVE: "CVE-2020-1747"}
	vexResult := formats.VEXResult{
		CVE:            "CVE-2020-1747",
		Confidence:     formats.ConfidenceHigh,
		ResolvedBy:     "reachability_analysis",
		AnalysisMethod: "tree_sitter",
		Evidence:       "yaml.load is called",
		Symbols:        []string{"yaml.load"},
		MaxCallDepth:   2,
		EntryFiles:     []string{"src/app.py"},
		CallPaths: []formats.CallPath{
			{
				Nodes: []formats.CallNode{
					{Symbol: "app.main", File: "src/app.py", Line: 10},
					{Symbol: "yaml.load", File: "yaml/__init__.py", Line: 100},
				},
			},
		},
	}
	return finding, vexResult
}

func TestBuildVulnNotes_ReachabilityPaths_CallPathNote(t *testing.T) {
	finding, vexResult := reachabilityVEXResult()
	notes := buildVulnNotes(&finding, &vexResult)

	if len(notes) < 3 {
		t.Fatalf("expected at least 3 notes, got %d: %v", len(notes), notes)
	}

	var callPathNote *note
	for i := range notes {
		if notes[i].Title == "Reachability Call Path 1" {
			callPathNote = &notes[i]
		}
	}

	if callPathNote == nil {
		t.Fatal("expected a 'Reachability Call Path 1' note")
		return //nolint:govet // unreachable, satisfies staticcheck SA5011
	}
	if callPathNote.Category != "details" {
		t.Errorf("call path note category = %q, want details", callPathNote.Category)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(callPathNote.Text), &parsed); err != nil {
		t.Fatalf("call path note text is not valid JSON: %v\nText: %s", err, callPathNote.Text)
	}
	if _, ok := parsed["call_path"]; !ok {
		t.Error("call path JSON missing 'call_path' key")
	}
}

func TestBuildVulnNotes_ReachabilityPaths_SummaryNote(t *testing.T) {
	finding, vexResult := reachabilityVEXResult()
	notes := buildVulnNotes(&finding, &vexResult)

	if len(notes) < 3 {
		t.Fatalf("expected at least 3 notes, got %d: %v", len(notes), notes)
	}

	var summaryNote *note
	for i := range notes {
		if notes[i].Title == "Reachability Analysis Summary" {
			summaryNote = &notes[i]
		}
	}

	if summaryNote == nil {
		t.Fatal("expected a 'Reachability Analysis Summary' note")
		return //nolint:govet // unreachable, satisfies staticcheck SA5011
	}
	if !strings.Contains(summaryNote.Text, "confidence=high") {
		t.Errorf("summary note missing confidence, got: %s", summaryNote.Text)
	}
	if !strings.Contains(summaryNote.Text, "yaml.load") {
		t.Errorf("summary note missing symbol, got: %s", summaryNote.Text)
	}
}

func TestBuildVulnNotes_NoReachabilityNotes_ForNonReachability(t *testing.T) {
	finding := formats.Finding{CVE: "CVE-2022-32149"}
	vexResult := formats.VEXResult{
		CVE:        "CVE-2022-32149",
		Confidence: formats.ConfidenceHigh,
		ResolvedBy: "version",
		Evidence:   "version not in affected range",
	}

	notes := buildVulnNotes(&finding, &vexResult)

	for _, n := range notes {
		if strings.Contains(n.Title, "Reachability") {
			t.Errorf("non-reachability result should not produce reachability notes, got: %v", n)
		}
	}
}
