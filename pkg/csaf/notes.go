// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package csaf

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ravan/cra-toolkit/pkg/formats"
)

func buildDocumentNotes(findings []formats.Finding) []note {
	// Collect unique component names and per-CVE details.
	type cveDetail struct {
		cve         string
		description string
		fixVersion  string
	}
	seenCVE := make(map[string]bool)
	seenComp := make(map[string]bool)
	var components []string
	var details []cveDetail
	for i := range findings {
		f := &findings[i]
		if !seenCVE[f.CVE] {
			seenCVE[f.CVE] = true
			details = append(details, cveDetail{
				cve:         f.CVE,
				description: f.Description,
				fixVersion:  f.FixVersion,
			})
		}
		if f.AffectedName != "" && !seenComp[f.AffectedName] {
			seenComp[f.AffectedName] = true
			components = append(components, f.AffectedName)
		}
	}

	// 1. Summary note — mirrors SUSE "Title of the patch" pattern.
	summaryText := fmt.Sprintf("Security update for %s", strings.Join(components, ", "))
	if len(components) == 0 {
		summaryText = fmt.Sprintf("Security advisory addressing %d vulnerability(ies)", len(details))
	}

	// 2. Description note — per-CVE detail block.
	var descBuilder strings.Builder
	descBuilder.WriteString("This advisory addresses the following vulnerabilities:\n")
	for _, d := range details {
		descBuilder.WriteString(fmt.Sprintf("\n- %s", d.cve))
		if d.description != "" {
			descBuilder.WriteString(fmt.Sprintf(": %s", d.description))
		}
		if d.fixVersion != "" {
			descBuilder.WriteString(fmt.Sprintf(" Fixed in version %s.", d.fixVersion))
		}
	}

	return []note{
		{
			Category: "summary",
			Title:    "Advisory Summary",
			Text:     summaryText,
		},
		{
			Category: "description",
			Title:    "Description",
			Text:     descBuilder.String(),
		},
		{
			Category: "legal_disclaimer",
			Title:    "Terms of use",
			Text:     "CSAF 2.0 data is provided under the Creative Commons License 4.0 with Attribution (CC-BY-4.0).",
		},
	}
}

func buildVulnNotes(finding *formats.Finding, vexResult *formats.VEXResult) []note {
	var notes []note
	if finding.Description != "" {
		notes = append(notes, note{Category: "description", Text: finding.Description})
	}
	if vexResult.Confidence >= formats.ConfidenceHigh && vexResult.Evidence != "" {
		notes = append(notes, note{Category: "details", Title: "VEX Assessment", Text: vexResult.Evidence})
	}
	if vexResult.ResolvedBy == "reachability_analysis" {
		notes = append(notes, buildReachabilityNotes(vexResult)...)
	}
	return notes
}

func buildReachabilityNotes(vexResult *formats.VEXResult) []note {
	// Pre-allocate: one note per call path plus one summary note.
	notes := make([]note, 0, len(vexResult.CallPaths)+1)

	// One note per call path with JSON body.
	for i, p := range vexResult.CallPaths {
		pathNodes := make([]map[string]any, len(p.Nodes))
		for j, n := range p.Nodes {
			pathNodes[j] = map[string]any{
				"symbol": n.Symbol,
				"file":   n.File,
				"line":   n.Line,
			}
		}
		body := map[string]any{
			"call_path":  pathNodes,
			"depth":      p.Depth(),
			"confidence": vexResult.Confidence.String(),
		}
		jsonBytes, _ := json.Marshal(body)
		notes = append(notes, note{
			Category: "details",
			Title:    fmt.Sprintf("Reachability Call Path %d", i+1),
			Text:     string(jsonBytes),
		})
	}

	// Summary note.
	symbols := strings.Join(vexResult.Symbols, ",")
	entryFiles := strings.Join(vexResult.EntryFiles, ",")
	summary := fmt.Sprintf("confidence=%s symbols=%s max_depth=%d entry_files=%s",
		vexResult.Confidence.String(), symbols, vexResult.MaxCallDepth, entryFiles)
	notes = append(notes, note{
		Category: "details",
		Title:    "Reachability Analysis Summary",
		Text:     summary,
	})

	return notes
}
