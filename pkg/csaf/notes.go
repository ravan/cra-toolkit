package csaf

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
)

func buildDocumentNotes(findings []formats.Finding) []note {
	var cves []string
	seen := make(map[string]bool)
	for i := range findings {
		f := &findings[i]
		if !seen[f.CVE] {
			seen[f.CVE] = true
			cves = append(cves, f.CVE)
		}
	}
	return []note{{
		Category: "summary",
		Title:    "Advisory Summary",
		Text:     fmt.Sprintf("Security advisory addressing %d vulnerability(ies): %s.", len(cves), strings.Join(cves, ", ")),
	}}
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
