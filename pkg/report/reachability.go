// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package report

import (
	"fmt"
	"strings"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
)

// renderNode renders a single call graph node for display.
func renderNode(j int, n formats.CallNode) string {
	loc := "<dependency>:0"
	if n.File != "" {
		loc = fmt.Sprintf("%s:%d", n.File, n.Line)
	}
	if j == 0 {
		return fmt.Sprintf("      %s  [%s]\n", n.Symbol, loc)
	}
	indent := strings.Repeat("  ", j)
	return fmt.Sprintf("      %s→ %s  [%s]\n", indent, n.Symbol, loc)
}

// ReachabilityDetail renders a human-readable reachability evidence block
// for an auditor. Returns empty string for non-reachability results.
func ReachabilityDetail(v *formats.VEXResult) string {
	if v.ResolvedBy != "reachability_analysis" {
		return ""
	}

	var b strings.Builder
	b.WriteString("Reachability Evidence:\n")

	if len(v.CallPaths) == 0 {
		b.WriteString("  No call path found from application entry points to vulnerable symbol.\n")
		if len(v.Symbols) > 0 {
			b.WriteString(fmt.Sprintf("  Symbols checked: %s\n", strings.Join(v.Symbols, ", ")))
		}
		b.WriteString(fmt.Sprintf("  Confidence: %s\n", v.Confidence.String()))
		return b.String()
	}

	if len(v.Symbols) > 0 {
		b.WriteString(fmt.Sprintf("  Symbols: %s\n", strings.Join(v.Symbols, ", ")))
	}
	b.WriteString(fmt.Sprintf("  Call paths (%d):\n", len(v.CallPaths)))

	for i, p := range v.CallPaths {
		b.WriteString(fmt.Sprintf("    Path %d (depth %d):\n", i+1, p.Depth()))
		for j, n := range p.Nodes {
			b.WriteString(renderNode(j, n))
		}
	}

	return b.String()
}
