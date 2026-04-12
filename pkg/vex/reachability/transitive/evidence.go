// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"github.com/ravan/cra-toolkit/pkg/formats"
)

// DeepestPath selects the single path with the most nodes from a slice of
// alternative paths. RunHop returns one path per reaching symbol (each tracing
// from that caller back to the target); only the deepest path captures the
// full call chain and should be used for stitching.
func DeepestPath(paths []formats.CallPath) formats.CallPath {
	var best formats.CallPath
	for _, p := range paths {
		if len(p.Nodes) > len(best.Nodes) {
			best = p
		}
	}
	return best
}

// StitchCallPaths concatenates a sequence of per-hop call paths into a single
// continuous path. Adjacent hops are expected to share a boundary node
// (the last node of hop N equals the first node of hop N+1); if they do, the
// duplicate is elided. Non-overlapping hops are concatenated as-is.
func StitchCallPaths(parts []formats.CallPath) formats.CallPath {
	var out formats.CallPath
	for i, p := range parts {
		if len(p.Nodes) == 0 {
			continue
		}
		if i == 0 {
			out.Nodes = append(out.Nodes, p.Nodes...)
			continue
		}
		start := 0
		if len(out.Nodes) > 0 && out.Nodes[len(out.Nodes)-1].Symbol == p.Nodes[0].Symbol {
			start = 1
		}
		out.Nodes = append(out.Nodes, p.Nodes[start:]...)
	}
	return out
}
