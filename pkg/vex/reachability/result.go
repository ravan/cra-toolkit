package reachability

import (
	"fmt"
	"strings"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
)

// Result holds the outcome of a reachability analysis.
type Result struct {
	Reachable  bool               // whether the vulnerable code is reachable
	Confidence formats.Confidence // confidence level of the determination
	Evidence   string             // human-readable evidence description
	Symbols    []string           // symbols found to be reachable (if any)
	Paths      []CallPath         // call paths from entry points to vulnerable symbols
}

// CallPath represents a call chain from an entry point to a vulnerable symbol.
type CallPath struct {
	Nodes []CallNode
}

// String returns a human-readable representation of the call path.
func (p CallPath) String() string {
	parts := make([]string, len(p.Nodes))
	for i, n := range p.Nodes {
		if n.File != "" && n.Line > 0 {
			parts[i] = fmt.Sprintf("%s (%s:%d)", n.Symbol, n.File, n.Line)
		} else {
			parts[i] = n.Symbol
		}
	}
	return strings.Join(parts, " -> ")
}

// CallNode represents a single node in a call path.
type CallNode struct {
	Symbol string // qualified name (e.g., "myapp.handler.process")
	File   string // relative file path
	Line   int    // line number (1-based, 0 if unknown)
}
