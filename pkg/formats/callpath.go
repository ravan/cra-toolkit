package formats

import (
	"fmt"
	"strings"
)

// CallNode represents a single node in a call path.
type CallNode struct {
	Symbol string // qualified name (e.g., "com.example.App.process")
	File   string // repo-relative file path
	Line   int    // 1-based; 0 if unknown
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

// Depth returns the number of nodes in the call path.
func (p CallPath) Depth() int {
	return len(p.Nodes)
}

// EntryPoint returns the first node in the call path.
// Panics if the path is empty.
func (p CallPath) EntryPoint() CallNode {
	return p.Nodes[0]
}
