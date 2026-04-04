// Package treesitter provides the shared tree-sitter analysis core for
// building interprocedural call graphs and performing reachability analysis
// across multiple programming languages.
package treesitter

import "strings"

// SymbolID uniquely identifies a symbol within a project.
type SymbolID string

// NewSymbolID creates a SymbolID from package path components.
// Example: NewSymbolID("myapp", "handler", "process") → "myapp.handler.process"
func NewSymbolID(parts ...string) SymbolID {
	return SymbolID(strings.Join(parts, "."))
}

// Symbol represents a code symbol (function, method, class, module) extracted
// from a source file's AST.
type Symbol struct {
	ID            SymbolID
	Name          string
	QualifiedName string
	Language      string
	File          string
	Package       string
	StartLine     int
	EndLine       int
	Kind          SymbolKind
	IsEntryPoint  bool
	IsExternal    bool
}

// SymbolKind classifies what kind of code construct a symbol represents.
type SymbolKind int

const (
	SymbolFunction SymbolKind = iota
	SymbolMethod
	SymbolClass
	SymbolModule
)

func (k SymbolKind) String() string {
	switch k {
	case SymbolFunction:
		return "function"
	case SymbolMethod:
		return "method"
	case SymbolClass:
		return "class"
	case SymbolModule:
		return "module"
	default:
		return "unknown"
	}
}

// Import represents a module import extracted from source code.
type Import struct {
	Module  string
	Symbols []string
	Alias   string
	File    string
	Line    int
}

// Edge represents a call relationship between two symbols in the graph.
type Edge struct {
	From       SymbolID
	To         SymbolID
	Kind       EdgeKind
	Confidence float64
	File       string
	Line       int
}

// EdgeKind classifies the type of call relationship.
type EdgeKind int

const (
	EdgeDirect   EdgeKind = iota
	EdgeDispatch
	EdgeImport
)

func (k EdgeKind) String() string {
	switch k {
	case EdgeDirect:
		return "direct"
	case EdgeDispatch:
		return "dispatch"
	case EdgeImport:
		return "import"
	default:
		return "unknown"
	}
}
