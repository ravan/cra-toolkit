// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package treesitter

// importEntry holds information about an imported module.
type importEntry struct {
	module  string
	symbols []string
}

// Scope tracks name bindings within a single file or block during AST traversal.
// It supports lexical scoping via a parent chain and import alias resolution.
type Scope struct {
	parent  *Scope
	names   map[string]string
	imports map[string]importEntry
}

// NewScope creates a new scope. Pass nil for a top-level scope.
func NewScope(parent *Scope) *Scope {
	return &Scope{
		parent:  parent,
		names:   make(map[string]string),
		imports: make(map[string]importEntry),
	}
}

// Define binds a local name to a fully-qualified symbol ID in this scope.
func (s *Scope) Define(name, qualifiedName string) {
	s.names[name] = qualifiedName
}

// Lookup resolves a name to its fully-qualified symbol ID, walking up the
// parent chain if not found in the current scope.
func (s *Scope) Lookup(name string) (string, bool) {
	if q, ok := s.names[name]; ok {
		return q, true
	}
	if s.parent != nil {
		return s.parent.Lookup(name)
	}
	return "", false
}

// DefineImport records a module import, optionally with an alias.
// alias is the local name (e.g., "yaml" for "import yaml as yaml").
func (s *Scope) DefineImport(alias, module string, symbols []string) {
	s.imports[alias] = importEntry{module: module, symbols: symbols}
}

// LookupImport returns the module name for a given import alias.
func (s *Scope) LookupImport(alias string) (string, bool) {
	if e, ok := s.imports[alias]; ok {
		return e.module, true
	}
	return "", false
}

// AllImports returns all recorded imports.
func (s *Scope) AllImports() []Import {
	imports := make([]Import, 0, len(s.imports))
	for alias, e := range s.imports {
		imports = append(imports, Import{
			Module:  e.module,
			Symbols: e.symbols,
			Alias:   alias,
		})
	}
	return imports
}
