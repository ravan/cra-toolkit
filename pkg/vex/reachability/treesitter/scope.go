// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package treesitter

// importEntry holds information about an imported module binding for one alias.
// An alias can have multiple entries when the same local name is reassigned to
// different modules within the same file (e.g., body-parser's urlencoded.js
// where `mod = require('qs')` in one branch and `mod = require('querystring')`
// in another). Reachability analysis treats all candidates as potentially
// reachable.
type importEntry struct {
	module  string
	symbols []string
}

// Scope tracks name bindings within a single file or block during AST traversal.
// It supports lexical scoping via a parent chain and import alias resolution.
type Scope struct {
	parent  *Scope
	names   map[string]string
	imports map[string][]importEntry
}

// NewScope creates a new scope. Pass nil for a top-level scope.
func NewScope(parent *Scope) *Scope {
	return &Scope{
		parent:  parent,
		names:   make(map[string]string),
		imports: make(map[string][]importEntry),
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
//
// DefineImport is additive: repeated calls with the same alias accumulate
// candidate modules rather than overwriting. Duplicate (alias, module) pairs
// are coalesced so the same module is not added twice.
func (s *Scope) DefineImport(alias, module string, symbols []string) {
	for _, existing := range s.imports[alias] {
		if existing.module == module {
			return
		}
	}
	s.imports[alias] = append(s.imports[alias], importEntry{module: module, symbols: symbols})
}

// LookupImport returns the first module name bound to the given import alias.
// When an alias resolves to multiple modules, only the first candidate is
// returned; callers that need all candidates should use LookupImports.
func (s *Scope) LookupImport(alias string) (string, bool) {
	if entries, ok := s.imports[alias]; ok && len(entries) > 0 {
		return entries[0].module, true
	}
	if s.parent != nil {
		return s.parent.LookupImport(alias)
	}
	return "", false
}

// LookupImports returns all module names bound to the given import alias.
// An alias can map to multiple modules when it is reassigned within the same
// file (e.g., `mod = require('qs')` in one branch and
// `mod = require('querystring')` in another). Returns nil if the alias is
// unknown.
func (s *Scope) LookupImports(alias string) []string {
	if entries, ok := s.imports[alias]; ok && len(entries) > 0 {
		mods := make([]string, 0, len(entries))
		for _, e := range entries {
			mods = append(mods, e.module)
		}
		return mods
	}
	if s.parent != nil {
		return s.parent.LookupImports(alias)
	}
	return nil
}

// AllImports returns all recorded imports. Multi-valued aliases emit one
// Import per candidate module.
func (s *Scope) AllImports() []Import {
	imports := make([]Import, 0, len(s.imports))
	for alias, entries := range s.imports {
		for _, e := range entries {
			imports = append(imports, Import{
				Module:  e.module,
				Symbols: e.symbols,
				Alias:   alias,
			})
		}
	}
	return imports
}
