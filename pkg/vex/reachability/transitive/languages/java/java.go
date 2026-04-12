// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

// Package java provides the Java LanguageSupport implementation for the
// transitive cross-package reachability analyzer. It is imported only
// by the transitive package's LanguageFor factory.
package java

import (
	"path/filepath"
	"strings"
	"unsafe"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
	grammarjava "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/java"
	javaextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/java"
)

// Language is the Java LanguageSupport implementation. Callers use New
// to construct a value; the zero value is not valid.
type Language struct {
	extractor *chaExtractor
}

// New returns a fresh Java Language. The extractor wraps the raw Java
// extractor with CrossFileStateExtractor delegation for CHA.
func New() *Language {
	return &Language{extractor: &chaExtractor{inner: javaextractor.New()}}
}

func (l *Language) Name() string                            { return "java" }
func (l *Language) Ecosystem() string                       { return "maven" }
func (l *Language) FileExtensions() []string                { return []string{".java"} }
func (l *Language) Grammar() unsafe.Pointer                 { return grammarjava.Language() }
func (l *Language) Extractor() treesitter.LanguageExtractor { return l.extractor }

// IsExportedSymbol reports whether a symbol is part of the Java package's
// public API. Java's visibility model is explicit — public means exported.
func (l *Language) IsExportedSymbol(sym *treesitter.Symbol) bool {
	if sym == nil {
		return false
	}
	if !sym.IsPublic {
		return false
	}
	switch sym.Kind {
	case treesitter.SymbolFunction, treesitter.SymbolMethod, treesitter.SymbolClass:
		return true
	}
	return false
}

// ModulePath derives a dotted module path for a Java source file relative
// to sourceDir. Strips the conventional src/main/java/ prefix when present:
//
//	src/main/java/com/google/gson/Gson.java → "gson.com.google.gson.Gson"
//	com/example/Service.java                → "lib.com.example.Service"
func (l *Language) ModulePath(file, sourceDir, packageName string) string {
	rel, err := filepath.Rel(sourceDir, file)
	if err != nil || strings.HasPrefix(rel, "..") {
		return packageName
	}
	rel = strings.TrimSuffix(rel, filepath.Ext(rel))
	parts := strings.Split(rel, string(filepath.Separator))
	// Strip conventional src/main/java/ prefix.
	if len(parts) >= 3 && parts[0] == "src" && parts[1] == "main" && parts[2] == "java" {
		parts = parts[3:]
	}
	if len(parts) == 0 {
		return packageName
	}
	mod := strings.Join(parts, ".")
	return packageName + "." + mod
}

// SymbolKey composes a dotted symbol key: "<modulePath>.<symbolName>".
func (l *Language) SymbolKey(modulePath, symbolName string) string {
	return modulePath + "." + symbolName
}

// NormalizeImports is the identity function for Java. Java imports are
// already fully-qualified dotted paths. No rewriting is required.
func (l *Language) NormalizeImports(raw []treesitter.Import) []treesitter.Import {
	return raw
}

// ResolveDottedTarget resolves a dotted call target whose prefix is an
// import alias. For example, given "Logger" and a scope where "Logger"
// maps to "org.apache.logging.log4j.Logger", returns
// "org.apache.logging.log4j.Logger.getLogger" for suffix="getLogger".
func (l *Language) ResolveDottedTarget(prefix, suffix string, scope *treesitter.Scope) (treesitter.SymbolID, bool) {
	resolved, ok := scope.LookupImport(prefix)
	if !ok {
		return "", false
	}
	return treesitter.SymbolID(resolved + "." + suffix), true
}

// ResolveSelfCall rewrites "this.X" call targets to the class-qualified
// form "ClassName.X" by extracting the class context from the caller's
// symbol ID. Only applies when `from` has at least three dot-separated
// components (package.class.method).
func (l *Language) ResolveSelfCall(to, from treesitter.SymbolID) treesitter.SymbolID {
	toStr := string(to)
	if !strings.HasPrefix(toStr, "this.") {
		return to
	}
	methodName := toStr[len("this."):]
	fromParts := strings.Split(string(from), ".")
	if len(fromParts) < 3 {
		return to
	}
	classQual := strings.Join(fromParts[:len(fromParts)-1], ".")
	return treesitter.SymbolID(classQual + "." + methodName)
}

// chaExtractor wraps the raw Java tree-sitter extractor and implements
// the CrossFileStateExtractor interface by delegating to the Java
// extractor's SnapshotCHA/RestoreCHA methods.
type chaExtractor struct {
	inner *javaextractor.Extractor
}

func (e *chaExtractor) ExtractSymbols(file string, source []byte, tree *tree_sitter.Tree) ([]*treesitter.Symbol, error) {
	return e.inner.ExtractSymbols(file, source, tree)
}

func (e *chaExtractor) ResolveImports(file string, source []byte, tree *tree_sitter.Tree, projectRoot string) ([]treesitter.Import, error) {
	return e.inner.ResolveImports(file, source, tree, projectRoot)
}

func (e *chaExtractor) ExtractCalls(file string, source []byte, tree *tree_sitter.Tree, scope *treesitter.Scope) ([]treesitter.Edge, error) {
	return e.inner.ExtractCalls(file, source, tree, scope)
}

func (e *chaExtractor) FindEntryPoints(symbols []*treesitter.Symbol, projectRoot string) []treesitter.SymbolID {
	return e.inner.FindEntryPoints(symbols, projectRoot)
}

// SnapshotState captures the CHA cross-file state for restoration.
func (e *chaExtractor) SnapshotState() any {
	return e.inner.SnapshotCHA()
}

// RestoreState merges a CHA snapshot back into the extractor.
func (e *chaExtractor) RestoreState(s any) {
	if snap, ok := s.(*javaextractor.CHASnapshot); ok {
		e.inner.RestoreCHA(snap)
	}
}
