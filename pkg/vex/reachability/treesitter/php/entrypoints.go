package php

import (
	"path/filepath"
	"strings"

	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter"
)

// isRouteAttribute returns true if the attribute name is a known route attribute.
// Supports Symfony #[Route] and similar conventions.
func isRouteAttribute(attr string) bool {
	// Strip argument list if present, e.g. "@Route('/path')" → "@Route"
	name := attr
	if idx := strings.IndexByte(attr, '('); idx > 0 {
		name = attr[:idx]
	}
	name = strings.TrimSpace(name)

	switch name {
	case "@Route", "@Get", "@Post", "@Put", "@Delete", "@Patch":
		return true
	}
	return false
}

// isControllerClass returns true if the class name ends with "Controller" or "Action".
func isControllerClass(className string) bool {
	return strings.HasSuffix(className, "Controller") || strings.HasSuffix(className, "Action")
}

// isIndexFile returns true if the file is an index.php entry point.
func isIndexFile(file string) bool {
	return filepath.Base(file) == "index.php"
}

// FindEntryPoints returns SymbolIDs of methods that are application entry points.
//
// Detection strategies:
//  1. Symfony #[Route] — controller actions decorated with route attributes
//  2. Public methods in classes ending with "Controller" or "Action"
//  3. index.php — all functions/methods in the file are entry points
//  4. Laravel Route::get/post/etc. — detected via scoped calls at file level (handled by mapHandlers)
//
//nolint:gocognit,gocyclo // entry point detection checks multiple strategies
func (e *Extractor) FindEntryPoints(symbols []*treesitter.Symbol, _ string) []treesitter.SymbolID {
	var eps []treesitter.SymbolID

	for _, sym := range symbols {
		if sym == nil {
			continue
		}
		if sym.Kind != treesitter.SymbolMethod {
			continue
		}

		// 1. #[Route] or similar HTTP attribute on method
		attrs, hasAttrs := e.attributes[sym.ID]
		if hasAttrs {
			for _, attr := range attrs {
				if isRouteAttribute(attr) {
					eps = append(eps, sym.ID)
					break
				}
			}
		}

		// 2. Public method in a *Controller or *Action class
		if isControllerClass(sym.Package) || isControllerClass(e.classOf[sym.ID]) {
			if e.publicMethods[sym.ID] {
				eps = append(eps, sym.ID)
			}
		}

		// 3. index.php entry point: any function/method in the file
		if isIndexFile(sym.File) {
			eps = append(eps, sym.ID)
		}
	}

	return dedup(eps)
}

// dedup removes duplicate SymbolIDs while preserving order.
func dedup(ids []treesitter.SymbolID) []treesitter.SymbolID {
	seen := make(map[treesitter.SymbolID]bool, len(ids))
	result := make([]treesitter.SymbolID, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			result = append(result, id)
		}
	}
	return result
}
