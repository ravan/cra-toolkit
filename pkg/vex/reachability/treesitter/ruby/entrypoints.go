// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package ruby

import (
	"path/filepath"
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter"
)

// RegisterRoutes parses a routes.rb AST and registers controller#action pairs.
// This must be called before FindEntryPoints when Rails routes are available.
func (e *Extractor) RegisterRoutes(src []byte, tree *tree_sitter.Tree) error {
	root := tree.RootNode()
	e.routes = collectRoutes(root, src)
	return nil
}

// collectRoutes walks the AST to find Rails route declarations.
// Supports: get '/path', to: 'controller#action'
//
//nolint:gocognit // recursive visitor with route extraction logic
func collectRoutes(node *tree_sitter.Node, src []byte) []routeAction {
	if node == nil {
		return nil
	}

	var routes []routeAction

	if node.Kind() == "call" {
		route := extractRoute(node, src)
		if route != nil {
			routes = append(routes, *route)
		}
	}

	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		routes = append(routes, collectRoutes(child, src)...)
	}

	return routes
}

// extractRoute attempts to parse a Rails route call node like:
// get '/parse', to: 'pages#parse'
//
//nolint:gocognit,gocyclo // Rails route parsing must scan argument pairs to find the "to:" key
func extractRoute(node *tree_sitter.Node, src []byte) *routeAction {
	if node.ChildCount() == 0 {
		return nil
	}
	first := node.Child(0)
	if first == nil {
		return nil
	}
	methodName := nodeText(first, src)
	// Only process HTTP verb route declarations
	if !isHTTPVerb(methodName) {
		return nil
	}

	argList := node.ChildByFieldName("arguments")
	if argList == nil {
		return nil
	}

	// Look for a pair with key "to" and value like 'pages#parse'
	for i := uint(0); i < argList.ChildCount(); i++ {
		child := argList.Child(i)
		if child == nil || child.Kind() != "pair" {
			continue
		}
		// pair: hash_key_symbol ":" value
		key := ""
		val := ""
		for j := uint(0); j < child.ChildCount(); j++ {
			grandchild := child.Child(j)
			if grandchild == nil {
				continue
			}
			switch grandchild.Kind() {
			case "hash_key_symbol":
				key = nodeText(grandchild, src)
			case "string":
				val = extractStringContent(grandchild, src)
			}
		}
		if key == "to" && val != "" {
			return parseControllerAction(val)
		}
	}
	return nil
}

// isHTTPVerb returns true for Rails route HTTP verb methods.
func isHTTPVerb(name string) bool {
	switch name {
	case "get", "post", "put", "patch", "delete", "options", "head":
		return true
	}
	return false
}

// parseControllerAction parses 'pages#parse' → PagesController::parse.
func parseControllerAction(spec string) *routeAction {
	// spec format: "controller#action"
	// controller name may be namespaced: "admin/pages#index"
	hashIdx := strings.LastIndex(spec, "#")
	if hashIdx < 0 {
		return nil
	}
	controllerPart := spec[:hashIdx]
	action := spec[hashIdx+1:]

	if controllerPart == "" || action == "" {
		return nil
	}

	// Convert controller path to class name: admin/pages → Admin::PagesController
	segments := strings.Split(controllerPart, "/")
	classSegments := make([]string, 0, len(segments))
	for i, seg := range segments {
		if i == len(segments)-1 {
			// Last segment: capitalize and append "Controller"
			classSegments = append(classSegments, capitalize(seg)+"Controller")
		} else {
			classSegments = append(classSegments, capitalize(seg))
		}
	}

	controller := strings.Join(classSegments, "::")

	return &routeAction{
		controller: controller,
		action:     action,
	}
}

// capitalize capitalizes the first letter of a string.
func capitalize(s string) string {
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// FindEntryPoints returns SymbolIDs of methods that are application entry points.
//
// Detection strategies:
//  1. Rails routes → controller actions (if RegisterRoutes was called)
//  2. Rake tasks: symbols with Kind=SymbolFunction prefixed with "task:"
//  3. Sinatra routes: symbols with Kind=SymbolFunction prefixed with "sinatra:"
//  4. Sidekiq workers: methods named "perform" or "perform_async" in worker classes
//  5. bin/* scripts: any top-level symbols are entry points
//
//nolint:gocognit,gocyclo // multi-strategy entry point detection requires multiple condition branches
func (e *Extractor) FindEntryPoints(symbols []*treesitter.Symbol, _ string) []treesitter.SymbolID {
	var eps []treesitter.SymbolID

	// Build a lookup for routed actions: "PagesController::parse" → true
	routedActions := make(map[treesitter.SymbolID]bool, len(e.routes))
	for _, r := range e.routes {
		routedActions[treesitter.SymbolID(r.controller+"::"+r.action)] = true
	}

	for _, sym := range symbols {
		if sym == nil {
			continue
		}

		// Strategy 1: Rails routes
		if len(e.routes) > 0 && sym.Kind == treesitter.SymbolMethod {
			if routedActions[sym.ID] {
				eps = append(eps, sym.ID)
				continue
			}
		}

		// Strategy 2: Rake tasks (already tracked by ID prefix during ExtractSymbols)
		if sym.Kind == treesitter.SymbolFunction && strings.HasPrefix(string(sym.ID), "task:") {
			eps = append(eps, sym.ID)
			continue
		}

		// Strategy 3: Sinatra routes
		if sym.Kind == treesitter.SymbolFunction && strings.HasPrefix(string(sym.ID), "sinatra:") {
			eps = append(eps, sym.ID)
			continue
		}

		// Strategy 4: Sidekiq workers — methods named "perform" or "perform_async"
		if sym.Kind == treesitter.SymbolMethod {
			if sym.Name == "perform" || sym.Name == "perform_async" {
				eps = append(eps, sym.ID)
				continue
			}
		}

		// Strategy 5: bin/* scripts
		if sym.File != "" && isBinFile(sym.File) {
			eps = append(eps, sym.ID)
			continue
		}
	}

	// If no routes were registered, fall back to all controller actions
	if len(e.routes) == 0 {
		for _, sym := range symbols {
			if sym == nil || sym.Kind != treesitter.SymbolMethod {
				continue
			}
			if isControllerClass(sym.Package) {
				eps = append(eps, sym.ID)
			}
		}
	}

	return dedup(eps)
}

// isControllerClass returns true if the class name ends with "Controller".
func isControllerClass(className string) bool {
	return strings.HasSuffix(className, "Controller")
}

// isBinFile returns true if the file is in a bin/ directory.
func isBinFile(file string) bool {
	dir := filepath.ToSlash(filepath.Dir(file))
	base := filepath.Base(dir)
	return base == "bin" || strings.HasSuffix(dir, "/bin")
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
