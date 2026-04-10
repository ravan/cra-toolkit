// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"fmt"
)

// Package identifies a package by name and version.
type Package struct {
	Name    string
	Version string
}

// DepGraph is a forward dependency graph: node → its declared dependencies.
// Only packages present in the caller-supplied pinned set are included as nodes.
type DepGraph struct {
	nodes map[string]Package  // name → pinned version
	edges map[string][]string // name → []dep name
	roots []string            // application-root package names
}

// BuildDepGraph constructs a DepGraph by calling fetcher.Manifest for each
// pinned package and intersecting the declared dependencies with the pinned
// set. SBOM dependsOn edges are deliberately ignored — we derive structure
// from authoritative per-package manifests.
func BuildDepGraph(ctx context.Context, fetcher Fetcher, pinned []Package, roots []string) (*DepGraph, error) {
	g := &DepGraph{
		nodes: make(map[string]Package, len(pinned)),
		edges: make(map[string][]string, len(pinned)),
		roots: roots,
	}
	for _, p := range pinned {
		g.nodes[p.Name] = p
	}
	for _, p := range pinned {
		m, err := fetcher.Manifest(ctx, p.Name, p.Version)
		if err != nil {
			// Manifest fetch failures degrade the package to a leaf so the
			// walker can still traverse around it.
			continue
		}
		var deps []string
		for depName := range m.Dependencies {
			if _, ok := g.nodes[depName]; ok {
				deps = append(deps, depName)
			}
		}
		g.edges[p.Name] = deps
	}
	return g, nil
}

// Node returns the pinned Package for name if present.
func (g *DepGraph) Node(name string) (Package, bool) {
	p, ok := g.nodes[name]
	return p, ok
}

// Edges returns the direct dependencies of name in the pinned set.
func (g *DepGraph) Edges(name string) []string {
	return g.edges[name]
}

// Roots returns the application-root package names (direct dependencies of the
// top-level application component).
func (g *DepGraph) Roots() []string {
	return g.roots
}

// PathsTo returns all simple paths from any root to target. Each path starts
// with a root and ends with target. If no path exists, returns nil.
func (g *DepGraph) PathsTo(target string) [][]Package {
	if _, ok := g.nodes[target]; !ok {
		return nil
	}
	var results [][]Package
	for _, root := range g.roots {
		var path []string
		visited := make(map[string]bool)
		g.dfs(root, target, path, visited, &results)
	}
	return results
}

func (g *DepGraph) dfs(cur, target string, path []string, visited map[string]bool, results *[][]Package) {
	if visited[cur] {
		return
	}
	visited[cur] = true
	defer func() { visited[cur] = false }()

	path = append(path, cur)
	if cur == target {
		pkgs := make([]Package, len(path))
		for i, n := range path {
			pkgs[i] = g.nodes[n]
		}
		*results = append(*results, pkgs)
		return
	}
	for _, dep := range g.edges[cur] {
		g.dfs(dep, target, path, visited, results)
	}
}

// MustNode is a convenience for callers that know the node exists.
func (g *DepGraph) MustNode(name string) Package {
	if p, ok := g.nodes[name]; ok {
		return p
	}
	panic(fmt.Sprintf("dep graph: node %q missing", name))
}
