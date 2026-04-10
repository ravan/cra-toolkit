// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"testing"
)

// fakeFetcher satisfies Fetcher for manifest-only tests by returning canned
// dependency maps.
type fakeFetcher struct {
	eco       string
	manifests map[string]map[string]string // "name@version" → deps
}

func (f *fakeFetcher) Ecosystem() string { return f.eco }

func (f *fakeFetcher) Fetch(ctx context.Context, name, version string, _ *Digest) (FetchResult, error) {
	return FetchResult{}, nil
}

func (f *fakeFetcher) Manifest(ctx context.Context, name, version string) (PackageManifest, error) {
	key := name + "@" + version
	deps, ok := f.manifests[key]
	if !ok {
		return PackageManifest{}, nil
	}
	return PackageManifest{Dependencies: deps}, nil
}

func TestBuildDepGraph_PrunesToVulnerable(t *testing.T) {
	pinned := []Package{
		{Name: "flask", Version: "2.0.1"},
		{Name: "werkzeug", Version: "2.0.2"},
		{Name: "requests", Version: "2.26.0"},
		{Name: "urllib3", Version: "1.26.5"},
		{Name: "unrelated", Version: "1.0.0"},
	}
	roots := []string{"flask", "requests"}
	fetcher := &fakeFetcher{
		eco: "pypi",
		manifests: map[string]map[string]string{
			"flask@2.0.1":     {"werkzeug": ""},
			"werkzeug@2.0.2":  {"urllib3": ""},
			"requests@2.26.0": {"urllib3": ""},
			"urllib3@1.26.5":  {},
			"unrelated@1.0.0": {},
		},
	}
	g, err := BuildDepGraph(context.Background(), fetcher, pinned, roots)
	if err != nil {
		t.Fatalf("BuildDepGraph: %v", err)
	}

	paths := g.PathsTo("urllib3")
	if len(paths) != 2 {
		t.Errorf("expected 2 paths to urllib3, got %d: %v", len(paths), paths)
	}
	for _, p := range paths {
		if p[len(p)-1].Name != "urllib3" {
			t.Errorf("path does not end at urllib3: %v", p)
		}
	}

	// Verify unrelated exists in the full graph (we only prune at PathsTo).
	if _, ok := g.Node("unrelated"); !ok {
		t.Errorf("expected unrelated to be in the graph")
	}
}

func TestBuildDepGraph_NoPath(t *testing.T) {
	pinned := []Package{
		{Name: "a", Version: "1"},
		{Name: "b", Version: "1"},
	}
	fetcher := &fakeFetcher{
		eco: "pypi",
		manifests: map[string]map[string]string{
			"a@1": {},
			"b@1": {},
		},
	}
	g, err := BuildDepGraph(context.Background(), fetcher, pinned, []string{"a"})
	if err != nil {
		t.Fatal(err)
	}
	if paths := g.PathsTo("b"); len(paths) != 0 {
		t.Errorf("expected 0 paths to b, got %d", len(paths))
	}
}
