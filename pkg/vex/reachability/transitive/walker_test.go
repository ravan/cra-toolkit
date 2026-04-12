// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/python"
)

// stubHopRunner records calls and returns canned results so the walker's
// orchestration and short-circuit logic can be exercised without real parsing.
type stubHopRunner struct {
	calls   []HopInput
	results map[string]HopResult // keyed by SourceDir (proxy for package)
}

func (s *stubHopRunner) Run(ctx context.Context, in HopInput) (HopResult, error) {
	s.calls = append(s.calls, in)
	if r, ok := s.results[in.SourceDir]; ok {
		return r, nil
	}
	return HopResult{}, nil
}

// stubFetcher returns a deterministic source dir per (name, version) without
// making any network calls.
type stubFetcher struct{}

func (stubFetcher) Ecosystem() string { return "stub" }
func (stubFetcher) Fetch(ctx context.Context, name, version string, _ *Digest) (FetchResult, error) {
	return FetchResult{SourceDir: "/pkg/" + name + "@" + version}, nil
}

func (stubFetcher) Manifest(ctx context.Context, name, version string) (PackageManifest, error) {
	return PackageManifest{}, nil
}

func TestWalker_Reachable_StitchesCallPaths(t *testing.T) {
	// Path: app → D1 → D2 → V
	path := []Package{
		{Name: "D1", Version: "1"},
		{Name: "D2", Version: "1"},
		{Name: "V", Version: "1"},
	}
	hops := &stubHopRunner{
		results: map[string]HopResult{
			"/pkg/D2@1": {ReachingSymbols: []string{"D2.foo"}},
			"/pkg/D1@1": {ReachingSymbols: []string{"D1.bar"}},
		},
	}
	w := &Walker{
		Fetcher:     stubFetcher{},
		Hop:         hops.Run,
		Config:      DefaultConfig(),
		Language:    python.New(),
		InitialTarg: []string{"V.entry"},
	}
	res, err := w.WalkPath(context.Background(), path)
	if err != nil {
		t.Fatalf("WalkPath: %v", err)
	}
	if !res.Completed {
		t.Fatalf("expected path to complete walking to D1, res=%+v", res)
	}
	if len(res.FinalTargets) == 0 {
		t.Errorf("expected non-empty FinalTargets")
	}
	// Expect one hop per intermediate package (D2, D1) — 2 hops.
	if len(hops.calls) != 2 {
		t.Errorf("expected 2 hops, got %d", len(hops.calls))
	}
}

func TestWalker_ShortCircuit_OnBrokenLink(t *testing.T) {
	path := []Package{
		{Name: "D1", Version: "1"},
		{Name: "D2", Version: "1"},
		{Name: "V", Version: "1"},
	}
	hops := &stubHopRunner{
		results: map[string]HopResult{
			// D2 has no caller of V → broken at D2 → V link.
			"/pkg/D2@1": {ReachingSymbols: nil},
			// D1 would reach if we got there, but we should not.
			"/pkg/D1@1": {ReachingSymbols: []string{"D1.bar"}},
		},
	}
	w := &Walker{
		Fetcher:     stubFetcher{},
		Hop:         hops.Run,
		Config:      DefaultConfig(),
		Language:    python.New(),
		InitialTarg: []string{"V.entry"},
	}
	res, err := w.WalkPath(context.Background(), path)
	if err != nil {
		t.Fatalf("WalkPath: %v", err)
	}
	if res.Completed {
		t.Errorf("expected short-circuit, but path completed")
	}
	if res.BrokenAt != "D2" {
		t.Errorf("expected BrokenAt=D2, got %q", res.BrokenAt)
	}
	// Walker must not fetch D1 after D2 short-circuits.
	if len(hops.calls) != 1 {
		t.Errorf("expected exactly 1 hop (D2), got %d", len(hops.calls))
	}
}

// TestWalker_HopPaths_Propagated verifies that per-hop Paths returned by the
// HopRunner are collected into WalkResult.HopPaths.
func TestWalker_HopPaths_Propagated(t *testing.T) {
	path := []Package{
		{Name: "D1", Version: "1"},
		{Name: "V", Version: "1"},
	}
	hopPath := formats.CallPath{Nodes: []formats.CallNode{
		{Symbol: "D1.bar", File: "d1.py", Line: 5},
		{Symbol: "V.entry"},
	}}
	hops := &stubHopRunner{
		results: map[string]HopResult{
			"/pkg/D1@1": {
				ReachingSymbols: []string{"D1.bar"},
				Paths:           []formats.CallPath{hopPath},
			},
		},
	}
	w := &Walker{
		Fetcher:     stubFetcher{},
		Hop:         hops.Run,
		Config:      DefaultConfig(),
		Language:    python.New(),
		InitialTarg: []string{"V.entry"},
	}
	res, err := w.WalkPath(context.Background(), path)
	if err != nil {
		t.Fatalf("WalkPath: %v", err)
	}
	if !res.Completed {
		t.Fatalf("expected Completed, got BrokenAt=%q", res.BrokenAt)
	}
	if len(res.HopPaths) != 1 {
		t.Errorf("expected 1 hop path in WalkResult.HopPaths, got %d", len(res.HopPaths))
	}
}

func TestWalker_HopBoundExceeded(t *testing.T) {
	longPath := make([]Package, 10)
	for i := range longPath {
		longPath[i] = Package{Name: "N" + string(rune('A'+i)), Version: "1"}
	}
	hops := &stubHopRunner{results: map[string]HopResult{}}
	cfg := DefaultConfig()
	cfg.MaxHopsPerPath = 3
	w := &Walker{
		Fetcher:     stubFetcher{},
		Hop:         hops.Run,
		Config:      cfg,
		Language:    python.New(),
		InitialTarg: []string{"target"},
	}
	res, _ := w.WalkPath(context.Background(), longPath)
	if res.BoundExceeded != "max_hops" {
		t.Errorf("expected BoundExceeded=max_hops, got %q", res.BoundExceeded)
	}
}
