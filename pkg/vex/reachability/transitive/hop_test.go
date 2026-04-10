// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"path/filepath"
	"testing"
)

func TestRunHop_Python_FindsCaller(t *testing.T) {
	src, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "testdata", "transitive", "hop", "python-caller"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := RunHop(context.Background(), HopInput{
		Language:      "python",
		SourceDir:     src,
		TargetSymbols: []string{"urllib3.PoolManager"},
		MaxTargets:    100,
	})
	if err != nil {
		t.Fatalf("RunHop: %v", err)
	}
	if len(res.ReachingSymbols) == 0 {
		t.Fatalf("expected at least one reaching symbol")
	}
	found := false
	for _, s := range res.ReachingSymbols {
		if s == "caller.outer_func" || s == "outer_func" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected outer_func in reaching symbols, got %v", res.ReachingSymbols)
	}
}

func TestRunHop_Python_NoCaller(t *testing.T) {
	src, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "testdata", "transitive", "hop", "python-caller"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := RunHop(context.Background(), HopInput{
		Language:      "python",
		SourceDir:     src,
		TargetSymbols: []string{"somepkg.does_not_exist"},
		MaxTargets:    100,
	})
	if err != nil {
		t.Fatalf("RunHop: %v", err)
	}
	if len(res.ReachingSymbols) != 0 {
		t.Errorf("expected no reaching symbols, got %v", res.ReachingSymbols)
	}
}
