// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

// Package rust implements a reachability analyzer for Rust using cargo-scan.
package rust

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability"
)

// Analyzer uses cargo-scan to determine reachability in Rust projects.
type Analyzer struct{}

// New returns a new Rust reachability analyzer.
func New() *Analyzer { return &Analyzer{} }

func (a *Analyzer) Language() string { return "rust" }

// Analyze runs cargo-scan on the source directory and checks whether the
// vulnerability identified in the finding is reachable.
func (a *Analyzer) Analyze(ctx context.Context, sourceDir string, finding *formats.Finding) (reachability.Result, error) {
	if _, err := exec.LookPath("cargo-scan"); err != nil {
		return reachability.Result{
			Reachable:  false,
			Confidence: formats.ConfidenceLow,
			Evidence:   fmt.Sprintf("cargo-scan not installed: %v", err),
		}, nil
	}

	output, err := runCargoScan(ctx, sourceDir)
	if err != nil {
		return reachability.Result{
			Reachable:  false,
			Confidence: formats.ConfidenceLow,
			Evidence:   fmt.Sprintf("cargo-scan execution failed: %v", err),
		}, nil
	}

	return parseCargoScanOutput(output, finding), nil
}

// runCargoScan executes cargo-scan in the given directory.
func runCargoScan(ctx context.Context, dir string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "cargo-scan", "scan", "--json")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if len(out) > 0 {
				return out, nil
			}
			return exitErr.Stderr, nil
		}
		return nil, err
	}
	return out, nil
}

// parseCargoScanOutput parses cargo-scan output and determines reachability.
// This is a placeholder implementation that will be adjusted when cargo-scan
// is available and the output format is known.
func parseCargoScanOutput(data []byte, finding *formats.Finding) reachability.Result {
	_ = data
	_ = finding
	return reachability.Result{
		Reachable:  false,
		Confidence: formats.ConfidenceLow,
		Evidence:   "cargo-scan output parsing not yet implemented",
	}
}
