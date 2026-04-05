// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package reachability

import (
	"context"

	"github.com/ravan/cra-toolkit/pkg/formats"
)

// Analyzer performs reachability analysis for a specific language ecosystem.
type Analyzer interface {
	// Language returns the language this analyzer supports (e.g. "go", "python").
	Language() string
	// Analyze determines whether vulnerable code in the finding is reachable
	// from source code in sourceDir.
	Analyze(ctx context.Context, sourceDir string, finding *formats.Finding) (Result, error)
}
