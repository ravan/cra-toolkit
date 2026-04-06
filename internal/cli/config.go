// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package cli

import (
	"context"

	urfave "github.com/urfave/cli/v3"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/vex"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability"
)

// HookFn is a hook function signature matching toolkit.HookFunc.
// Defined here to avoid a circular import with pkg/toolkit.
type HookFn = func(ctx context.Context, pkg string, opts any, err error) error

// RunConfig carries extension registrations from the toolkit facade
// through the CLI layer into each package's Run() function.
type RunConfig struct {
	ExtraFilters      []vex.Filter
	ExtraAnalyzers    map[string]reachability.Analyzer
	ExtraCommands     []*urfave.Command
	ExtraScanParsers  map[formats.Format]formats.ScanParser
	ExtraSBOMParsers  map[formats.Format]formats.SBOMParser
	ExtraVEXWriters   map[string]formats.VEXWriter
	ExtraFormatProbes []formats.FormatProbe
	PreHooks          map[string][]HookFn
	PostHooks         map[string][]HookFn
}
