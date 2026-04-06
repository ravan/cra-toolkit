// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package toolkit

import (
	"context"
	"fmt"

	urfave "github.com/urfave/cli/v3"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/vex"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability"
)

var validPackages = map[string]bool{
	"vex": true, "report": true, "csaf": true, "evidence": true, "policykit": true,
}

// RunConfig carries extension registrations from the toolkit facade
// through the CLI layer into each package's Run() function.
// This duplicates internal/cli.RunConfig to avoid a circular import;
// the CLI layer converts between the two at the boundary.
type RunConfig struct {
	ExtraFilters      []vex.Filter
	ExtraAnalyzers    map[string]reachability.Analyzer
	ExtraCommands     []*urfave.Command
	ExtraScanParsers  map[formats.Format]formats.ScanParser
	ExtraSBOMParsers  map[formats.Format]formats.SBOMParser
	ExtraVEXWriters   map[string]formats.VEXWriter
	ExtraFormatProbes []formats.FormatProbe
	PreHooks          map[string][]HookFunc
	PostHooks         map[string][]HookFunc
}

// CLIRunner is the function signature for creating and running the CLI.
// This indirection avoids a circular import between pkg/toolkit and internal/cli.
type CLIRunner func(version string, cfg *RunConfig, ctx context.Context, args []string) error

// App is the public facade for the CRA toolkit.
// Phase 2 extension modules create an App, register their extensions,
// and call RunCLI to start the CLI.
type App struct {
	version     string
	filters     []vex.Filter
	analyzers   map[string]reachability.Analyzer
	commands    []*urfave.Command
	scanParsers map[formats.Format]formats.ScanParser
	sbomParsers map[formats.Format]formats.SBOMParser
	vexWriters  map[string]formats.VEXWriter
	preHooks    map[string][]HookFunc
	postHooks   map[string][]HookFunc
	probes      []formats.FormatProbe
	cliRunner   CLIRunner
}

// New creates a new App with the given version string.
func New(version string) *App {
	return &App{
		version:     version,
		analyzers:   make(map[string]reachability.Analyzer),
		scanParsers: make(map[formats.Format]formats.ScanParser),
		sbomParsers: make(map[formats.Format]formats.SBOMParser),
		vexWriters:  make(map[string]formats.VEXWriter),
		preHooks:    make(map[string][]HookFunc),
		postHooks:   make(map[string][]HookFunc),
	}
}

// SetCLIRunner sets the function used by RunCLI to create and run the CLI.
// This is typically called once by the main package to inject the internal/cli dependency.
func (a *App) SetCLIRunner(r CLIRunner) {
	a.cliRunner = r
}

// RegisterFilter adds a VEX filter to the extension pipeline.
func (a *App) RegisterFilter(f vex.Filter) { a.filters = append(a.filters, f) }

// RegisterAnalyzer adds a reachability analyzer for the given language.
func (a *App) RegisterAnalyzer(lang string, az reachability.Analyzer) { a.analyzers[lang] = az }

// RegisterCommand adds a custom CLI subcommand.
func (a *App) RegisterCommand(cmd *urfave.Command) { a.commands = append(a.commands, cmd) }

// RegisterScanParser adds a scan result parser for the given format.
func (a *App) RegisterScanParser(format formats.Format, p formats.ScanParser) {
	a.scanParsers[format] = p
}

// RegisterSBOMParser adds an SBOM parser for the given format.
func (a *App) RegisterSBOMParser(format formats.Format, p formats.SBOMParser) {
	a.sbomParsers[format] = p
}

// RegisterVEXWriter adds a VEX output writer with the given name.
func (a *App) RegisterVEXWriter(name string, w formats.VEXWriter) { a.vexWriters[name] = w }

// RegisterFormatProbe adds a format detection probe.
func (a *App) RegisterFormatProbe(p formats.FormatProbe) { a.probes = append(a.probes, p) }

// RegisterHook registers a pre or post hook for the given package.
// Valid packages: vex, report, csaf, evidence, policykit.
func (a *App) RegisterHook(pkg string, h Hook) error {
	if !validPackages[pkg] {
		return fmt.Errorf("invalid hook package %q: must be one of vex, report, csaf, evidence, policykit", pkg)
	}
	if h.Phase == Pre {
		a.preHooks[pkg] = append(a.preHooks[pkg], h.Fn)
	} else {
		a.postHooks[pkg] = append(a.postHooks[pkg], h.Fn)
	}
	return nil
}

// BuildConfig returns a RunConfig populated with all registered extensions.
func (a *App) BuildConfig() *RunConfig {
	return &RunConfig{
		ExtraFilters:      a.filters,
		ExtraAnalyzers:    a.analyzers,
		ExtraCommands:     a.commands,
		ExtraScanParsers:  a.scanParsers,
		ExtraSBOMParsers:  a.sbomParsers,
		ExtraVEXWriters:   a.vexWriters,
		ExtraFormatProbes: a.probes,
		PreHooks:          a.preHooks,
		PostHooks:         a.postHooks,
	}
}

// RunCLI builds the CLI from the registered extensions and runs it.
func (a *App) RunCLI(ctx context.Context, args []string) error {
	if a.cliRunner == nil {
		return fmt.Errorf("toolkit: CLI runner not set; call SetCLIRunner before RunCLI")
	}
	return a.cliRunner(a.version, a.BuildConfig(), ctx, args)
}
