// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package toolkit_test

import (
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	urfave "github.com/urfave/cli/v3"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/toolkit"
	"github.com/ravan/cra-toolkit/pkg/vex"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability"
)

// --- test stubs ---

type stubFilter struct{ name string }

func (f *stubFilter) Name() string { return f.name }
func (f *stubFilter) Evaluate(_ *formats.Finding, _ []formats.Component) (vex.Result, bool) {
	return vex.Result{}, false
}

type stubAnalyzer struct{ lang string }

func (a *stubAnalyzer) Language() string { return a.lang }
func (a *stubAnalyzer) Analyze(_ context.Context, _ string, _ *formats.Finding) (reachability.Result, error) {
	return reachability.Result{Reachable: false}, nil
}

type stubScanParser struct{}

func (p *stubScanParser) Parse(_ io.Reader) ([]formats.Finding, error) { return nil, nil }

type stubSBOMParser struct{}

func (p *stubSBOMParser) Parse(_ io.Reader) ([]formats.Component, error) { return nil, nil }

type stubVEXWriter struct{}

func (w *stubVEXWriter) Write(_ io.Writer, _ []formats.VEXResult) error { return nil }

// --- tests ---

func TestNew(t *testing.T) {
	app := toolkit.New("1.0.0")
	require.NotNil(t, app)
}

func TestRegisterFilter(t *testing.T) {
	app := toolkit.New("1.0.0")
	f1 := &stubFilter{name: "f1"}
	f2 := &stubFilter{name: "f2"}

	app.RegisterFilter(f1)
	app.RegisterFilter(f2)

	cfg := app.BuildConfig()
	require.Len(t, cfg.ExtraFilters, 2)
	assert.Equal(t, "f1", cfg.ExtraFilters[0].Name())
	assert.Equal(t, "f2", cfg.ExtraFilters[1].Name())
}

func TestRegisterAnalyzer(t *testing.T) {
	app := toolkit.New("1.0.0")
	goAz := &stubAnalyzer{lang: "go"}
	rustAz := &stubAnalyzer{lang: "rust"}

	app.RegisterAnalyzer("go", goAz)
	app.RegisterAnalyzer("rust", rustAz)

	cfg := app.BuildConfig()
	require.Len(t, cfg.ExtraAnalyzers, 2)
	assert.Equal(t, "go", cfg.ExtraAnalyzers["go"].Language())
	assert.Equal(t, "rust", cfg.ExtraAnalyzers["rust"].Language())
}

func TestRegisterAnalyzer_DuplicateOverwrites(t *testing.T) {
	app := toolkit.New("1.0.0")
	az1 := &stubAnalyzer{lang: "go-v1"}
	az2 := &stubAnalyzer{lang: "go-v2"}

	app.RegisterAnalyzer("go", az1)
	app.RegisterAnalyzer("go", az2)

	cfg := app.BuildConfig()
	require.Len(t, cfg.ExtraAnalyzers, 1)
	assert.Equal(t, "go-v2", cfg.ExtraAnalyzers["go"].Language())
}

func TestRegisterCommand(t *testing.T) {
	app := toolkit.New("1.0.0")
	cmd := &urfave.Command{Name: "custom"}

	app.RegisterCommand(cmd)

	cfg := app.BuildConfig()
	require.Len(t, cfg.ExtraCommands, 1)
	assert.Equal(t, "custom", cfg.ExtraCommands[0].Name)
}

func TestRegisterScanParser(t *testing.T) {
	app := toolkit.New("1.0.0")
	p := &stubScanParser{}

	app.RegisterScanParser(formats.FormatGrype, p)

	cfg := app.BuildConfig()
	require.Len(t, cfg.ExtraScanParsers, 1)
	assert.NotNil(t, cfg.ExtraScanParsers[formats.FormatGrype])
}

func TestRegisterSBOMParser(t *testing.T) {
	app := toolkit.New("1.0.0")
	p := &stubSBOMParser{}

	app.RegisterSBOMParser(formats.FormatCycloneDX, p)

	cfg := app.BuildConfig()
	require.Len(t, cfg.ExtraSBOMParsers, 1)
	assert.NotNil(t, cfg.ExtraSBOMParsers[formats.FormatCycloneDX])
}

func TestRegisterVEXWriter(t *testing.T) {
	app := toolkit.New("1.0.0")
	w := &stubVEXWriter{}

	app.RegisterVEXWriter("custom", w)

	cfg := app.BuildConfig()
	require.Len(t, cfg.ExtraVEXWriters, 1)
	assert.NotNil(t, cfg.ExtraVEXWriters["custom"])
}

func TestRegisterFormatProbe(t *testing.T) {
	app := toolkit.New("1.0.0")
	probe := formats.FormatProbe{
		Format: formats.FormatGrype,
		Detect: func(_ map[string]json.RawMessage) bool { return true },
	}

	app.RegisterFormatProbe(probe)

	cfg := app.BuildConfig()
	require.Len(t, cfg.ExtraFormatProbes, 1)
	assert.Equal(t, formats.FormatGrype, cfg.ExtraFormatProbes[0].Format)
}

func TestRegisterHook(t *testing.T) {
	app := toolkit.New("1.0.0")

	preFn := func(_ context.Context, _ string, _ any, _ error) error { return nil }
	postFn := func(_ context.Context, _ string, _ any, _ error) error { return nil }

	err := app.RegisterHook("vex", toolkit.Hook{Phase: toolkit.Pre, Fn: preFn})
	require.NoError(t, err)

	err = app.RegisterHook("vex", toolkit.Hook{Phase: toolkit.Post, Fn: postFn})
	require.NoError(t, err)

	err = app.RegisterHook("report", toolkit.Hook{Phase: toolkit.Pre, Fn: preFn})
	require.NoError(t, err)

	cfg := app.BuildConfig()
	assert.Len(t, cfg.PreHooks["vex"], 1)
	assert.Len(t, cfg.PostHooks["vex"], 1)
	assert.Len(t, cfg.PreHooks["report"], 1)
}

func TestRegisterHook_InvalidPackage(t *testing.T) {
	app := toolkit.New("1.0.0")
	fn := func(_ context.Context, _ string, _ any, _ error) error { return nil }

	err := app.RegisterHook("invalid", toolkit.Hook{Phase: toolkit.Pre, Fn: fn})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid hook package")
}

func TestRegisterHook_AllValidPackages(t *testing.T) {
	validPkgs := []string{"vex", "report", "csaf", "evidence", "policykit"}
	fn := func(_ context.Context, _ string, _ any, _ error) error { return nil }

	for _, pkg := range validPkgs {
		app := toolkit.New("1.0.0")
		err := app.RegisterHook(pkg, toolkit.Hook{Phase: toolkit.Pre, Fn: fn})
		assert.NoError(t, err, "expected %q to be a valid package", pkg)
	}
}

func TestRunCLI_NilRunner(t *testing.T) {
	app := toolkit.New("1.0.0")
	err := app.RunCLI(context.Background(), []string{"cra", "version"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CLI runner not set")
}

func TestRunCLI_VersionCommand(t *testing.T) {
	app := toolkit.New("1.0.0-test")
	app.SetCLIRunner(cliRunner)

	err := app.RunCLI(context.Background(), []string{"cra", "version"})
	require.NoError(t, err)
}

func TestRunCLI_ExtraCommand(t *testing.T) {
	var executed bool
	app := toolkit.New("1.0.0")
	app.RegisterCommand(&urfave.Command{
		Name: "hello",
		Action: func(_ context.Context, _ *urfave.Command) error {
			executed = true
			return nil
		},
	})
	app.SetCLIRunner(cliRunner)

	err := app.RunCLI(context.Background(), []string{"cra", "hello"})
	require.NoError(t, err)
	assert.True(t, executed)
}

// cliRunner is a test helper that creates the real CLI and runs it,
// without pkg/toolkit importing internal/cli directly.
func cliRunner(version string, cfg toolkit.RunConfig, ctx context.Context, args []string) error {
	root := &urfave.Command{
		Name:    "cra",
		Version: version,
		Commands: []*urfave.Command{
			{
				Name: "version",
				Action: func(_ context.Context, _ *urfave.Command) error {
					return nil
				},
			},
		},
	}
	root.Commands = append(root.Commands, cfg.ExtraCommands...)
	return root.Run(ctx, args)
}
