// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package toolkit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	urfave "github.com/urfave/cli/v3"

	"github.com/ravan/cra-toolkit/internal/cli"
	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/toolkit"
	"github.com/ravan/cra-toolkit/pkg/vex"
)

// realCLIRunner bridges toolkit.RunConfig to cli.New, creating the full CLI
// and running it. This is what a real main() would do.
func realCLIRunner(version string, cfg *toolkit.RunConfig, ctx context.Context, args []string) error {
	cmd := cli.New(version, cfg)
	return cmd.Run(ctx, args)
}

// targetedFilter is a test filter that marks a specific CVE as not_affected.
type targetedFilter struct {
	targetCVE string
}

func (f *targetedFilter) Name() string { return "targeted-test-filter" }

func (f *targetedFilter) Evaluate(finding *formats.Finding, _ []formats.Component) (vex.Result, bool) {
	if finding.CVE == f.targetCVE {
		return vex.Result{
			CVE:           finding.CVE,
			ComponentPURL: finding.AffectedPURL,
			Status:        formats.StatusNotAffected,
			Justification: formats.JustificationVulnerableCodeNotPresent,
			ResolvedBy:    "targeted-test-filter",
			Evidence:      "Resolved by targeted extension filter",
		}, true
	}
	return vex.Result{}, false
}

// openVEXDocument mirrors the OpenVEX JSON structure for test assertions.
type openVEXDocument struct {
	Context    string             `json:"@context"`
	Statements []openVEXStatement `json:"statements"`
}

type openVEXStatement struct {
	Vulnerability struct {
		Name string `json:"name"`
	} `json:"vulnerability"`
	Products []struct {
		ID string `json:"@id"`
	} `json:"products"`
	Status          string `json:"status"`
	Justification   string `json:"justification,omitempty"`
	ImpactStatement string `json:"impact_statement,omitempty"`
}

func fixtureDir() string {
	return filepath.Join("..", "..", "testdata", "integration", "go-reachable")
}

func TestIntegration_CustomFilterInVEXPipeline(t *testing.T) {
	sbom := filepath.Join(fixtureDir(), "sbom.cdx.json")
	scan := filepath.Join(fixtureDir(), "grype.json")
	requireFixtures(t, sbom, scan)

	app := toolkit.New("0.0.0-test")
	app.RegisterFilter(&targetedFilter{targetCVE: "CVE-2022-32149"})
	app.SetCLIRunner(realCLIRunner)

	outFile := filepath.Join(t.TempDir(), "vex-output.json")

	err := app.RunCLI(context.Background(), []string{
		"cra", "vex",
		"--sbom", sbom,
		"--scan", scan,
		"--output", outFile,
	})
	require.NoError(t, err)

	data, err := os.ReadFile(outFile) //nolint:gosec // test file path from t.TempDir()
	require.NoError(t, err)
	require.NotEmpty(t, data, "output file should not be empty")

	var doc openVEXDocument
	err = json.Unmarshal(data, &doc)
	require.NoError(t, err)
	assert.Equal(t, "https://openvex.dev/ns/v0.2.0", doc.Context)
	require.NotEmpty(t, doc.Statements, "expected at least one VEX statement")

	var found bool
	for _, s := range doc.Statements {
		if s.Vulnerability.Name == "CVE-2022-32149" {
			found = true
			assert.Equal(t, "not_affected", s.Status,
				"custom filter should override CVE-2022-32149 to not_affected")
			assert.Equal(t, "vulnerable_code_not_present", s.Justification)
			break
		}
	}
	assert.True(t, found, "CVE-2022-32149 should appear in VEX output")
}

func TestIntegration_HooksFireDuringVEX(t *testing.T) {
	sbom := filepath.Join(fixtureDir(), "sbom.cdx.json")
	scan := filepath.Join(fixtureDir(), "grype.json")
	requireFixtures(t, sbom, scan)

	var preFired atomic.Bool
	var postFired atomic.Bool
	var postErr error

	app := toolkit.New("0.0.0-test")
	app.SetCLIRunner(realCLIRunner)

	err := app.RegisterHook("vex", toolkit.Hook{
		Phase: toolkit.Pre,
		Fn: func(_ context.Context, pkg string, _ any, _ error) error {
			assert.Equal(t, "vex", pkg)
			preFired.Store(true)
			return nil
		},
	})
	require.NoError(t, err)

	err = app.RegisterHook("vex", toolkit.Hook{
		Phase: toolkit.Post,
		Fn: func(_ context.Context, pkg string, _ any, runErr error) error {
			assert.Equal(t, "vex", pkg)
			postFired.Store(true)
			postErr = runErr
			return nil
		},
	})
	require.NoError(t, err)

	outFile := filepath.Join(t.TempDir(), "hooks-vex.json")
	err = app.RunCLI(context.Background(), []string{
		"cra", "vex",
		"--sbom", sbom,
		"--scan", scan,
		"--output", outFile,
	})
	require.NoError(t, err)

	assert.True(t, preFired.Load(), "pre-hook should have fired")
	assert.True(t, postFired.Load(), "post-hook should have fired")
	assert.NoError(t, postErr, "post-hook should receive nil error on success")
}

func TestIntegration_ExtraCommandViaRunCLI(t *testing.T) {
	var buf bytes.Buffer

	app := toolkit.New("0.0.0-test")
	app.RegisterCommand(&urfave.Command{
		Name:  "hello",
		Usage: "test custom command",
		Action: func(_ context.Context, _ *urfave.Command) error {
			buf.WriteString("hello from extension")
			return nil
		},
	})
	app.SetCLIRunner(realCLIRunner)

	err := app.RunCLI(context.Background(), []string{"cra", "hello"})
	require.NoError(t, err)
	assert.Equal(t, "hello from extension", buf.String())
}

func TestIntegration_ZeroExtensions_IdenticalBehavior(t *testing.T) {
	sbom := filepath.Join(fixtureDir(), "sbom.cdx.json")
	scan := filepath.Join(fixtureDir(), "grype.json")
	requireFixtures(t, sbom, scan)

	app := toolkit.New("0.0.0-test")
	app.SetCLIRunner(realCLIRunner)

	outFile := filepath.Join(t.TempDir(), "zero-ext-vex.json")
	err := app.RunCLI(context.Background(), []string{
		"cra", "vex",
		"--sbom", sbom,
		"--scan", scan,
		"--output", outFile,
	})
	require.NoError(t, err)

	data, err := os.ReadFile(outFile) //nolint:gosec // test file path from t.TempDir()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	var doc openVEXDocument
	err = json.Unmarshal(data, &doc)
	require.NoError(t, err)
	assert.Equal(t, "https://openvex.dev/ns/v0.2.0", doc.Context)
	require.NotEmpty(t, doc.Statements, "baseline run should produce VEX statements")

	// Every statement must have a valid VEX status.
	validStatuses := map[string]bool{
		"not_affected": true, "affected": true,
		"fixed": true, "under_investigation": true,
	}
	for _, s := range doc.Statements {
		assert.True(t, validStatuses[s.Status],
			"statement for %s has invalid status %q", s.Vulnerability.Name, s.Status)
	}
}

// requireFixtures skips the test if fixture files are missing.
func requireFixtures(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			t.Skipf("fixture not found: %s", p)
		}
	}
}
