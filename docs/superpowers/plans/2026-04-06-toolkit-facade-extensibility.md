# Toolkit Facade Extensibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `pkg/toolkit/` facade that makes the CRA toolkit extensible by external Go modules, enabling a commercial product to register extra filters, analyzers, commands, parsers, writers, and hooks without forking.

**Architecture:** New `pkg/toolkit/` package with an `App` struct and registration API. A `RunConfig` struct in `internal/cli/` carries registrations through the CLI layer into each package's `Run()` function via variadic `RunOption` parameters. `pkg/toolkit` imports `internal/cli` (one-way) — no circular dependency. `internal/cli/config.go` uses a type alias for hook functions to avoid importing `pkg/toolkit`. Built-in behavior is untouched when no extensions are registered.

**Tech Stack:** Go 1.26, urfave/cli v3, testify

**Dependency note:** `pkg/toolkit` -> `internal/cli` (allowed, same module). `internal/cli` does NOT import `pkg/toolkit` (would create a cycle). Hook function types use a type alias (`HookFn`) in `internal/cli/config.go` that matches `toolkit.HookFunc` without importing it.

---

### Task 1: FormatProbe Type in pkg/formats

Add the `FormatProbe` type and make `DetectFormat` accept variadic extra probes. This is a prerequisite for everything else.

**Files:**
- Modify: `pkg/formats/detect.go`
- Modify: `pkg/formats/detect_test.go`

- [ ] **Step 1: Write failing tests for FormatProbe extension**

Add to the end of `pkg/formats/detect_test.go`:

```go
func TestDetectFormat_ExtraProbeMatchesCustomFormat(t *testing.T) {
	// A JSON doc with a custom key that no built-in probe matches.
	const customJSON = `{"custom_scanner": "v1", "results": []}`
	r := mustStringReader(customJSON)

	const FormatCustom formats.Format = 100

	probe := formats.FormatProbe{
		Format: FormatCustom,
		Detect: func(doc map[string]json.RawMessage) bool {
			_, ok := doc["custom_scanner"]
			return ok
		},
	}

	got, err := formats.DetectFormat(r, probe)
	if err != nil {
		t.Fatalf("DetectFormat: %v", err)
	}
	if got != FormatCustom {
		t.Errorf("DetectFormat = %v, want %v", got, FormatCustom)
	}
}

func TestDetectFormat_ExtraProbeDoesNotOverrideBuiltin(t *testing.T) {
	// A Grype file should still be detected as Grype even with a probe registered.
	const base = "../../testdata/integration/"
	f, err := os.Open(base + "go-reachable/grype.json")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	const FormatCustom formats.Format = 100
	probe := formats.FormatProbe{
		Format: FormatCustom,
		Detect: func(doc map[string]json.RawMessage) bool {
			// This probe would match anything with "matches" key — but built-in
			// Grype detection should fire first.
			_, ok := doc["matches"]
			return ok
		},
	}

	got, err := formats.DetectFormat(f, probe)
	if err != nil {
		t.Fatalf("DetectFormat: %v", err)
	}
	if got != formats.FormatGrype {
		t.Errorf("DetectFormat = %v, want FormatGrype", got)
	}
}

func TestDetectFormat_EmptyExtraProbes(t *testing.T) {
	// Passing no extra probes should work identically to before.
	const base = "../../testdata/integration/"
	f, err := os.Open(base + "go-reachable/grype.json")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	got, err := formats.DetectFormat(f)
	if err != nil {
		t.Fatalf("DetectFormat: %v", err)
	}
	if got != formats.FormatGrype {
		t.Errorf("DetectFormat = %v, want FormatGrype", got)
	}
}
```

Add `"encoding/json"` to the imports in `detect_test.go`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -race -count=1 ./pkg/formats/...`
Expected: Compilation failure — `formats.FormatProbe` not defined, `DetectFormat` doesn't accept extra args.

- [ ] **Step 3: Implement FormatProbe and update DetectFormat**

In `pkg/formats/detect.go`, add the `FormatProbe` type after line 47 (after `String()` method):

```go
// FormatProbe is a pluggable format detection rule.
// External modules register probes to support custom formats.
// Define custom Format constants starting at 100+ to avoid collisions with built-in formats.
type FormatProbe struct {
	Format Format
	Detect func(doc map[string]json.RawMessage) bool
}
```

Change the `DetectFormat` signature on line 53 from:
```go
func DetectFormat(r io.Reader) (Format, error) {
```
to:
```go
func DetectFormat(r io.Reader, extraProbes ...FormatProbe) (Format, error) {
```

Add before the final `return FormatUnknown, nil` on line 120:

```go
	// Extension probes (checked after all built-in probes).
	for _, probe := range extraProbes {
		if probe.Detect(doc) {
			return probe.Format, nil
		}
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -race -count=1 ./pkg/formats/...`
Expected: All tests PASS (existing + 3 new).

- [ ] **Step 5: Run full test suite to verify no regressions**

Run: `go test -race -count=1 ./...`
Expected: All tests PASS. The variadic parameter change is backward-compatible — existing callers pass no extra args.

- [ ] **Step 6: Commit**

```bash
git add pkg/formats/detect.go pkg/formats/detect_test.go
git commit -m "feat: add FormatProbe type and variadic probe support to DetectFormat"
```

---

### Task 2: Hook Types and ExecuteWithHooks

The hook infrastructure that all `Run()` functions will use. No dependency on `internal/cli`.

**Files:**
- Create: `pkg/toolkit/hooks.go`
- Create: `pkg/toolkit/hooks_test.go`

- [ ] **Step 1: Write failing tests for ExecuteWithHooks**

Create `pkg/toolkit/hooks_test.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package toolkit_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ravan/cra-toolkit/pkg/toolkit"
)

func TestExecuteWithHooks_NoHooks(t *testing.T) {
	called := false
	err := toolkit.ExecuteWithHooks(context.Background(), "vex", nil, nil, func() error {
		called = true
		return nil
	})
	require.NoError(t, err)
	assert.True(t, called)
}

func TestExecuteWithHooks_PreOnly(t *testing.T) {
	var order []string
	hooks := []toolkit.Hook{
		{Phase: toolkit.Pre, Fn: func(_ context.Context, pkg string, _ any, _ error) error {
			order = append(order, "pre:"+pkg)
			return nil
		}},
	}
	err := toolkit.ExecuteWithHooks(context.Background(), "vex", hooks, nil, func() error {
		order = append(order, "fn")
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"pre:vex", "fn"}, order)
}

func TestExecuteWithHooks_PostOnly(t *testing.T) {
	var order []string
	hooks := []toolkit.Hook{
		{Phase: toolkit.Post, Fn: func(_ context.Context, pkg string, _ any, fnErr error) error {
			order = append(order, "post:"+pkg)
			assert.NoError(t, fnErr)
			return nil
		}},
	}
	err := toolkit.ExecuteWithHooks(context.Background(), "report", hooks, nil, func() error {
		order = append(order, "fn")
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"fn", "post:report"}, order)
}

func TestExecuteWithHooks_PreError_StopsExecution(t *testing.T) {
	fnCalled := false
	hooks := []toolkit.Hook{
		{Phase: toolkit.Pre, Fn: func(_ context.Context, _ string, _ any, _ error) error {
			return errors.New("pre-hook failed")
		}},
	}
	err := toolkit.ExecuteWithHooks(context.Background(), "vex", hooks, nil, func() error {
		fnCalled = true
		return nil
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pre-hook")
	assert.False(t, fnCalled)
}

func TestExecuteWithHooks_PostReceivesFnError(t *testing.T) {
	fnErr := errors.New("fn failed")
	var receivedErr error
	hooks := []toolkit.Hook{
		{Phase: toolkit.Post, Fn: func(_ context.Context, _ string, _ any, err error) error {
			receivedErr = err
			return nil
		}},
	}
	err := toolkit.ExecuteWithHooks(context.Background(), "vex", hooks, nil, func() error {
		return fnErr
	})
	// When post-hook returns nil, the original fn error is returned.
	require.Error(t, err)
	assert.Equal(t, fnErr, err)
	assert.Equal(t, fnErr, receivedErr)
}

func TestExecuteWithHooks_MultipleHooks_FireInOrder(t *testing.T) {
	var order []string
	hooks := []toolkit.Hook{
		{Phase: toolkit.Pre, Fn: func(_ context.Context, _ string, _ any, _ error) error {
			order = append(order, "pre1")
			return nil
		}},
		{Phase: toolkit.Pre, Fn: func(_ context.Context, _ string, _ any, _ error) error {
			order = append(order, "pre2")
			return nil
		}},
		{Phase: toolkit.Post, Fn: func(_ context.Context, _ string, _ any, _ error) error {
			order = append(order, "post1")
			return nil
		}},
		{Phase: toolkit.Post, Fn: func(_ context.Context, _ string, _ any, _ error) error {
			order = append(order, "post2")
			return nil
		}},
	}
	err := toolkit.ExecuteWithHooks(context.Background(), "vex", hooks, nil, func() error {
		order = append(order, "fn")
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"pre1", "pre2", "fn", "post1", "post2"}, order)
}

func TestExecuteWithHooks_PostHookError_OverridesFnSuccess(t *testing.T) {
	hooks := []toolkit.Hook{
		{Phase: toolkit.Post, Fn: func(_ context.Context, _ string, _ any, _ error) error {
			return errors.New("post-hook failed")
		}},
	}
	err := toolkit.ExecuteWithHooks(context.Background(), "vex", hooks, nil, func() error {
		return nil // fn succeeds
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "post-hook")
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -race -count=1 ./pkg/toolkit/...`
Expected: Compilation failure — package `toolkit` does not exist yet.

- [ ] **Step 3: Implement hook types and ExecuteWithHooks**

Create `pkg/toolkit/hooks.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package toolkit

import (
	"context"
	"fmt"
)

// HookPhase determines when a hook fires relative to a Run() function.
type HookPhase int

const (
	// Pre hooks fire before the Run() function executes.
	Pre HookPhase = iota
	// Post hooks fire after the Run() function executes.
	Post
)

// HookFunc receives the package name ("vex", "report", etc.),
// the options struct (as any), and for Post hooks, the error result from Run().
type HookFunc func(ctx context.Context, pkg string, opts any, err error) error

// Hook runs before or after a package's Run() function.
type Hook struct {
	Phase HookPhase
	Fn    HookFunc
}

// ExecuteWithHooks wraps a function call with pre and post hooks.
// Pre hooks fire in order before fn. If any pre hook returns an error, fn is not called.
// Post hooks fire in order after fn, receiving fn's error. If fn errored and all post
// hooks return nil, the original fn error is returned.
func ExecuteWithHooks(ctx context.Context, pkg string, hooks []Hook, opts any, fn func() error) error {
	for _, h := range hooks {
		if h.Phase == Pre {
			if err := h.Fn(ctx, pkg, opts, nil); err != nil {
				return fmt.Errorf("%s pre-hook: %w", pkg, err)
			}
		}
	}

	fnErr := fn()

	for _, h := range hooks {
		if h.Phase == Post {
			if err := h.Fn(ctx, pkg, opts, fnErr); err != nil {
				return fmt.Errorf("%s post-hook: %w", pkg, err)
			}
		}
	}

	return fnErr
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -race -count=1 ./pkg/toolkit/...`
Expected: All 7 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/toolkit/hooks.go pkg/toolkit/hooks_test.go
git commit -m "feat: add toolkit hook types and ExecuteWithHooks"
```

---

### Task 3: RunConfig in internal/cli and cli.New() Signature Change

Create the `RunConfig` struct and update `cli.New()` to accept it. Update `cmd/cra/main.go` to pass an empty config.

**Files:**
- Create: `internal/cli/config.go`
- Modify: `internal/cli/root.go`
- Modify: `cmd/cra/main.go`

- [ ] **Step 1: Create RunConfig struct**

Create `internal/cli/config.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package cli

import (
	"context"

	urfave "github.com/urfave/cli/v3"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/toolkit"
	"github.com/ravan/cra-toolkit/pkg/vex"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability"
)

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
	Hooks             map[string][]toolkit.Hook
}

// VEXHooks returns the hooks registered for the "vex" package.
func (c RunConfig) VEXHooks() []toolkit.Hook { return c.Hooks["vex"] }

// ReportHooks returns the hooks registered for the "report" package.
func (c RunConfig) ReportHooks() []toolkit.Hook { return c.Hooks["report"] }

// CSAFHooks returns the hooks registered for the "csaf" package.
func (c RunConfig) CSAFHooks() []toolkit.Hook { return c.Hooks["csaf"] }

// EvidenceHooks returns the hooks registered for the "evidence" package.
func (c RunConfig) EvidenceHooks() []toolkit.Hook { return c.Hooks["evidence"] }

// PolicykitHooks returns the hooks registered for the "policykit" package.
func (c RunConfig) PolicykitHooks() []toolkit.Hook { return c.Hooks["policykit"] }
```

Wait — this imports `pkg/toolkit` (for `toolkit.Hook`). And later `pkg/toolkit/toolkit.go` will import `internal/cli` (for `cli.New()` and `cli.RunConfig`). That's a circular dependency.

**Fix: Use a type alias for the hook function in RunConfig instead of importing toolkit.**

Create `internal/cli/config.go`:

```go
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
// Defined here as a type alias to avoid a circular import with pkg/toolkit.
type HookFn = func(ctx context.Context, pkg string, opts any, err error) error

// HookPhase determines when a hook fires relative to a Run() function.
type HookPhase int

const (
	// HookPre hooks fire before the Run() function executes.
	HookPre HookPhase = iota
	// HookPost hooks fire after the Run() function executes.
	HookPost
)

// Hook mirrors toolkit.Hook without importing pkg/toolkit.
type Hook struct {
	Phase HookPhase
	Fn    HookFn
}

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
```

Using `PreHooks`/`PostHooks` maps of `HookFn` avoids needing to mirror the `Hook` struct at all. The toolkit facade splits its `[]Hook` into pre/post when building `RunConfig`.

- [ ] **Step 2: Update cli.New() to accept RunConfig**

In `internal/cli/root.go`, change line 14 from:
```go
func New(version string) *urfave.Command {
```
to:
```go
func New(version string, cfg RunConfig) *urfave.Command {
```

Add extra commands after line 48 (after `newCsafCmd(),`). Insert before the closing `}` of Commands:

After the existing commands slice, add code to append extra commands:

```go
	cmd := &urfave.Command{
		Name:    "cra",
		Usage:   "SUSE CRA Compliance Toolkit",
		Version: version,
		Flags: []urfave.Flag{
			// ... existing flags unchanged ...
		},
		Commands: []*urfave.Command{
			newVersionCmd(version),
			newVexCmd(cfg),
			newPolicykitCmd(cfg),
			newReportCmd(cfg),
			newEvidenceCmd(cfg),
			newCsafCmd(cfg),
		},
	}

	// Append extra commands from extensions.
	cmd.Commands = append(cmd.Commands, cfg.ExtraCommands...)

	return cmd
```

Note: each `newXxxCmd` now receives `cfg` to pass extensions to the package `Run()` calls. This is implemented in Task 5.

For now, just update the signature and pass `cfg` through. The `newXxxCmd` functions keep their current signatures for now — we'll update them in Task 5. So the intermediate step is:

```go
func New(version string, cfg RunConfig) *urfave.Command {
	cmd := &urfave.Command{
		Name:    "cra",
		Usage:   "SUSE CRA Compliance Toolkit",
		Version: version,
		Flags: []urfave.Flag{
			&urfave.StringFlag{
				Name:    "format",
				Aliases: []string{"f"},
				Value:   "json",
				Usage:   "output format: json or text",
			},
			&urfave.StringFlag{
				Name:    "output",
				Aliases: []string{"o"},
				Usage:   "output file path (default: stdout)",
			},
			&urfave.BoolFlag{
				Name:    "quiet",
				Aliases: []string{"q"},
				Usage:   "suppress non-essential output",
			},
			&urfave.BoolFlag{
				Name:  "verbose",
				Usage: "enable debug logging",
			},
		},
		Commands: []*urfave.Command{
			newVersionCmd(version),
			newVexCmd(),
			newPolicykitCmd(),
			newReportCmd(),
			newEvidenceCmd(),
			newCsafCmd(),
		},
	}

	cmd.Commands = append(cmd.Commands, cfg.ExtraCommands...)

	return cmd
}
```

- [ ] **Step 3: Update cmd/cra/main.go**

Change line 21 from:
```go
	cmd := cli.New(version)
```
to:
```go
	cmd := cli.New(version, cli.RunConfig{})
```

- [ ] **Step 4: Run full test suite to verify no regressions**

Run: `go test -race -count=1 ./...`
Expected: All tests PASS. The empty `RunConfig{}` produces identical behavior.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/config.go internal/cli/root.go cmd/cra/main.go
git commit -m "feat: add RunConfig to cli.New() for extension support"
```

---

### Task 4: RunOption Pattern on pkg/vex/vex.go

Add `RunOption` variadic parameter to `vex.Run()`. Update `buildFilterChain()` and `buildAnalyzers()` to accept extras. Update `openDetected()` and parse functions to pass extra probes/parsers.

**Files:**
- Modify: `pkg/vex/vex.go`
- Modify: `pkg/vex/vex_test.go` (add extension tests)

- [ ] **Step 1: Write failing tests for vex.Run with RunOptions**

Add to the end of `pkg/vex/vex_test.go`:

```go
func TestRun_WithExtraFilter_ResolvesBeforeBuiltin(t *testing.T) {
	// A custom filter that marks everything as not_affected.
	opts := vex.Options{
		SBOMPath:     "../../testdata/integration/go-reachable/sbom.cdx.json",
		ScanPaths:    []string{"../../testdata/integration/go-reachable/grype.json"},
		OutputFormat: "openvex",
	}

	var buf bytes.Buffer
	err := vex.Run(&opts, &buf, vex.WithExtraFilters([]vex.Filter{
		&alwaysNotAffectedFilter{},
	}))
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	var doc openvexDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Every statement should be not_affected because our custom filter catches all.
	for i, stmt := range doc.Statements {
		if stmt.Status != "not_affected" {
			t.Errorf("statement[%d]: status=%s, want not_affected", i, stmt.Status)
		}
		if stmt.Justification != "custom_filter" {
			t.Errorf("statement[%d]: justification=%s, want custom_filter", i, stmt.Justification)
		}
	}
}

// alwaysNotAffectedFilter is a test filter that resolves everything as not_affected.
type alwaysNotAffectedFilter struct{}

func (f *alwaysNotAffectedFilter) Name() string { return "custom-always-not-affected" }
func (f *alwaysNotAffectedFilter) Evaluate(finding *formats.Finding, _ []formats.Component) (vex.Result, bool) {
	return vex.Result{
		CVE:           finding.CVE,
		ComponentPURL: finding.AffectedPURL,
		Status:        formats.StatusNotAffected,
		Justification: "custom_filter",
		ResolvedBy:    "custom-always-not-affected",
		Evidence:      "Resolved by custom extension filter",
	}, true
}

func TestRun_WithExtraVEXWriter(t *testing.T) {
	opts := vex.Options{
		SBOMPath:     "../../testdata/integration/go-reachable/sbom.cdx.json",
		ScanPaths:    []string{"../../testdata/integration/go-reachable/grype.json"},
		OutputFormat: "custom-writer",
	}

	customWriter := &countingWriter{}

	var buf bytes.Buffer
	err := vex.Run(&opts, &buf, vex.WithExtraVEXWriters(map[string]formats.VEXWriter{
		"custom-writer": customWriter,
	}))
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	if customWriter.count == 0 {
		t.Error("custom writer was not called")
	}
	if buf.Len() == 0 {
		t.Error("expected non-empty output from custom writer")
	}
}

// countingWriter counts how many results it received and writes minimal JSON.
type countingWriter struct{ count int }

func (w *countingWriter) Write(out io.Writer, results []formats.VEXResult) error {
	w.count = len(results)
	return json.NewEncoder(out).Encode(map[string]int{"count": len(results)})
}

func TestRun_ZeroRunOptions_IdenticalToBaseline(t *testing.T) {
	opts := vex.Options{
		SBOMPath:     "../../testdata/integration/go-reachable/sbom.cdx.json",
		ScanPaths:    []string{"../../testdata/integration/go-reachable/grype.json"},
		OutputFormat: "openvex",
	}

	// Run without RunOptions.
	var buf1 bytes.Buffer
	err := vex.Run(&opts, &buf1)
	if err != nil {
		t.Fatalf("Run() baseline error: %v", err)
	}

	// Run with empty RunOptions.
	var buf2 bytes.Buffer
	err = vex.Run(&opts, &buf2, func(_ *vex.RunConfig) {})
	if err != nil {
		t.Fatalf("Run() with empty option error: %v", err)
	}

	// Both outputs should be identical (same content, modulo whitespace).
	if buf1.String() != buf2.String() {
		t.Error("output differs between baseline and empty RunOptions")
	}
}
```

Add these imports at the top of `vex_test.go` if not already present: `"io"`, `"github.com/ravan/cra-toolkit/pkg/formats"`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -race -count=1 ./pkg/vex/ -run "TestRun_With|TestRun_Zero"`
Expected: Compilation failure — `vex.WithExtraFilters`, `vex.RunConfig`, `vex.WithExtraVEXWriters` not defined.

- [ ] **Step 3: Implement RunOption pattern and update vex.Run()**

In `pkg/vex/vex.go`, add after the `Options` struct (after line 42):

```go
// RunConfig holds extension registrations passed via RunOption.
type RunConfig struct {
	extraFilters     []Filter
	extraAnalyzers   map[string]reachability.Analyzer
	extraScanParsers map[formats.Format]formats.ScanParser
	extraSBOMParsers map[formats.Format]formats.SBOMParser
	extraVEXWriters  map[string]formats.VEXWriter
	extraProbes      []formats.FormatProbe
	hooks            []Hook
}

// Hook mirrors the toolkit hook types for use within the vex package.
// It is populated by the CLI layer from toolkit.Hook values.
type Hook struct {
	Pre  bool
	Fn   func(ctx context.Context, pkg string, opts any, err error) error
}

// RunOption configures a Run() call with extensions.
type RunOption func(*RunConfig)

// WithExtraFilters appends filters to the VEX filter chain (after built-in filters).
func WithExtraFilters(filters []Filter) RunOption {
	return func(c *RunConfig) {
		c.extraFilters = append(c.extraFilters, filters...)
	}
}

// WithExtraAnalyzers merges extra analyzers into the analyzer map.
func WithExtraAnalyzers(analyzers map[string]reachability.Analyzer) RunOption {
	return func(c *RunConfig) {
		if c.extraAnalyzers == nil {
			c.extraAnalyzers = make(map[string]reachability.Analyzer)
		}
		for k, v := range analyzers {
			c.extraAnalyzers[k] = v
		}
	}
}

// WithExtraScanParsers registers additional scan parsers.
func WithExtraScanParsers(parsers map[formats.Format]formats.ScanParser) RunOption {
	return func(c *RunConfig) {
		if c.extraScanParsers == nil {
			c.extraScanParsers = make(map[formats.Format]formats.ScanParser)
		}
		for k, v := range parsers {
			c.extraScanParsers[k] = v
		}
	}
}

// WithExtraSBOMParsers registers additional SBOM parsers.
func WithExtraSBOMParsers(parsers map[formats.Format]formats.SBOMParser) RunOption {
	return func(c *RunConfig) {
		if c.extraSBOMParsers == nil {
			c.extraSBOMParsers = make(map[formats.Format]formats.SBOMParser)
		}
		for k, v := range parsers {
			c.extraSBOMParsers[k] = v
		}
	}
}

// WithExtraVEXWriters registers additional VEX output writers.
func WithExtraVEXWriters(writers map[string]formats.VEXWriter) RunOption {
	return func(c *RunConfig) {
		if c.extraVEXWriters == nil {
			c.extraVEXWriters = make(map[string]formats.VEXWriter)
		}
		for k, v := range writers {
			c.extraVEXWriters[k] = v
		}
	}
}

// WithExtraFormatProbes registers additional format detection probes.
func WithExtraFormatProbes(probes []formats.FormatProbe) RunOption {
	return func(c *RunConfig) {
		c.extraProbes = append(c.extraProbes, probes...)
	}
}
```

Now update the `Run()` function signature and body. Change the existing `Run` function (line 51):

```go
func Run(opts *Options, out io.Writer, runOpts ...RunOption) error {
	var cfg RunConfig
	for _, o := range runOpts {
		o(&cfg)
	}

	// 1. Parse SBOM.
	components, err := parseSBOM(opts.SBOMPath, cfg.extraProbes, cfg.extraSBOMParsers)
	if err != nil {
		return fmt.Errorf("parse SBOM: %w", err)
	}

	// 2. Parse scan results.
	var findings []formats.Finding
	for _, path := range opts.ScanPaths {
		f, err := parseScan(path, cfg.extraProbes, cfg.extraScanParsers)
		if err != nil {
			return fmt.Errorf("parse scan %s: %w", path, err)
		}
		findings = append(findings, f...)
	}

	// 3. Parse upstream VEX documents.
	var upstreamStatements []formats.VEXStatement
	for _, path := range opts.UpstreamVEXPaths {
		stmts, err := parseVEX(path, cfg.extraProbes)
		if err != nil {
			return fmt.Errorf("parse upstream VEX %s: %w", path, err)
		}
		upstreamStatements = append(upstreamStatements, stmts...)
	}

	// 4. Build filter chain.
	filters := buildFilterChain(upstreamStatements, opts.SourceDir, cfg.extraFilters, cfg.extraAnalyzers)

	// 5. Run each finding through chain.
	results := make([]formats.VEXResult, 0, len(findings))
	for i := range findings {
		result := RunChain(filters, &findings[i], components)
		results = append(results, result)
	}

	// 6. Write output.
	writer := selectWriter(opts.OutputFormat, cfg.extraVEXWriters)
	return writer.Write(out, results)
}
```

Update `openDetected` to accept extra probes:

```go
func openDetected(path string, extraProbes []formats.FormatProbe) (formats.Format, *os.File, error) {
	df, err := os.Open(path) //nolint:gosec // path is from CLI flag, user-controlled
	if err != nil {
		return formats.FormatUnknown, nil, fmt.Errorf("open for detection: %w", err)
	}

	format, err := formats.DetectFormat(df, extraProbes...)
	_ = df.Close()
	if err != nil {
		return formats.FormatUnknown, nil, fmt.Errorf("detect format: %w", err)
	}

	pf, err := os.Open(path) //nolint:gosec // path is from CLI flag, user-controlled
	if err != nil {
		return formats.FormatUnknown, nil, fmt.Errorf("open for parsing: %w", err)
	}

	return format, pf, nil
}
```

Update `parseSBOM`:

```go
func parseSBOM(path string, extraProbes []formats.FormatProbe, extra map[formats.Format]formats.SBOMParser) ([]formats.Component, error) {
	format, f, err := openDetected(path, extraProbes)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only file

	switch format {
	case formats.FormatCycloneDX:
		return cyclonedx.Parser{}.Parse(f)
	case formats.FormatSPDX:
		return spdx.Parser{}.Parse(f)
	default:
		if p, ok := extra[format]; ok {
			return p.Parse(f)
		}
		return nil, fmt.Errorf("unsupported SBOM format: %s", format)
	}
}
```

Update `parseScan`:

```go
func parseScan(path string, extraProbes []formats.FormatProbe, extra map[formats.Format]formats.ScanParser) ([]formats.Finding, error) {
	format, f, err := openDetected(path, extraProbes)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only file

	switch format {
	case formats.FormatGrype:
		return grype.Parser{}.Parse(f)
	case formats.FormatTrivy:
		return trivy.Parser{}.Parse(f)
	case formats.FormatSARIF:
		return sarif.Parser{}.Parse(f)
	default:
		if p, ok := extra[format]; ok {
			return p.Parse(f)
		}
		return nil, fmt.Errorf("unsupported scan format: %s", format)
	}
}
```

Update `parseVEX`:

```go
func parseVEX(path string, extraProbes []formats.FormatProbe) ([]formats.VEXStatement, error) {
	format, f, err := openDetected(path, extraProbes)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only file

	switch format {
	case formats.FormatOpenVEX:
		return openvex.Parser{}.Parse(f)
	case formats.FormatCSAF:
		return csafvex.Parser{}.Parse(f)
	default:
		return nil, fmt.Errorf("unsupported VEX format: %s", format)
	}
}
```

Update `buildFilterChain`:

```go
func buildFilterChain(upstreamStatements []formats.VEXStatement, sourceDir string, extraFilters []Filter, extraAnalyzers map[string]reachability.Analyzer) []Filter {
	var filters []Filter

	if len(upstreamStatements) > 0 {
		filters = append(filters, NewUpstreamFilter(upstreamStatements))
	}

	filters = append(filters,
		NewPresenceFilter(),
		NewVersionFilter(),
		NewPlatformFilter(),
		NewPatchFilter(),
	)

	if sourceDir != "" {
		analyzers := buildAnalyzers(sourceDir, extraAnalyzers)
		if len(analyzers) > 0 {
			filters = append(filters, NewReachabilityFilter(sourceDir, analyzers))
		}
	}

	// Extension filters (appended after all built-in filters).
	filters = append(filters, extraFilters...)

	return filters
}
```

Update `buildAnalyzers`:

```go
func buildAnalyzers(sourceDir string, extra map[string]reachability.Analyzer) map[string]reachability.Analyzer {
	analyzers := make(map[string]reachability.Analyzer)

	langs := reachability.DetectLanguages(sourceDir)
	for _, lang := range langs {
		switch lang {
		case "go":
			analyzers["go"] = golang.New()
		case "rust":
			analyzers["rust"] = rust.New()
		case "python":
			analyzers["python"] = pythonanalyzer.New()
		case "javascript":
			analyzers["javascript"] = jsanalyzer.New()
		case "java":
			analyzers["java"] = javaanalyzer.New()
		case "csharp":
			analyzers["csharp"] = csharpanalyzer.New()
		case "php":
			analyzers["php"] = phpanalyzer.New()
		case "ruby":
			analyzers["ruby"] = rubyanalyzer.New()
		}
	}

	analyzers["generic"] = generic.New("")

	// Merge extras — override or add.
	for lang, az := range extra {
		analyzers[lang] = az
	}

	return analyzers
}
```

Update `selectWriter`:

```go
func selectWriter(format string, extra map[string]formats.VEXWriter) formats.VEXWriter {
	switch format {
	case "csaf":
		return csafvex.Writer{}
	case "openvex", "":
		return openvex.Writer{}
	default:
		if w, ok := extra[format]; ok {
			return w
		}
		return openvex.Writer{}
	}
}
```

Add `"context"` to the imports at the top of `vex.go`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -race -count=1 ./pkg/vex/...`
Expected: All tests PASS (existing + 3 new).

- [ ] **Step 5: Run full test suite**

Run: `go test -race -count=1 ./...`
Expected: All tests PASS. Existing tests call `vex.Run(&opts, &buf)` with no `RunOption` — still works.

- [ ] **Step 6: Commit**

```bash
git add pkg/vex/vex.go pkg/vex/vex_test.go
git commit -m "feat: add RunOption pattern to vex.Run() for extensible filters, parsers, and writers"
```

---

### Task 5: RunOption Pattern on report, policykit, evidence, csaf

Add `RunOption` to the remaining packages' `Run()` functions. These only need hook support (plus `csaf` gets extra scan parsers).

**Files:**
- Modify: `pkg/report/report.go`
- Modify: `pkg/policykit/policykit.go`
- Modify: `pkg/evidence/evidence.go`
- Modify: `pkg/csaf/csaf.go`

- [ ] **Step 1: Add RunOption to pkg/report/report.go**

Add after the imports:

```go
// RunOption configures a Run() call with extensions.
type RunOption func(*runConfig)

type runConfig struct {
	hooks []runHook
}

type runHook struct {
	pre bool
	fn  func(ctx context.Context, pkg string, opts any, err error) error
}

// WithPreHooks registers pre-execution hooks.
func WithPreHooks(fns ...func(ctx context.Context, pkg string, opts any, err error) error) RunOption {
	return func(c *runConfig) {
		for _, fn := range fns {
			c.hooks = append(c.hooks, runHook{pre: true, fn: fn})
		}
	}
}

// WithPostHooks registers post-execution hooks.
func WithPostHooks(fns ...func(ctx context.Context, pkg string, opts any, err error) error) RunOption {
	return func(c *runConfig) {
		for _, fn := range fns {
			c.hooks = append(c.hooks, runHook{pre: false, fn: fn})
		}
	}
}
```

Change the `Run` signature from:
```go
func Run(opts *Options, out io.Writer) error {
```
to:
```go
func Run(opts *Options, out io.Writer, runOpts ...RunOption) error {
```

Add at the top of `Run()`:
```go
	var cfg runConfig
	for _, o := range runOpts {
		o(&cfg)
	}
```

The existing function body stays unchanged — hooks are applied at the CLI layer via `toolkit.ExecuteWithHooks`, not inside `Run()` itself. The `runConfig` is available for future in-process hooks if needed, but for now the CLI layer handles hook execution.

Actually, let me reconsider. The spec says hooks wrap `Run()` calls. The simplest approach: the CLI layer wraps `pkg.Run()` with `toolkit.ExecuteWithHooks()`. The packages themselves don't need to know about hooks. So we DON'T need `RunOption` on report/policykit/evidence/csaf at all — just on `vex` (which has the filter/analyzer/parser/writer extensions).

But the spec says all `Run()` functions gain `...RunOption`. Let me keep it consistent — add the variadic parameter to all for forward compatibility, but only `vex.Run` actually uses the options. The other packages just accept and ignore the options for now.

Let me simplify. For report, policykit, evidence, csaf:

```go
// RunOption configures a Run() call with extensions.
type RunOption func(*runConfig)

type runConfig struct{}

func Run(opts *Options, out io.Writer, _ ...RunOption) error {
    // ... existing body unchanged ...
}
```

This is the minimal change — adds the variadic parameter for API compatibility, does nothing with it. Hook execution happens at the CLI layer.

- [ ] **Step 2: Add RunOption to pkg/policykit/policykit.go**

Add after the imports:

```go
// RunOption configures a Run() call with extensions.
type RunOption func(*runConfig)

type runConfig struct{}
```

Change line 44 from:
```go
func Run(opts *Options, out io.Writer) error {
```
to:
```go
func Run(opts *Options, out io.Writer, _ ...RunOption) error {
```

- [ ] **Step 3: Add RunOption to pkg/evidence/evidence.go**

Add after the imports:

```go
// RunOption configures a Run() call with extensions.
type RunOption func(*runConfig)

type runConfig struct{}
```

Change line 16 from:
```go
func Run(opts *Options, out io.Writer) error {
```
to:
```go
func Run(opts *Options, out io.Writer, _ ...RunOption) error {
```

- [ ] **Step 4: Add RunOption to pkg/csaf/csaf.go**

Add after the imports:

```go
// RunOption configures a Run() call with extensions.
type RunOption func(*runConfig)

type runConfig struct{}
```

Change line 37 from:
```go
func Run(opts *Options, out io.Writer) error {
```
to:
```go
func Run(opts *Options, out io.Writer, _ ...RunOption) error {
```

- [ ] **Step 5: Run full test suite**

Run: `go test -race -count=1 ./...`
Expected: All tests PASS. The variadic parameter is backward-compatible.

- [ ] **Step 6: Commit**

```bash
git add pkg/report/report.go pkg/policykit/policykit.go pkg/evidence/evidence.go pkg/csaf/csaf.go
git commit -m "feat: add RunOption variadic parameter to report, policykit, evidence, csaf Run()"
```

---

### Task 6: CLI Layer Wiring — Pass Extensions to Run()

Update the CLI command handlers to pass `RunConfig` extensions into the package `Run()` calls. Wire up hook execution via `toolkit.ExecuteWithHooks`.

**Files:**
- Modify: `internal/cli/root.go`
- Modify: `internal/cli/vex.go`
- Modify: `internal/cli/policykit.go`
- Modify: `internal/cli/report.go`
- Modify: `internal/cli/evidence.go`
- Modify: `internal/cli/csaf.go`

- [ ] **Step 1: Update root.go to pass cfg to command factories**

The command factory functions need to receive `RunConfig` so they can pass extensions to `Run()`. Update `internal/cli/root.go`:

```go
func New(version string, cfg RunConfig) *urfave.Command {
	cmd := &urfave.Command{
		Name:    "cra",
		Usage:   "SUSE CRA Compliance Toolkit",
		Version: version,
		Flags: []urfave.Flag{
			&urfave.StringFlag{
				Name:    "format",
				Aliases: []string{"f"},
				Value:   "json",
				Usage:   "output format: json or text",
			},
			&urfave.StringFlag{
				Name:    "output",
				Aliases: []string{"o"},
				Usage:   "output file path (default: stdout)",
			},
			&urfave.BoolFlag{
				Name:    "quiet",
				Aliases: []string{"q"},
				Usage:   "suppress non-essential output",
			},
			&urfave.BoolFlag{
				Name:  "verbose",
				Usage: "enable debug logging",
			},
		},
		Commands: []*urfave.Command{
			newVersionCmd(version),
			newVexCmd(cfg),
			newPolicykitCmd(cfg),
			newReportCmd(cfg),
			newEvidenceCmd(cfg),
			newCsafCmd(cfg),
		},
	}

	cmd.Commands = append(cmd.Commands, cfg.ExtraCommands...)

	return cmd
}
```

- [ ] **Step 2: Update vex.go to pass extensions**

Update `internal/cli/vex.go`. Add imports for `"context"`, `"github.com/ravan/cra-toolkit/pkg/toolkit"`, `"github.com/ravan/cra-toolkit/pkg/formats"`:

```go
func newVexCmd(cfg RunConfig) *urfave.Command {
	return &urfave.Command{
		Name:  "vex",
		Usage: "Determine VEX status for vulnerabilities against an SBOM",
		Flags: []urfave.Flag{
			// ... all existing flags unchanged ...
		},
		Action: func(ctx context.Context, cmd *urfave.Command) error {
			outputFormat := cmd.String("output-format")
			if !hasVEXWriter(outputFormat, cfg.ExtraVEXWriters) {
				return fmt.Errorf("unsupported output format %q", outputFormat)
			}

			opts := &vex.Options{
				SBOMPath:         cmd.String("sbom"),
				ScanPaths:        cmd.StringSlice("scan"),
				UpstreamVEXPaths: cmd.StringSlice("upstream-vex"),
				SourceDir:        cmd.String("source-dir"),
				OutputFormat:     outputFormat,
			}

			w, closer := OutputWriter(cmd)
			defer closer() //nolint:errcheck // closer returns nil for stdout

			// Build RunOptions from config.
			var runOpts []vex.RunOption
			if len(cfg.ExtraFilters) > 0 {
				runOpts = append(runOpts, vex.WithExtraFilters(cfg.ExtraFilters))
			}
			if len(cfg.ExtraAnalyzers) > 0 {
				runOpts = append(runOpts, vex.WithExtraAnalyzers(cfg.ExtraAnalyzers))
			}
			if len(cfg.ExtraScanParsers) > 0 {
				runOpts = append(runOpts, vex.WithExtraScanParsers(cfg.ExtraScanParsers))
			}
			if len(cfg.ExtraSBOMParsers) > 0 {
				runOpts = append(runOpts, vex.WithExtraSBOMParsers(cfg.ExtraSBOMParsers))
			}
			if len(cfg.ExtraVEXWriters) > 0 {
				runOpts = append(runOpts, vex.WithExtraVEXWriters(cfg.ExtraVEXWriters))
			}
			if len(cfg.ExtraFormatProbes) > 0 {
				runOpts = append(runOpts, vex.WithExtraFormatProbes(cfg.ExtraFormatProbes))
			}

			// Wrap with hooks.
			hooks := buildHooks(cfg, "vex")
			return toolkit.ExecuteWithHooks(ctx, "vex", hooks, opts, func() error {
				return vex.Run(opts, w, runOpts...)
			})
		},
	}
}

// hasVEXWriter checks if the given format has a built-in or registered writer.
func hasVEXWriter(format string, extra map[string]formats.VEXWriter) bool {
	if format == "openvex" || format == "csaf" {
		return true
	}
	_, ok := extra[format]
	return ok
}
```

Add a helper function to convert `RunConfig` hooks to `toolkit.Hook` slices. Since `internal/cli` cannot import `pkg/toolkit` (circular dep), we need a different approach.

Wait — I need to re-examine the dependency graph:

- `internal/cli/vex.go` calls `toolkit.ExecuteWithHooks()` → imports `pkg/toolkit`
- `internal/cli/config.go` has `RunConfig` → must NOT import `pkg/toolkit` (or we get a cycle)

But `vex.go` importing `toolkit` is fine as long as `config.go` doesn't. Let me check: `config.go` defines `RunConfig` with `PreHooks`/`PostHooks` using `HookFn` (a type alias defined locally). `vex.go` imports `toolkit` for `ExecuteWithHooks`. That works — the cycle would only happen if `config.go` imported `toolkit`.

But `toolkit.ExecuteWithHooks` takes `[]toolkit.Hook`, and `RunConfig` has `PreHooks`/`PostHooks` maps. We need to convert. Add a helper in `vex.go` (or a shared file in `internal/cli/`):

```go
// buildHooks converts RunConfig pre/post hooks to toolkit.Hook slice.
func buildHooks(cfg RunConfig, pkg string) []toolkit.Hook {
	var hooks []toolkit.Hook
	for _, fn := range cfg.PreHooks[pkg] {
		hooks = append(hooks, toolkit.Hook{Phase: toolkit.Pre, Fn: fn})
	}
	for _, fn := range cfg.PostHooks[pkg] {
		hooks = append(hooks, toolkit.Hook{Phase: toolkit.Post, Fn: fn})
	}
	return hooks
}
```

This goes in a new file `internal/cli/hooks.go` (shared by all command files):

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package cli

import "github.com/ravan/cra-toolkit/pkg/toolkit"

// buildHooks converts RunConfig pre/post hooks into a toolkit.Hook slice
// for a specific package.
func buildHooks(cfg RunConfig, pkg string) []toolkit.Hook {
	var hooks []toolkit.Hook
	for _, fn := range cfg.PreHooks[pkg] {
		hooks = append(hooks, toolkit.Hook{Phase: toolkit.Pre, Fn: fn})
	}
	for _, fn := range cfg.PostHooks[pkg] {
		hooks = append(hooks, toolkit.Hook{Phase: toolkit.Post, Fn: fn})
	}
	return hooks
}
```

This file imports `pkg/toolkit` but `config.go` does not — no cycle.

- [ ] **Step 3: Update policykit.go**

```go
func newPolicykitCmd(cfg RunConfig) *urfave.Command {
	return &urfave.Command{
		// ... all existing flags unchanged ...
		Action: func(ctx context.Context, cmd *urfave.Command) error {
			// ... existing option parsing unchanged ...

			w, closer := OutputWriter(cmd)
			defer closer() //nolint:errcheck // output writer close errors are non-actionable at this point

			hooks := buildHooks(cfg, "policykit")
			return toolkit.ExecuteWithHooks(ctx, "policykit", hooks, opts, func() error {
				return policykit.Run(opts, w)
			})
		},
	}
}
```

- [ ] **Step 4: Update report.go**

```go
func newReportCmd(cfg RunConfig) *urfave.Command {
	return &urfave.Command{
		// ... all existing flags unchanged ...
		Action: func(ctx context.Context, cmd *urfave.Command) error {
			// ... existing option parsing unchanged ...

			w, closer := OutputWriter(cmd)
			defer closer() //nolint:errcheck // output writer close errors are non-actionable

			hooks := buildHooks(cfg, "report")
			return toolkit.ExecuteWithHooks(ctx, "report", hooks, opts, func() error {
				return report.Run(opts, w)
			})
		},
	}
}
```

- [ ] **Step 5: Update evidence.go**

```go
func newEvidenceCmd(cfg RunConfig) *urfave.Command {
	return &urfave.Command{
		// ... all existing flags unchanged ...
		Action: func(ctx context.Context, cmd *urfave.Command) error {
			// ... existing option building unchanged ...

			w, closer := OutputWriter(cmd)
			defer closer() //nolint:errcheck // CLI cleanup

			hooks := buildHooks(cfg, "evidence")
			return toolkit.ExecuteWithHooks(ctx, "evidence", hooks, opts, func() error {
				return evidence.Run(opts, w)
			})
		},
	}
}
```

- [ ] **Step 6: Update csaf.go**

```go
func newCsafCmd(cfg RunConfig) *urfave.Command {
	return &urfave.Command{
		// ... all existing flags unchanged ...
		Action: func(ctx context.Context, cmd *urfave.Command) error {
			// ... existing option building unchanged ...

			w, closer := OutputWriter(cmd)
			defer closer() //nolint:errcheck // closer returns nil for stdout

			hooks := buildHooks(cfg, "csaf")
			return toolkit.ExecuteWithHooks(ctx, "csaf", hooks, opts, func() error {
				return csaf.Run(opts, w)
			})
		},
	}
}
```

- [ ] **Step 7: Run full test suite**

Run: `go test -race -count=1 ./...`
Expected: All tests PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/cli/root.go internal/cli/hooks.go internal/cli/vex.go internal/cli/policykit.go internal/cli/report.go internal/cli/evidence.go internal/cli/csaf.go
git commit -m "feat: wire RunConfig extensions through CLI layer to package Run() calls"
```

---

### Task 7: Toolkit App and RunCLI

Create the `App` struct, registration methods, and `RunCLI()`. This is the public facade that Phase 2 will import.

**Files:**
- Create: `pkg/toolkit/toolkit.go`
- Create: `pkg/toolkit/toolkit_test.go`

- [ ] **Step 1: Write failing tests for App**

Create `pkg/toolkit/toolkit_test.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package toolkit_test

import (
	"context"
	"encoding/json"
	"io"
	"testing"

	urfave "github.com/urfave/cli/v3"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/toolkit"
	"github.com/ravan/cra-toolkit/pkg/vex"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability"
)

// stubFilter is a test filter that always resolves with not_affected.
type stubFilter struct{ name string }

func (f *stubFilter) Name() string { return f.name }
func (f *stubFilter) Evaluate(_ *formats.Finding, _ []formats.Component) (vex.Result, bool) {
	return vex.Result{Status: formats.StatusNotAffected, ResolvedBy: f.name}, true
}

// stubAnalyzer is a test analyzer.
type stubAnalyzer struct{ lang string }

func (a *stubAnalyzer) Language() string { return a.lang }
func (a *stubAnalyzer) Analyze(_ context.Context, _ string, _ *formats.Finding) (reachability.Result, error) {
	return reachability.Result{Reachable: false}, nil
}

// stubScanParser is a test scan parser.
type stubScanParser struct{}

func (p *stubScanParser) Parse(_ io.Reader) ([]formats.Finding, error) {
	return []formats.Finding{{CVE: "CVE-2099-0001"}}, nil
}

// stubSBOMParser is a test SBOM parser.
type stubSBOMParser struct{}

func (p *stubSBOMParser) Parse(_ io.Reader) ([]formats.Component, error) {
	return []formats.Component{{Name: "stub"}}, nil
}

// stubVEXWriter is a test VEX writer.
type stubVEXWriter struct{}

func (w *stubVEXWriter) Write(out io.Writer, results []formats.VEXResult) error {
	return json.NewEncoder(out).Encode(results)
}

func TestNew(t *testing.T) {
	app := toolkit.New("1.0.0")
	require.NotNil(t, app)
}

func TestRegisterFilter(t *testing.T) {
	app := toolkit.New("1.0.0")
	app.RegisterFilter(&stubFilter{name: "test-filter"})

	cfg := app.BuildConfig()
	require.Len(t, cfg.ExtraFilters, 1)
	assert.Equal(t, "test-filter", cfg.ExtraFilters[0].Name())
}

func TestRegisterFilter_Multiple(t *testing.T) {
	app := toolkit.New("1.0.0")
	app.RegisterFilter(&stubFilter{name: "f1"})
	app.RegisterFilter(&stubFilter{name: "f2"})

	cfg := app.BuildConfig()
	require.Len(t, cfg.ExtraFilters, 2)
}

func TestRegisterAnalyzer(t *testing.T) {
	app := toolkit.New("1.0.0")
	app.RegisterAnalyzer("ruby", &stubAnalyzer{lang: "ruby"})

	cfg := app.BuildConfig()
	require.Contains(t, cfg.ExtraAnalyzers, "ruby")
}

func TestRegisterAnalyzer_OverridesSameKey(t *testing.T) {
	app := toolkit.New("1.0.0")
	first := &stubAnalyzer{lang: "go"}
	second := &stubAnalyzer{lang: "go"}
	app.RegisterAnalyzer("go", first)
	app.RegisterAnalyzer("go", second)

	cfg := app.BuildConfig()
	assert.Equal(t, second, cfg.ExtraAnalyzers["go"])
}

func TestRegisterCommand(t *testing.T) {
	app := toolkit.New("1.0.0")
	cmd := &urfave.Command{Name: "agent", Usage: "run the agent"}
	app.RegisterCommand(cmd)

	cfg := app.BuildConfig()
	require.Len(t, cfg.ExtraCommands, 1)
	assert.Equal(t, "agent", cfg.ExtraCommands[0].Name)
}

func TestRegisterScanParser(t *testing.T) {
	app := toolkit.New("1.0.0")
	app.RegisterScanParser(formats.Format(100), &stubScanParser{})

	cfg := app.BuildConfig()
	require.Contains(t, cfg.ExtraScanParsers, formats.Format(100))
}

func TestRegisterSBOMParser(t *testing.T) {
	app := toolkit.New("1.0.0")
	app.RegisterSBOMParser(formats.Format(101), &stubSBOMParser{})

	cfg := app.BuildConfig()
	require.Contains(t, cfg.ExtraSBOMParsers, formats.Format(101))
}

func TestRegisterVEXWriter(t *testing.T) {
	app := toolkit.New("1.0.0")
	app.RegisterVEXWriter("custom-vex", &stubVEXWriter{})

	cfg := app.BuildConfig()
	require.Contains(t, cfg.ExtraVEXWriters, "custom-vex")
}

func TestRegisterHook(t *testing.T) {
	app := toolkit.New("1.0.0")
	hookFn := func(_ context.Context, _ string, _ any, _ error) error { return nil }
	err := app.RegisterHook("vex", toolkit.Hook{Phase: toolkit.Post, Fn: hookFn})
	require.NoError(t, err)

	cfg := app.BuildConfig()
	require.Len(t, cfg.PostHooks["vex"], 1)
}

func TestRegisterHook_PreHook(t *testing.T) {
	app := toolkit.New("1.0.0")
	hookFn := func(_ context.Context, _ string, _ any, _ error) error { return nil }
	err := app.RegisterHook("report", toolkit.Hook{Phase: toolkit.Pre, Fn: hookFn})
	require.NoError(t, err)

	cfg := app.BuildConfig()
	require.Len(t, cfg.PreHooks["report"], 1)
}

func TestRegisterHook_InvalidPackage(t *testing.T) {
	app := toolkit.New("1.0.0")
	hookFn := func(_ context.Context, _ string, _ any, _ error) error { return nil }
	err := app.RegisterHook("invalid-pkg", toolkit.Hook{Phase: toolkit.Pre, Fn: hookFn})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid-pkg")
}

func TestRegisterFormatProbe(t *testing.T) {
	app := toolkit.New("1.0.0")
	probe := formats.FormatProbe{
		Format: formats.Format(100),
		Detect: func(_ map[string]json.RawMessage) bool { return true },
	}
	app.RegisterFormatProbe(probe)

	cfg := app.BuildConfig()
	require.Len(t, cfg.ExtraFormatProbes, 1)
}

func TestRunCLI_VersionCommand(t *testing.T) {
	app := toolkit.New("1.2.3")
	// Running "cra version" should succeed without error.
	err := app.RunCLI(context.Background(), []string{"cra", "version"})
	require.NoError(t, err)
}

func TestRunCLI_ExtraCommand(t *testing.T) {
	var called bool
	app := toolkit.New("1.0.0")
	app.RegisterCommand(&urfave.Command{
		Name:  "custom",
		Usage: "a custom command",
		Action: func(_ context.Context, _ *urfave.Command) error {
			called = true
			return nil
		},
	})

	err := app.RunCLI(context.Background(), []string{"cra", "custom"})
	require.NoError(t, err)
	assert.True(t, called)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -race -count=1 ./pkg/toolkit/ -run "TestNew|TestRegister|TestRunCLI"`
Expected: Compilation failure — `toolkit.New` returns nothing useful, `BuildConfig()` not defined.

- [ ] **Step 3: Implement App struct**

Create `pkg/toolkit/toolkit.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

// Package toolkit provides the extensible entry point for the CRA toolkit.
// External modules (e.g. a commercial product) import this package to register
// additional filters, analyzers, commands, parsers, writers, and hooks
// without forking the open-source codebase.
package toolkit

import (
	"context"
	"fmt"

	urfave "github.com/urfave/cli/v3"

	"github.com/ravan/cra-toolkit/internal/cli"
	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/vex"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability"
)

// validPackages lists the package names that support hooks.
var validPackages = map[string]bool{
	"vex":       true,
	"report":    true,
	"csaf":      true,
	"evidence":  true,
	"policykit": true,
}

// App is the extensible entry point for the CRA toolkit.
// Create with New(), register extensions, then call RunCLI().
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
}

// New creates a toolkit App with the given version string.
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

// RegisterFilter appends a filter to the VEX filter chain (after built-in filters).
func (a *App) RegisterFilter(f vex.Filter) {
	a.filters = append(a.filters, f)
}

// RegisterAnalyzer registers a reachability analyzer for a language.
// Registering an existing language replaces the built-in analyzer.
func (a *App) RegisterAnalyzer(lang string, az reachability.Analyzer) {
	a.analyzers[lang] = az
}

// RegisterCommand adds a CLI subcommand.
func (a *App) RegisterCommand(cmd *urfave.Command) {
	a.commands = append(a.commands, cmd)
}

// RegisterScanParser registers a scan parser for a custom format.
// Use a custom formats.Format constant (e.g. const FormatSnyk formats.Format = 100).
func (a *App) RegisterScanParser(format formats.Format, p formats.ScanParser) {
	a.scanParsers[format] = p
}

// RegisterSBOMParser registers an SBOM parser for a custom format.
func (a *App) RegisterSBOMParser(format formats.Format, p formats.SBOMParser) {
	a.sbomParsers[format] = p
}

// RegisterVEXWriter registers a VEX output writer for a named format.
func (a *App) RegisterVEXWriter(name string, w formats.VEXWriter) {
	a.vexWriters[name] = w
}

// RegisterHook adds a pre/post hook for a package's Run() function.
// Valid package names: "vex", "report", "csaf", "evidence", "policykit".
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

// RegisterFormatProbe adds a format detection probe (checked after built-in probes).
func (a *App) RegisterFormatProbe(p formats.FormatProbe) {
	a.probes = append(a.probes, p)
}

// BuildConfig returns the RunConfig for passing to cli.New().
// This bridges the public facade with the internal CLI layer.
func (a *App) BuildConfig() cli.RunConfig {
	return cli.RunConfig{
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

// RunCLI builds the CLI with base + registered commands, injects all
// registered extensions, and executes.
func (a *App) RunCLI(ctx context.Context, args []string) error {
	cmd := cli.New(a.version, a.BuildConfig())
	return cmd.Run(ctx, args)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -race -count=1 ./pkg/toolkit/...`
Expected: All tests PASS.

- [ ] **Step 5: Run full test suite**

Run: `go test -race -count=1 ./...`
Expected: All tests PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/toolkit/toolkit.go pkg/toolkit/toolkit_test.go
git commit -m "feat: add toolkit App facade with registration API and RunCLI"
```

---

### Task 8: Taskfile Entry and Quality Gate

Add test task for the toolkit package and run all quality gates.

**Files:**
- Modify: `Taskfile.yml`

- [ ] **Step 1: Add test:toolkit task**

Add after the `test:reachability:llmjudge` task in `Taskfile.yml`:

```yaml
  test:toolkit:
    desc: Run toolkit facade tests
    cmds:
      - go test -race -count=1 -v ./pkg/toolkit/...
```

- [ ] **Step 2: Run the full quality gate**

Run: `task quality`
Expected: fmt:check, vet, lint, test — all PASS.

- [ ] **Step 3: Fix any lint issues**

If golangci-lint reports issues, fix them. Common issues:
- Unused parameters (the `_ ...RunOption` on report/policykit/evidence/csaf)
- Import ordering
- Comment formatting

- [ ] **Step 4: Run all integration tests**

Run: `task test:integration && task test:policykit && task test:report && task test:evidence`
Expected: All PASS.

- [ ] **Step 5: Run all reachability tests**

Run: `task test:reachability`
Expected: All PASS.

- [ ] **Step 6: Commit Taskfile**

```bash
git add Taskfile.yml
git commit -m "chore: add test:toolkit task to Taskfile"
```

---

### Task 9: End-to-End Integration Test

A comprehensive test that creates a `toolkit.App`, registers extensions, and runs the full VEX pipeline through `RunCLI` to verify end-to-end extension flow.

**Files:**
- Create: `pkg/toolkit/integration_test.go`

- [ ] **Step 1: Write the integration test**

Create `pkg/toolkit/integration_test.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package toolkit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/toolkit"
	"github.com/ravan/cra-toolkit/pkg/vex"
)

const fixtureBase = "../../testdata/integration"

func TestIntegration_CustomFilterInVEXPipeline(t *testing.T) {
	// Register a custom filter that marks a specific CVE as not_affected.
	app := toolkit.New("test")
	app.RegisterFilter(&targetedFilter{
		targetCVE: "CVE-2022-32149",
	})

	// Run the VEX command via RunCLI, capture output to a temp file.
	outFile, err := os.CreateTemp(t.TempDir(), "vex-*.json")
	require.NoError(t, err)
	outPath := outFile.Name()
	outFile.Close()

	err = app.RunCLI(context.Background(), []string{
		"cra", "vex",
		"--sbom", fixtureBase + "/go-reachable/sbom.cdx.json",
		"--scan", fixtureBase + "/go-reachable/grype.json",
		"--output-format", "openvex",
		"--output", outPath,
	})
	require.NoError(t, err)

	// Read and parse the output.
	data, err := os.ReadFile(outPath)
	require.NoError(t, err)

	var doc struct {
		Statements []struct {
			Vulnerability struct{ Name string } `json:"vulnerability"`
			Status        string                `json:"status"`
			Justification string                `json:"justification,omitempty"`
		} `json:"statements"`
	}
	require.NoError(t, json.Unmarshal(data, &doc))

	// Find the targeted CVE and verify the custom filter resolved it.
	for _, stmt := range doc.Statements {
		if stmt.Vulnerability.Name == "CVE-2022-32149" {
			assert.Equal(t, "not_affected", stmt.Status)
			return
		}
	}
	t.Error("CVE-2022-32149 not found in output statements")
}

func TestIntegration_HooksFireDuringVEX(t *testing.T) {
	app := toolkit.New("test")

	var preRan, postRan bool
	var postErr error

	err := app.RegisterHook("vex", toolkit.Hook{
		Phase: toolkit.Pre,
		Fn: func(_ context.Context, pkg string, _ any, _ error) error {
			preRan = true
			assert.Equal(t, "vex", pkg)
			return nil
		},
	})
	require.NoError(t, err)

	err = app.RegisterHook("vex", toolkit.Hook{
		Phase: toolkit.Post,
		Fn: func(_ context.Context, pkg string, _ any, fnErr error) error {
			postRan = true
			postErr = fnErr
			return nil
		},
	})
	require.NoError(t, err)

	outFile, err := os.CreateTemp(t.TempDir(), "vex-*.json")
	require.NoError(t, err)
	outPath := outFile.Name()
	outFile.Close()

	err = app.RunCLI(context.Background(), []string{
		"cra", "vex",
		"--sbom", fixtureBase + "/go-reachable/sbom.cdx.json",
		"--scan", fixtureBase + "/go-reachable/grype.json",
		"--output", outPath,
	})
	require.NoError(t, err)

	assert.True(t, preRan, "pre-hook should have fired")
	assert.True(t, postRan, "post-hook should have fired")
	assert.NoError(t, postErr, "post-hook should receive nil error on success")
}

func TestIntegration_ExtraCommandViaRunCLI(t *testing.T) {
	app := toolkit.New("test")

	var buf bytes.Buffer
	app.RegisterCommand(&urfave.Command{
		Name:  "hello",
		Usage: "test command",
		Action: func(_ context.Context, _ *urfave.Command) error {
			buf.WriteString("hello from extension")
			return nil
		},
	})

	err := app.RunCLI(context.Background(), []string{"cra", "hello"})
	require.NoError(t, err)
	assert.Equal(t, "hello from extension", buf.String())
}

func TestIntegration_ZeroExtensions_IdenticalBehavior(t *testing.T) {
	// An app with no extensions should produce identical output to the base CLI.
	app := toolkit.New("test")

	outFile, err := os.CreateTemp(t.TempDir(), "vex-*.json")
	require.NoError(t, err)
	outPath := outFile.Name()
	outFile.Close()

	err = app.RunCLI(context.Background(), []string{
		"cra", "vex",
		"--sbom", fixtureBase + "/go-reachable/sbom.cdx.json",
		"--scan", fixtureBase + "/go-reachable/grype.json",
		"--output-format", "openvex",
		"--output", outPath,
	})
	require.NoError(t, err)

	data, err := os.ReadFile(outPath)
	require.NoError(t, err)

	// Verify it's valid OpenVEX.
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &doc))
	ctx, ok := doc["@context"].(string)
	require.True(t, ok)
	assert.Contains(t, ctx, "openvex")
}

// targetedFilter marks a specific CVE as not_affected.
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
			Evidence:      "Resolved by targeted extension filter in integration test",
		}, true
	}
	return vex.Result{}, false
}
```

Add the missing import for `urfave`:
```go
import (
	urfave "github.com/urfave/cli/v3"
	// ... other imports ...
)
```

- [ ] **Step 2: Run integration tests**

Run: `go test -race -count=1 -v ./pkg/toolkit/ -run TestIntegration`
Expected: All 4 integration tests PASS.

- [ ] **Step 3: Run full test suite to verify no regressions**

Run: `go test -race -count=1 ./...`
Expected: All tests PASS.

- [ ] **Step 4: Commit**

```bash
git add pkg/toolkit/integration_test.go
git commit -m "test: add end-to-end integration tests for toolkit facade"
```

---

### Task 10: Final Verification

Run every test command in the Taskfile to verify zero regressions.

- [ ] **Step 1: Run full quality gate**

Run: `task quality`
Expected: fmt:check PASS, vet PASS, lint PASS, test PASS.

- [ ] **Step 2: Run integration tests**

Run: `task test:integration`
Expected: All PASS.

- [ ] **Step 3: Run policykit tests**

Run: `task test:policykit`
Expected: All PASS.

- [ ] **Step 4: Run report tests**

Run: `task test:report`
Expected: All PASS.

- [ ] **Step 5: Run evidence tests**

Run: `task test:evidence`
Expected: All PASS.

- [ ] **Step 6: Run reachability tests**

Run: `task test:reachability`
Expected: All PASS.

- [ ] **Step 7: Run toolkit tests**

Run: `task test:toolkit`
Expected: All PASS.

- [ ] **Step 8: Build binary**

Run: `task build`
Expected: Binary builds successfully at `bin/cra`.

- [ ] **Step 9: Smoke test binary**

Run: `./bin/cra version`
Expected: Prints version string.

Run: `./bin/cra --help`
Expected: Shows help with all commands (vex, policykit, report, evidence, csaf, version).

- [ ] **Step 10: Commit any final fixes**

If any step above required fixes, commit them:

```bash
git add -A
git commit -m "fix: address lint/test issues from final verification"
```
