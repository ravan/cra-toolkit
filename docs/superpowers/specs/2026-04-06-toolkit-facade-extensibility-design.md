# Toolkit Facade Extensibility Design

**Date:** 2026-04-06
**Status:** Draft

## Goal

Make the open-source CRA toolkit extensible so that a separate commercial repository can import it as a Go module dependency and add LLM-enhanced capabilities without forking. The open-source binary must remain functionally identical — zero behavior change for existing users.

This is strictly a Phase 1 (open-source) change. Phase 2 (commercial product) internals are out of scope.

## Approach

**Toolkit Facade pattern.** A new `pkg/toolkit/` package provides a single entry point (`toolkit.App`) with registration methods for filters, analyzers, commands, parsers, writers, and hooks. The existing `internal/cli/` stays internal. The open-source binary passes empty registrations — all code paths remain identical.

Phase 2 creates its own binary that imports `pkg/toolkit/`, registers its extensions, and calls `RunCLI()`. No forking, no vendoring, no Go plugins.

## Deliverables

| Deliverable | Description |
|---|---|
| `pkg/toolkit/` package | `App` struct with registration API and `RunCLI()` entry point |
| `RunOption` pattern on all `Run()` functions | Variadic options for extra filters, analyzers, parsers, writers, hooks |
| `FormatProbe` extensibility | Pluggable format detection in `pkg/formats/detect.go` |
| `RunConfig` internal plumbing | Internal struct passing registrations from facade through CLI to packages |
| Full test coverage | Unit tests for facade, integration tests for extension flow, LLM judge tests updated |

## Architecture

### The Facade: `pkg/toolkit/`

```go
package toolkit

import (
    "context"

    urfave "github.com/urfave/cli/v3"

    "github.com/ravan/cra-toolkit/pkg/formats"
    "github.com/ravan/cra-toolkit/pkg/vex"
    "github.com/ravan/cra-toolkit/pkg/vex/reachability"
)

// App is the extensible entry point for the CRA toolkit.
type App struct {
    version     string
    filters     []vex.Filter
    analyzers   map[string]reachability.Analyzer
    commands    []*urfave.Command
    scanParsers map[string]formats.ScanParser
    sbomParsers map[string]formats.SBOMParser
    vexWriters  map[string]formats.VEXWriter
    hooks       map[string][]Hook
}

// HookPhase determines when a hook fires relative to Run().
type HookPhase int

const (
    Pre  HookPhase = iota
    Post
)

// Hook runs before or after a package's Run() function.
type Hook struct {
    Phase HookPhase
    Fn    HookFunc
}

// HookFunc receives the package name ("vex", "report", etc.),
// the options struct (as any), and for Post hooks, the error result.
type HookFunc func(ctx context.Context, pkg string, opts any, err error) error

// New creates a toolkit App with the given version string.
func New(version string) *App

// RegisterFilter appends a filter to the VEX filter chain (after built-in filters).
func (a *App) RegisterFilter(f vex.Filter)

// RegisterAnalyzer registers a reachability analyzer for a language.
// Registering an existing language replaces the built-in analyzer.
func (a *App) RegisterAnalyzer(lang string, az reachability.Analyzer)

// RegisterCommand adds a CLI subcommand.
func (a *App) RegisterCommand(cmd *urfave.Command)

// RegisterScanParser registers a scan parser for a named format.
func (a *App) RegisterScanParser(name string, p formats.ScanParser)

// RegisterSBOMParser registers an SBOM parser for a named format.
func (a *App) RegisterSBOMParser(name string, p formats.SBOMParser)

// RegisterVEXWriter registers a VEX output writer for a named format.
func (a *App) RegisterVEXWriter(name string, w formats.VEXWriter)

// RegisterHook adds a pre/post hook for a package's Run() function.
// Valid package names: "vex", "report", "csaf", "evidence", "policykit".
func (a *App) RegisterHook(pkg string, h Hook)

// RegisterFormatProbe adds a format detection probe (checked after built-in probes).
func (a *App) RegisterFormatProbe(p formats.FormatProbe)

// RunCLI builds the CLI with base + registered commands, injects all
// registered extensions, and executes.
func (a *App) RunCLI(ctx context.Context, args []string) error
```

### Phase 2 Usage Example

```go
// cmd/cra-enterprise/main.go
package main

import (
    "context"
    "os"

    "github.com/ravan/cra-toolkit/pkg/toolkit"
)

func main() {
    app := toolkit.New(version)

    // Extend VEX pipeline
    app.RegisterFilter(llmReachFilter)
    app.RegisterAnalyzer("dynamic", llmAnalyzer)

    // Add commands
    app.RegisterCommand(newAgentCmd())
    app.RegisterCommand(newExplainCmd())
    app.RegisterCommand(newConsistencyCmd())

    // Add post-run validation
    app.RegisterHook("report", toolkit.Hook{
        Phase: toolkit.Post,
        Fn:    consistencyChecker.Validate,
    })

    if err := app.RunCLI(context.Background(), os.Args); err != nil {
        os.Exit(1)
    }
}
```

### Internal Plumbing: `RunConfig`

A new internal struct carries registrations from the facade through the CLI layer to the packages.

```go
// internal/cli/config.go
package cli

type RunConfig struct {
    ExtraFilters      []vex.Filter
    ExtraAnalyzers    map[string]reachability.Analyzer
    ExtraCommands     []*urfave.Command
    ExtraScanParsers  map[string]formats.ScanParser
    ExtraSBOMParsers  map[string]formats.SBOMParser
    ExtraVEXWriters   map[string]formats.VEXWriter
    ExtraFormatProbes []formats.FormatProbe
    Hooks             map[string][]toolkit.Hook
}
```

`cli.New()` signature changes from `New(version string)` to `New(version string, cfg RunConfig)`. The open-source binary passes `RunConfig{}`.

### Run() Function Extensions

Each `Run()` function gains variadic `RunOption` parameters. The existing signatures remain valid (zero options = current behavior).

**pkg/vex/vex.go:**
```go
type RunOption func(*runConfig)

type runConfig struct {
    extraFilters     []Filter
    extraAnalyzers   map[string]reachability.Analyzer
    extraScanParsers map[string]formats.ScanParser
    extraSBOMParsers map[string]formats.SBOMParser
    extraVEXWriters  map[string]formats.VEXWriter
    extraProbes      []formats.FormatProbe
    hooks            []toolkit.Hook
}

func WithExtraFilters(filters []Filter) RunOption
func WithExtraAnalyzers(analyzers map[string]reachability.Analyzer) RunOption
func WithExtraScanParsers(parsers map[string]formats.ScanParser) RunOption
func WithExtraSBOMParsers(parsers map[string]formats.SBOMParser) RunOption
func WithExtraVEXWriters(writers map[string]formats.VEXWriter) RunOption
func WithExtraFormatProbes(probes []formats.FormatProbe) RunOption
func WithHooks(hooks []toolkit.Hook) RunOption

func Run(opts *Options, out io.Writer, runOpts ...RunOption) error
```

**pkg/report/report.go, pkg/policykit/policykit.go, pkg/evidence/evidence.go, pkg/csaf/csaf.go:**
```go
type RunOption func(*runConfig)

type runConfig struct {
    hooks            []toolkit.Hook
    extraScanParsers map[string]formats.ScanParser  // csaf only
}

func WithHooks(hooks []toolkit.Hook) RunOption

func Run(opts *Options, out io.Writer, runOpts ...RunOption) error
```

### Filter Chain Extension

`buildFilterChain()` accepts extra filters and appends them after the built-in chain:

```go
func buildFilterChain(upstream []formats.VEXStatement, sourceDir string, extra []Filter) []Filter {
    var filters []Filter

    // Upstream filter (only if there are upstream statements).
    if len(upstream) > 0 {
        filters = append(filters, NewUpstreamFilter(upstream))
    }

    // Built-in deterministic filters.
    filters = append(filters,
        NewPresenceFilter(),
        NewVersionFilter(),
        NewPlatformFilter(),
        NewPatchFilter(),
    )

    // Built-in reachability filter.
    if sourceDir != "" {
        analyzers := buildAnalyzers(sourceDir, nil)
        if len(analyzers) > 0 {
            filters = append(filters, NewReachabilityFilter(sourceDir, analyzers))
        }
    }

    // Extension filters (from Phase 2 or other consumers).
    filters = append(filters, extra...)

    return filters
}
```

### Analyzer Registry Extension

`buildAnalyzers()` merges extra analyzers after the built-in switch. Registering an existing language key replaces the built-in:

```go
func buildAnalyzers(sourceDir string, extra map[string]reachability.Analyzer) map[string]reachability.Analyzer {
    analyzers := make(map[string]reachability.Analyzer)
    langs := reachability.DetectLanguages(sourceDir)

    for _, lang := range langs {
        switch lang {
        // ... existing cases unchanged ...
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

### Format Detection Extension

`DetectFormat()` accepts extra probes, checked after all built-in probes:

```go
// pkg/formats/detect.go

// FormatProbe is a pluggable format detection rule.
type FormatProbe struct {
    Format Format
    Detect func(doc map[string]json.RawMessage) bool
}

func DetectFormat(data []byte, extraProbes ...FormatProbe) (Format, error) {
    var doc map[string]json.RawMessage
    if err := json.Unmarshal(data, &doc); err != nil {
        return "", fmt.Errorf("invalid JSON: %w", err)
    }

    // Built-in probes (existing logic, unchanged order).
    // CycloneDX, SPDX, SARIF, OpenVEX, CSAF, Grype, Trivy ...

    // Extension probes.
    for _, probe := range extraProbes {
        if probe.Detect(doc) {
            return probe.Format, nil
        }
    }

    return "", fmt.Errorf("unrecognized format")
}
```

### Parser and Writer Extension

Parse functions check extras in the `default` case of their existing switch:

```go
func parseScan(path string, extraProbes []formats.FormatProbe, extra map[string]formats.ScanParser) ([]formats.Finding, error) {
    format, f, err := openDetected(path, extraProbes)
    if err != nil {
        return nil, err
    }
    defer f.Close()

    switch format {
    case formats.FormatGrype:
        return grype.Parser{}.Parse(f)
    case formats.FormatTrivy:
        return trivy.Parser{}.Parse(f)
    case formats.FormatSARIF:
        return sarif.Parser{}.Parse(f)
    default:
        if p, ok := extra[string(format)]; ok {
            return p.Parse(f)
        }
        return nil, fmt.Errorf("unsupported scan format: %s", format)
    }
}
```

Same pattern for `parseSBOM`, `parseVEX`, and `selectWriter`.

CLI format validation becomes registry-aware:

```go
func hasWriter(format string, extra map[string]formats.VEXWriter) bool {
    if format == "openvex" || format == "csaf" {
        return true
    }
    _, ok := extra[format]
    return ok
}
```

### Hook Execution

A shared helper wraps any `Run()` function with pre/post hooks:

```go
// pkg/toolkit/hooks.go

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

## File Impact

### New Files

| File | Purpose |
|---|---|
| `pkg/toolkit/toolkit.go` | `App` struct, registration methods, `RunCLI()` |
| `pkg/toolkit/hooks.go` | `Hook`, `HookPhase`, `HookFunc`, `ExecuteWithHooks()` |
| `pkg/toolkit/toolkit_test.go` | Unit tests for registration and RunCLI |
| `pkg/toolkit/integration_test.go` | End-to-end extension flow tests |
| `internal/cli/config.go` | `RunConfig` struct |
| `testdata/integration/toolkit-custom-filter/` | Fixture for custom filter integration test |
| `testdata/integration/toolkit-custom-parser/` | Fixture for custom parser integration test |
| `testdata/integration/toolkit-hooks/` | Fixture for hook execution integration test |

### Modified Files

| File | Change |
|---|---|
| `cmd/cra/main.go` | `cli.New(version)` becomes `cli.New(version, cli.RunConfig{})` |
| `internal/cli/root.go` | `New()` accepts `RunConfig`, appends extra commands |
| `internal/cli/vex.go` | Passes extras and hooks to `vex.Run()`; registry-aware format validation |
| `internal/cli/policykit.go` | Passes hooks to `policykit.Run()` |
| `internal/cli/report.go` | Passes hooks to `report.Run()` |
| `internal/cli/evidence.go` | Passes hooks to `evidence.Run()` |
| `internal/cli/csaf.go` | Passes extras and hooks to `csaf.Run()` |
| `pkg/vex/vex.go` | `Run()` gains `...RunOption`; `buildFilterChain()` and `buildAnalyzers()` accept extras; parse functions accept extras |
| `pkg/policykit/policykit.go` | `Run()` gains `...RunOption` for hooks |
| `pkg/report/report.go` | `Run()` gains `...RunOption` for hooks |
| `pkg/evidence/evidence.go` | `Run()` gains `...RunOption` for hooks |
| `pkg/csaf/csaf.go` | `Run()` gains `...RunOption` for hooks and extra parsers |
| `pkg/formats/detect.go` | `DetectFormat()` accepts `[]FormatProbe`; new `FormatProbe` type |
| `Taskfile.yml` | Add `test:toolkit` task |

### Untouched

- All filter implementations (presence, version, platform, patch, upstream, reachability)
- All analyzer implementations (go, rust, python, javascript, java, csharp, php, ruby, generic)
- All parser implementations (grype, trivy, sarif, cyclonedx, spdx, openvex, csafvex)
- All writer implementations
- All Rego policies and templates
- `pkg/formats/` types and interfaces
- `filter.go` (`RunChain()` — already generic over `[]Filter`)
- `reachability/analyzer.go` (interface unchanged)
- `reachability/language.go` (detection unchanged)

## Testing Strategy

### Unit Tests (`pkg/toolkit/toolkit_test.go`)

Test the facade in isolation:

- `TestNew` — App initializes with empty registries
- `TestRegisterFilter` — filter is appended to the list
- `TestRegisterAnalyzer` — analyzer is stored by language key; duplicate key replaces
- `TestRegisterCommand` — command is appended
- `TestRegisterScanParser` — parser stored by name
- `TestRegisterSBOMParser` — parser stored by name
- `TestRegisterVEXWriter` — writer stored by name
- `TestRegisterHook` — hook stored by package name; invalid package name returns error
- `TestRegisterFormatProbe` — probe is appended

### Unit Tests (`pkg/toolkit/hooks_test.go`)

- `TestExecuteWithHooks_PreOnly` — pre-hook fires, fn executes
- `TestExecuteWithHooks_PostOnly` — fn executes, post-hook fires with fn's error
- `TestExecuteWithHooks_PreError` — pre-hook error stops execution, fn never called
- `TestExecuteWithHooks_PostReceivesFnError` — post-hook receives the fn error in its `err` parameter
- `TestExecuteWithHooks_MultipleHooks` — hooks fire in registration order
- `TestExecuteWithHooks_NoHooks` — fn executes normally with empty hook slice

### Unit Tests (`pkg/formats/detect_test.go` — extended)

- `TestDetectFormat_ExtraProbeMatchesAfterBuiltins` — extra probe only fires when built-ins don't match
- `TestDetectFormat_ExtraProbeNoFalsePositive` — extra probe doesn't interfere with built-in detection
- `TestDetectFormat_EmptyExtraProbes` — nil/empty extras produce identical behavior to current code

### Integration Tests (`pkg/toolkit/integration_test.go`)

End-to-end tests using real fixture data:

- `TestIntegration_CustomFilterInVEXChain` — registers a custom filter that marks a specific CVE as `not_affected`, runs VEX pipeline against fixture data, verifies the custom filter's result appears in output
- `TestIntegration_CustomAnalyzerOverridesBuiltin` — registers a custom Go analyzer that returns a different reachability result, verifies it overrides the built-in Go analyzer
- `TestIntegration_CustomScanParser` — registers a custom format probe + parser for a synthetic scan format, runs VEX with a fixture file in that format, verifies findings are parsed
- `TestIntegration_CustomVEXWriter` — registers a custom writer format, runs VEX with `--output-format=custom`, verifies output is produced by the custom writer
- `TestIntegration_PreHookModifiesOptions` — registers a pre-hook that sets a field on the options struct, verifies the modification takes effect
- `TestIntegration_PostHookReceivesError` — registers a post-hook, triggers an error in Run(), verifies the hook receives the error
- `TestIntegration_RunCLIWithExtraCommand` — registers a custom command, invokes it via RunCLI, verifies it executes
- `TestIntegration_ZeroExtensionsMatchesBaseline` — runs with empty RunConfig, compares output byte-for-byte against running the base CLI directly, verifies identical behavior

### Integration Tests (existing — must remain green)

All existing integration tests in `pkg/vex/`, `pkg/csaf/`, `pkg/report/`, `pkg/evidence/`, `pkg/policykit/` must pass without modification. The `Run()` signature change is backward-compatible (variadic options default to empty).

### LLM Judge Tests

Existing LLM judge tests remain unchanged and must pass. No new LLM judge tests are needed for this change — the facade is a structural extension, not a quality-of-output change.

## Backward Compatibility

The open-source binary's behavior is identical before and after this change:

1. `cmd/cra/main.go` passes `cli.RunConfig{}` — all extra slices/maps are nil
2. All `Run()` functions receive zero `RunOption`s — `runConfig` fields are nil/empty
3. `buildFilterChain(upstream, sourceDir, nil)` — `append(filters, nil...)` is a no-op
4. `buildAnalyzers(sourceDir, nil)` — ranging over nil map is a no-op
5. `DetectFormat(data, nil)` — ranging over nil slice is a no-op
6. Parse functions with nil extras — `default` case still returns "unsupported format" error
7. `ExecuteWithHooks` with nil hooks — fn executes directly

No existing test requires modification. No existing behavior changes.
