# Phase 1: Repository Structure & Project Harness Design

**Date:** 2026-04-03
**Status:** Approved
**Scope:** Structural setup of the SUSE CRA Toolkit monorepo for Phase 1 deterministic CLI tools

## 1. Overview

The SUSE CRA Toolkit is a set of five composable CLI tools filling verified gaps in the open-source supply chain security ecosystem for EU Cyber Resilience Act compliance. This spec covers the project harness: repo layout, CLI framework, build system, quality gates, and package architecture. Individual tool implementations will be planned and built in separate sessions.

### Decisions Made

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Repo strategy | Single monorepo | Shared domain code, single version, no cross-repo coordination |
| Binary strategy | Single binary with subcommands | One install, one version, composable via pipes |
| CLI framework | urfave/cli v3 | User preference |
| Go version | 1.24 (latest stable) | Latest language features |
| Module path | `github.com/ravan/cra-toolkit` | Current repo, rename later |
| OPA integration | Embedded (Go library) | Zero external deps, single binary |
| Format libraries | Existing OSS (cyclonedx-go, tools-golang, go-vex, etc.) | "Existing OSS does the heavy lifting" |
| Build system | Taskfile (task.dev) | User preference over Makefile |
| Output formats | JSON (default) + human-readable text | JSON for piping/CI, text for terminal |

## 2. Repository Structure

```
github.com/ravan/cra-toolkit/
├── cmd/
│   └── cra/                        # Single binary entrypoint
│       └── main.go
├── internal/
│   └── cli/                        # CLI wiring: commands, flags, output formatting
│       ├── root.go                 # Root command, global flags (--format, --output)
│       ├── vex.go                  # `cra vex` subcommand
│       ├── policykit.go            # `cra policykit` subcommand
│       ├── report.go               # `cra report` subcommand
│       ├── evidence.go             # `cra evidence` subcommand
│       └── csaf.go                 # `cra csaf` subcommand
├── pkg/
│   ├── vex/                        # VEX status determination logic
│   ├── policykit/                  # OPA policy evaluation engine + bundled Rego policies
│   ├── report/                     # Art. 14 notification generation
│   ├── evidence/                   # Evidence bundling + signing
│   ├── csaf/                       # Scanner-to-CSAF advisory bridge
│   ├── formats/                    # Shared SBOM/VEX/CSAF parsing & generation
│   └── vuln/                       # Shared vuln data fetching (NVD, OSV, KEV, EPSS)
├── policies/                       # Rego policy files for cra-policykit
│   └── annex1/
├── templates/                      # Report templates for cra-report
│   ├── early_warning.tmpl
│   ├── notification.tmpl
│   └── final_report.tmpl
├── testdata/                       # Shared test fixtures (sample SBOMs, scans, etc.)
├── docs/
├── .golangci.yml
├── Taskfile.yml
├── go.mod
├── go.sum
└── README.md
```

## 3. Package Architecture

### Dependency Graph

```
                    cmd/cra/main.go
                         │
                    internal/cli/
                    ┌────┼────┬────────┬──────────┐
                    │    │    │        │          │
                 pkg/vex pkg/policykit pkg/report pkg/evidence pkg/csaf
                    │    │    │        │          │
                    └────┴────┴────┬───┴──────────┘
                                   │
                          ┌────────┴────────┐
                      pkg/formats       pkg/vuln
```

### Dependency Rules

- Arrows only point downward. Domain packages never import each other.
- Domain packages communicate through shared types defined in `pkg/formats`.
- Only `internal/cli/` orchestrates multiple domain packages together (and later, the Phase 2 agent).
- `internal/cli/` is the only package that imports urfave/cli v3. Domain packages have zero CLI dependency.

### Package Responsibilities

| Package | Inputs | Outputs | Key External Deps |
|---------|--------|---------|-------------------|
| `pkg/formats` | Raw JSON/XML files | Parsed Go structs for SBOM, VEX, CSAF, SARIF | `cyclonedx-go`, `tools-golang`, `go-vex` |
| `pkg/vuln` | CVE IDs, CPEs, PURLs | Vulnerability records, KEV status, EPSS scores | NVD/OSV/KEV API clients |
| `pkg/vex` | Parsed SBOM + scan results | OpenVEX document with per-CVE status + justification | `pkg/formats`, `pkg/vuln` |
| `pkg/policykit` | SBOM + VEX + provenance artifacts | Policy evaluation report (pass/fail per rule) | `pkg/formats`, OPA SDK, embedded Rego policies |
| `pkg/report` | CVE data + VEX + product metadata | Art. 14 notification documents (24h/72h/14d) | `pkg/formats`, embedded Go templates |
| `pkg/evidence` | All outputs from above tools | Signed evidence bundle (ZIP with manifest) | `pkg/formats`, Cosign/Sigstore libs |
| `pkg/csaf` | Scan results + VEX assessment | CSAF 2.0 advisory documents | `pkg/formats` |

## 4. CLI Design

### Binary & Subcommands

**Binary name:** `cra`

**Subcommands:**
```
cra vex        # VEX status determination
cra policykit  # CRA Annex I policy evaluation
cra report     # Art. 14 notification generation
cra evidence   # Evidence bundling
cra csaf       # Scanner-to-CSAF bridge
cra version    # Print version/build info
```

Specific flags per subcommand will be designed in individual tool planning sessions.

### Global Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--format` | `-f` | `json` | Output format: `json` or `text` |
| `--output` | `-o` | stdout | Output file path |
| `--quiet` | `-q` | false | Suppress non-essential output |
| `--verbose` | `-v` | false | Debug logging |

### Conventions

- Accept input via file path args or stdin (for piping)
- Output to stdout by default (for piping between tools)
- Errors go to stderr, data goes to stdout
- Exit codes: 0 = success, 1 = error, 2 = policy violations found (for `policykit`)

### Example Composed Pipeline

```bash
cra vex --sbom bom.json --scan grype.json | \
cra csaf --sbom bom.json --vex - | \
cra evidence --sbom bom.json --vex - --sign
```

### Build Info

Version, commit SHA, and build date injected via `-ldflags` at build time.

## 5. Build, Test & Quality

### Taskfile

```
task build       # Build cmd/cra binary to ./bin/cra
task test        # Run all unit tests
task lint        # Full lint suite
task fmt         # gofumpt
task vet         # go vet
task quality     # All quality gates in one pass
task clean       # Remove build artifacts
```

### Quality Gates

All static analysis runs via `golangci-lint` with `.golangci.yml`:

| Tool | What It Catches | Threshold |
|------|----------------|-----------|
| gocyclo | Cyclomatic complexity | Max 9 per function |
| gocognit | Cognitive complexity | Max 12 per function |
| dupl | Duplicate code blocks | 100 token threshold |
| gocritic | Anti-patterns (unnecessary else, redundant assertions, etc.) | Default ruleset |
| gosec | Security issues (hardcoded creds, weak crypto, etc.) | All rules |
| errcheck | Unchecked errors | Strict |
| ineffassign | Useless variable assignments | Default |
| unconvert | Unnecessary type conversions | Default |
| misspell | Typos in comments/strings | Default |
| prealloc | Missing slice preallocation | Default |
| maintidx | Maintainability index (Halstead + cyclomatic + LOC) | Min 20 |

**`task quality`** runs: `fmt` check -> `vet` -> `golangci-lint` (all above) -> `test -race`

### Testing

- Unit tests per package using `testdata/` fixtures
- Table-driven tests (standard Go pattern)
- Shared fixtures at repo root `testdata/`, per-package `testdata/` where needed
- Race detector enabled in CI (`-race`)

### CI (GitHub Actions)

- On PR: `lint` -> `test` -> `build`
- On main: same + release binary builds
- Go version: 1.24

### Embedded Assets

- `policies/` Rego files embedded via `//go:embed` in `pkg/policykit/`
- `templates/` report templates embedded via `//go:embed` in `pkg/report/`

## 6. Key External Dependencies

| Dependency | Purpose | License |
|-----------|---------|---------|
| `github.com/urfave/cli/v3` | CLI framework | MIT |
| `github.com/CycloneDX/cyclonedx-go` | CycloneDX SBOM parsing | Apache 2.0 |
| `github.com/spdx/tools-golang` | SPDX SBOM parsing | Apache 2.0 |
| `github.com/openvex/go-vex` | OpenVEX document handling | Apache 2.0 |
| `github.com/open-policy-agent/opa` | Embedded policy engine | Apache 2.0 |
| `github.com/sigstore/cosign` | Artifact signing | Apache 2.0 |

## 7. What This Spec Does NOT Cover

The following will be designed in separate planning sessions per tool:
- Specific subcommand flags and behavior for each tool
- Detailed VEX determination logic
- Rego policy definitions for CRA Annex I
- Art. 14 report template content and ENISA format
- Evidence bundle schema and signing workflow
- CSAF 2.0 document generation details
- Phase 2 agent architecture
