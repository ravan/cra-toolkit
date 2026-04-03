# Phase 1 Project Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Set up the SUSE CRA Toolkit Go monorepo with a working CLI binary, all package stubs, quality gates, Taskfile, CI, and a passing test suite — ready for individual tool implementations.

**Architecture:** Single Go binary (`cra`) using urfave/cli v3 with subcommands (`vex`, `policykit`, `report`, `evidence`, `csaf`). Domain logic lives in `pkg/` (public, importable). CLI wiring lives in `internal/cli/` (private). Shared types in `pkg/formats/`, shared vuln fetching in `pkg/vuln/`.

**Tech Stack:** Go 1.24, urfave/cli v3, golangci-lint, Taskfile (task.dev), GitHub Actions, gofumpt

---

## File Map

| File | Responsibility |
|------|---------------|
| `go.mod` | Module definition: `github.com/ravan/suse-cra-toolkit` |
| `cmd/cra/main.go` | Binary entrypoint — creates root command, runs it |
| `internal/cli/root.go` | Root command definition with global flags (`--format`, `--output`, `--quiet`, `--verbose`) |
| `internal/cli/version.go` | `cra version` subcommand |
| `internal/cli/vex.go` | `cra vex` subcommand stub |
| `internal/cli/policykit.go` | `cra policykit` subcommand stub |
| `internal/cli/report.go` | `cra report` subcommand stub |
| `internal/cli/evidence.go` | `cra evidence` subcommand stub |
| `internal/cli/csaf.go` | `cra csaf` subcommand stub |
| `internal/cli/root_test.go` | Tests for root command, global flags, subcommand registration |
| `pkg/formats/formats.go` | Shared format types placeholder (SBOM, VEX, CSAF type aliases) |
| `pkg/vuln/vuln.go` | Shared vuln types placeholder |
| `pkg/vex/vex.go` | VEX package stub with exported interface |
| `pkg/policykit/policykit.go` | PolicyKit package stub with exported interface |
| `pkg/report/report.go` | Report package stub with exported interface |
| `pkg/evidence/evidence.go` | Evidence package stub with exported interface |
| `pkg/csaf/csaf.go` | CSAF package stub with exported interface |
| `.golangci.yml` | Linter config with all quality gates |
| `Taskfile.yml` | Build, test, lint, quality, fmt, vet, clean tasks |
| `.github/workflows/ci.yml` | CI pipeline: lint -> test -> build |
| `.gitignore` | Go binary, vendor, IDE files |
| `policies/.gitkeep` | Placeholder for Rego policies |
| `templates/.gitkeep` | Placeholder for report templates |
| `testdata/.gitkeep` | Placeholder for shared test fixtures |

---

### Task 1: Initialize Go Module and .gitignore

**Files:**
- Create: `go.mod`
- Modify: `.gitignore`

- [ ] **Step 1: Initialize Go module**

Run:
```bash
cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit
go mod init github.com/ravan/suse-cra-toolkit
```

Expected: `go.mod` created with `module github.com/ravan/suse-cra-toolkit` and `go 1.24`.

- [ ] **Step 2: Write .gitignore**

Write `.gitignore`:
```gitignore
# Build output
/bin/

# Go
*.exe
*.exe~
*.dll
*.so
*.dylib
*.test
*.out

# IDE
.idea/
.vscode/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db

# Coverage
coverage.out
coverage.html
```

- [ ] **Step 3: Commit**

```bash
git add go.mod .gitignore
git commit -m "chore: initialize Go module and gitignore"
```

---

### Task 2: Create Shared Package Stubs (pkg/formats, pkg/vuln)

**Files:**
- Create: `pkg/formats/formats.go`
- Create: `pkg/vuln/vuln.go`

These are the foundation packages that all domain packages will import. They need to exist first so the domain stubs can reference them.

- [ ] **Step 1: Write pkg/formats/formats.go**

```go
// Package formats provides shared types for SBOM, VEX, CSAF, and SARIF documents.
package formats
```

- [ ] **Step 2: Write pkg/vuln/vuln.go**

```go
// Package vuln provides shared types and clients for vulnerability data sources
// including NVD, OSV, CISA KEV, and EPSS.
package vuln
```

- [ ] **Step 3: Commit**

```bash
git add pkg/formats/formats.go pkg/vuln/vuln.go
git commit -m "chore: add shared package stubs (formats, vuln)"
```

---

### Task 3: Create Domain Package Stubs (pkg/vex, pkg/policykit, pkg/report, pkg/evidence, pkg/csaf)

**Files:**
- Create: `pkg/vex/vex.go`
- Create: `pkg/policykit/policykit.go`
- Create: `pkg/report/report.go`
- Create: `pkg/evidence/evidence.go`
- Create: `pkg/csaf/csaf.go`

Each stub declares the package and a placeholder Run function that returns "not implemented" — enough for the CLI subcommands to call.

- [ ] **Step 1: Write pkg/vex/vex.go**

```go
// Package vex implements VEX status determination using deterministic filters.
// It takes an SBOM and vulnerability scan results and auto-determines VEX status
// for each CVE using component presence, version range, platform, and patch checks.
package vex

import "errors"

// ErrNotImplemented is returned by stub functions that are not yet implemented.
var ErrNotImplemented = errors.New("vex: not implemented")

// Run executes VEX status determination. This is a stub for the project harness.
func Run() error {
	return ErrNotImplemented
}
```

- [ ] **Step 2: Write pkg/policykit/policykit.go**

```go
// Package policykit implements CRA Annex I policy evaluation using embedded OPA/Rego policies.
// It evaluates SBOM, VEX, and provenance artifacts against machine-checkable CRA rules.
package policykit

import "errors"

// ErrNotImplemented is returned by stub functions that are not yet implemented.
var ErrNotImplemented = errors.New("policykit: not implemented")

// Run executes CRA policy evaluation. This is a stub for the project harness.
func Run() error {
	return ErrNotImplemented
}
```

- [ ] **Step 3: Write pkg/report/report.go**

```go
// Package report generates CRA Article 14 vulnerability notification documents.
// It supports the three-stage pipeline: 24h early warning, 72h notification, 14-day final report.
package report

import "errors"

// ErrNotImplemented is returned by stub functions that are not yet implemented.
var ErrNotImplemented = errors.New("report: not implemented")

// Run executes report generation. This is a stub for the project harness.
func Run() error {
	return ErrNotImplemented
}
```

- [ ] **Step 4: Write pkg/evidence/evidence.go**

```go
// Package evidence bundles compliance outputs (SBOM, VEX, provenance, scans, policy reports)
// into a signed, versioned CRA evidence package for Annex VII technical documentation.
package evidence

import "errors"

// ErrNotImplemented is returned by stub functions that are not yet implemented.
var ErrNotImplemented = errors.New("evidence: not implemented")

// Run executes evidence bundling. This is a stub for the project harness.
func Run() error {
	return ErrNotImplemented
}
```

- [ ] **Step 5: Write pkg/csaf/csaf.go**

```go
// Package csaf converts vulnerability scanner output and VEX assessments
// into CSAF 2.0 advisories for downstream user notification per CRA Art. 14(8).
package csaf

import "errors"

// ErrNotImplemented is returned by stub functions that are not yet implemented.
var ErrNotImplemented = errors.New("csaf: not implemented")

// Run executes CSAF advisory generation. This is a stub for the project harness.
func Run() error {
	return ErrNotImplemented
}
```

- [ ] **Step 6: Commit**

```bash
git add pkg/vex/ pkg/policykit/ pkg/report/ pkg/evidence/ pkg/csaf/
git commit -m "chore: add domain package stubs (vex, policykit, report, evidence, csaf)"
```

---

### Task 4: Build the CLI — Root Command with Global Flags

**Files:**
- Create: `internal/cli/root.go`
- Create: `internal/cli/version.go`
- Create: `cmd/cra/main.go`

- [ ] **Step 1: Add urfave/cli v3 dependency**

Run:
```bash
cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit
go get github.com/urfave/cli/v3@latest
```

- [ ] **Step 2: Write internal/cli/root.go**

```go
package cli

import (
	"io"
	"os"

	urfave "github.com/urfave/cli/v3"
)

// New creates the root CRA CLI command with all global flags and subcommands registered.
func New(version string) *urfave.Command {
	return &urfave.Command{
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
				Name:    "verbose",
				Aliases: []string{"v"},
				Usage:   "enable debug logging",
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
}

// OutputWriter returns the appropriate writer based on the --output flag.
// If --output is set, it opens the file and returns it along with a close function.
// If --output is not set, it returns os.Stdout with a no-op close function.
func OutputWriter(cmd *urfave.Command) (io.Writer, func() error) {
	path := cmd.String("output")
	if path == "" {
		return os.Stdout, func() error { return nil }
	}

	f, err := os.Create(path)
	if err != nil {
		return os.Stdout, func() error { return nil }
	}

	return f, f.Close
}
```

- [ ] **Step 3: Write internal/cli/version.go**

```go
package cli

import (
	"context"
	"fmt"

	urfave "github.com/urfave/cli/v3"
)

func newVersionCmd(version string) *urfave.Command {
	return &urfave.Command{
		Name:  "version",
		Usage: "Print version information",
		Action: func(_ context.Context, cmd *urfave.Command) error {
			format := cmd.String("format")
			if format == "json" {
				fmt.Fprintf(cmd.Root().Writer, "{\"version\":%q}\n", version)
			} else {
				fmt.Fprintf(cmd.Root().Writer, "cra version %s\n", version)
			}
			return nil
		},
	}
}
```

- [ ] **Step 4: Write cmd/cra/main.go**

```go
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/ravan/suse-cra-toolkit/internal/cli"
)

var version = "dev"

func main() {
	cmd := cli.New(version)
	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
```

- [ ] **Step 5: Verify it compiles**

Run:
```bash
go build -o bin/cra ./cmd/cra
./bin/cra --help
```

Expected: Help output showing `cra` with subcommands and global flags.

- [ ] **Step 6: Commit**

```bash
git add cmd/cra/main.go internal/cli/root.go internal/cli/version.go go.mod go.sum
git commit -m "feat: add root CLI command with global flags and version subcommand"
```

---

### Task 5: Add Subcommand Stubs

**Files:**
- Create: `internal/cli/vex.go`
- Create: `internal/cli/policykit.go`
- Create: `internal/cli/report.go`
- Create: `internal/cli/evidence.go`
- Create: `internal/cli/csaf.go`

Each subcommand stub calls the corresponding `pkg/` package's `Run()` and handles the "not implemented" error with a user-friendly message.

- [ ] **Step 1: Write internal/cli/vex.go**

```go
package cli

import (
	"context"
	"fmt"

	urfave "github.com/urfave/cli/v3"

	"github.com/ravan/suse-cra-toolkit/pkg/vex"
)

func newVexCmd() *urfave.Command {
	return &urfave.Command{
		Name:  "vex",
		Usage: "Determine VEX status for vulnerabilities against an SBOM",
		Action: func(_ context.Context, cmd *urfave.Command) error {
			err := vex.Run()
			if err != nil {
				fmt.Fprintf(os.Stderr, "cra vex: %v\n", err)
				return err
			}
			return nil
		},
	}
}
```

Wait — the `os` import is needed. Let me correct: since this is a stub, let's keep it simpler and just return the error from the action. urfave/cli prints errors. Let me write all five correctly:

- [ ] **Step 1: Write internal/cli/vex.go**

```go
package cli

import (
	"context"

	urfave "github.com/urfave/cli/v3"

	"github.com/ravan/suse-cra-toolkit/pkg/vex"
)

func newVexCmd() *urfave.Command {
	return &urfave.Command{
		Name:  "vex",
		Usage: "Determine VEX status for vulnerabilities against an SBOM",
		Action: func(_ context.Context, _ *urfave.Command) error {
			return vex.Run()
		},
	}
}
```

- [ ] **Step 2: Write internal/cli/policykit.go**

```go
package cli

import (
	"context"

	urfave "github.com/urfave/cli/v3"

	"github.com/ravan/suse-cra-toolkit/pkg/policykit"
)

func newPolicykitCmd() *urfave.Command {
	return &urfave.Command{
		Name:  "policykit",
		Usage: "Evaluate CRA Annex I compliance policies against product artifacts",
		Action: func(_ context.Context, _ *urfave.Command) error {
			return policykit.Run()
		},
	}
}
```

- [ ] **Step 3: Write internal/cli/report.go**

```go
package cli

import (
	"context"

	urfave "github.com/urfave/cli/v3"

	"github.com/ravan/suse-cra-toolkit/pkg/report"
)

func newReportCmd() *urfave.Command {
	return &urfave.Command{
		Name:  "report",
		Usage: "Generate CRA Article 14 vulnerability notification documents",
		Action: func(_ context.Context, _ *urfave.Command) error {
			return report.Run()
		},
	}
}
```

- [ ] **Step 4: Write internal/cli/evidence.go**

```go
package cli

import (
	"context"

	urfave "github.com/urfave/cli/v3"

	"github.com/ravan/suse-cra-toolkit/pkg/evidence"
)

func newEvidenceCmd() *urfave.Command {
	return &urfave.Command{
		Name:  "evidence",
		Usage: "Bundle compliance outputs into a signed CRA evidence package",
		Action: func(_ context.Context, _ *urfave.Command) error {
			return evidence.Run()
		},
	}
}
```

- [ ] **Step 5: Write internal/cli/csaf.go**

```go
package cli

import (
	"context"

	urfave "github.com/urfave/cli/v3"

	"github.com/ravan/suse-cra-toolkit/pkg/csaf"
)

func newCsafCmd() *urfave.Command {
	return &urfave.Command{
		Name:  "csaf",
		Usage: "Convert scanner output and VEX into CSAF 2.0 advisories",
		Action: func(_ context.Context, _ *urfave.Command) error {
			return csaf.Run()
		},
	}
}
```

- [ ] **Step 6: Verify it compiles and all subcommands appear**

Run:
```bash
go build -o bin/cra ./cmd/cra
./bin/cra --help
```

Expected: Help output listing all 6 subcommands: `version`, `vex`, `policykit`, `report`, `evidence`, `csaf`.

- [ ] **Step 7: Verify a subcommand returns not-implemented**

Run:
```bash
./bin/cra vex
```

Expected: Non-zero exit code with error containing "not implemented".

- [ ] **Step 8: Commit**

```bash
git add internal/cli/vex.go internal/cli/policykit.go internal/cli/report.go internal/cli/evidence.go internal/cli/csaf.go
git commit -m "feat: add CLI subcommand stubs for all five CRA tools"
```

---

### Task 6: Write CLI Tests

**Files:**
- Create: `internal/cli/root_test.go`

Tests verify: root command creates successfully, all subcommands are registered, version command outputs correctly in both formats, subcommand stubs return not-implemented errors.

- [ ] **Step 1: Write the test file internal/cli/root_test.go**

```go
package cli_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/ravan/suse-cra-toolkit/internal/cli"
)

func TestNew_ReturnsCommand(t *testing.T) {
	cmd := cli.New("1.0.0-test")
	if cmd == nil {
		t.Fatal("expected non-nil command")
	}
	if cmd.Name != "cra" {
		t.Errorf("expected command name 'cra', got %q", cmd.Name)
	}
}

func TestNew_RegistersAllSubcommands(t *testing.T) {
	cmd := cli.New("1.0.0-test")

	expected := []string{"version", "vex", "policykit", "report", "evidence", "csaf"}
	registered := make(map[string]bool)
	for _, sub := range cmd.Commands {
		registered[sub.Name] = true
	}

	for _, name := range expected {
		if !registered[name] {
			t.Errorf("expected subcommand %q to be registered", name)
		}
	}
}

func TestVersionCmd_JSON(t *testing.T) {
	cmd := cli.New("1.2.3")
	var buf bytes.Buffer
	cmd.Writer = &buf

	err := cmd.Run(context.Background(), []string{"cra", "version"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, `"version"`) || !strings.Contains(out, "1.2.3") {
		t.Errorf("expected JSON version output containing 1.2.3, got %q", out)
	}
}

func TestVersionCmd_Text(t *testing.T) {
	cmd := cli.New("1.2.3")
	var buf bytes.Buffer
	cmd.Writer = &buf

	err := cmd.Run(context.Background(), []string{"cra", "--format", "text", "version"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "cra version 1.2.3") {
		t.Errorf("expected text version output, got %q", out)
	}
}

func TestSubcommandStubs_ReturnNotImplemented(t *testing.T) {
	subcmds := []string{"vex", "policykit", "report", "evidence", "csaf"}
	for _, name := range subcmds {
		t.Run(name, func(t *testing.T) {
			cmd := cli.New("test")
			err := cmd.Run(context.Background(), []string{"cra", name})
			if err == nil {
				t.Errorf("expected error from stub subcommand %q, got nil", name)
			}
			if err != nil && !strings.Contains(err.Error(), "not implemented") {
				t.Errorf("expected 'not implemented' error, got %q", err.Error())
			}
		})
	}
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run:
```bash
go test ./internal/cli/ -v
```

Expected: All tests PASS.

- [ ] **Step 3: Commit**

```bash
git add internal/cli/root_test.go
git commit -m "test: add CLI root command and subcommand registration tests"
```

---

### Task 7: Add Placeholder Directories

**Files:**
- Create: `policies/.gitkeep`
- Create: `templates/.gitkeep`
- Create: `testdata/.gitkeep`

- [ ] **Step 1: Create placeholder files**

Run:
```bash
cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit
mkdir -p policies templates testdata
touch policies/.gitkeep templates/.gitkeep testdata/.gitkeep
```

- [ ] **Step 2: Commit**

```bash
git add policies/.gitkeep templates/.gitkeep testdata/.gitkeep
git commit -m "chore: add placeholder directories for policies, templates, testdata"
```

---

### Task 8: Configure golangci-lint

**Files:**
- Create: `.golangci.yml`

- [ ] **Step 1: Write .golangci.yml**

```yaml
run:
  timeout: 5m
  go: "1.24"

linters:
  enable:
    - errcheck
    - gocyclo
    - gocognit
    - gocritic
    - gosec
    - ineffassign
    - unconvert
    - misspell
    - prealloc
    - dupl
    - maintidx
    - gofumpt

linters-settings:
  gocyclo:
    min-complexity: 10
  gocognit:
    min-complexity: 13
  dupl:
    threshold: 100
  maintidx:
    under: 20
  gofumpt:
    extra-rules: true
  gocritic:
    enabled-tags:
      - diagnostic
      - style
      - performance
      - opinionated

issues:
  exclude-use-default: false
  max-issues-per-linter: 0
  max-same-issues: 0
```

Note: `gocyclo` uses `min-complexity` (reports functions AT or ABOVE this value), so setting 10 means functions with complexity >= 10 are flagged — effectively enforcing max 9. Same logic for `gocognit` at 13 (max 12) and `maintidx` with `under: 20` (flags functions below 20).

- [ ] **Step 2: Install golangci-lint if not present and run it**

Run:
```bash
which golangci-lint || go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
golangci-lint run ./...
```

Expected: No lint issues (the codebase is minimal stubs).

- [ ] **Step 3: Commit**

```bash
git add .golangci.yml
git commit -m "chore: add golangci-lint config with quality gates"
```

---

### Task 9: Create Taskfile

**Files:**
- Create: `Taskfile.yml`

- [ ] **Step 1: Write Taskfile.yml**

```yaml
version: "3"

vars:
  BINARY: cra
  BUILD_DIR: bin
  MODULE: github.com/ravan/suse-cra-toolkit
  VERSION:
    sh: git describe --tags --always --dirty 2>/dev/null || echo "dev"
  COMMIT:
    sh: git rev-parse --short HEAD 2>/dev/null || echo "unknown"
  BUILD_DATE:
    sh: date -u '+%Y-%m-%dT%H:%M:%SZ'
  LDFLAGS: >-
    -s -w
    -X main.version={{.VERSION}}
    -X main.commit={{.COMMIT}}
    -X main.date={{.BUILD_DATE}}

tasks:
  default:
    desc: Show available tasks
    cmds:
      - task --list

  build:
    desc: Build the cra binary
    cmds:
      - go build -ldflags "{{.LDFLAGS}}" -o {{.BUILD_DIR}}/{{.BINARY}} ./cmd/cra
    sources:
      - "**/*.go"
      - go.mod
      - go.sum
    generates:
      - "{{.BUILD_DIR}}/{{.BINARY}}"

  test:
    desc: Run all unit tests with race detector
    cmds:
      - go test -race -count=1 ./...

  fmt:
    desc: Format code with gofumpt
    cmds:
      - gofumpt -w .

  fmt:check:
    desc: Check code formatting
    cmds:
      - test -z "$(gofumpt -l .)" || (echo "Files need formatting (run 'task fmt'):" && gofumpt -l . && exit 1)

  vet:
    desc: Run go vet
    cmds:
      - go vet ./...

  lint:
    desc: Run golangci-lint
    cmds:
      - golangci-lint run ./...

  quality:
    desc: Run all quality gates
    cmds:
      - task: fmt:check
      - task: vet
      - task: lint
      - task: test

  clean:
    desc: Remove build artifacts
    cmds:
      - rm -rf {{.BUILD_DIR}}
```

- [ ] **Step 2: Update cmd/cra/main.go to accept ldflags for commit and date**

Update `cmd/cra/main.go` to include `commit` and `date` variables:

```go
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/ravan/suse-cra-toolkit/internal/cli"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	cmd := cli.New(version)
	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
```

- [ ] **Step 3: Install task if not present, then verify**

Run:
```bash
which task || go install github.com/go-task/task/v3/cmd/task@latest
task build
./bin/cra --help
```

Expected: Binary builds successfully and shows help.

- [ ] **Step 4: Run task quality**

Run:
```bash
task quality
```

Expected: All quality gates pass (fmt, vet, lint, test).

- [ ] **Step 5: Commit**

```bash
git add Taskfile.yml cmd/cra/main.go
git commit -m "chore: add Taskfile with build, test, lint, and quality targets"
```

---

### Task 10: Add GitHub Actions CI

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Write .github/workflows/ci.yml**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  quality:
    name: Quality Gates
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: "1.24"

      - name: Install Task
        uses: arduino/setup-task@v2
        with:
          version: 3.x

      - name: Install gofumpt
        run: go install mvdan.cc/gofumpt@latest

      - name: Install golangci-lint
        uses: golangci/golangci-lint-action@v6
        with:
          version: latest
          args: --timeout=5m

      - name: Check formatting
        run: task fmt:check

      - name: Vet
        run: task vet

      - name: Test
        run: task test

      - name: Build
        run: task build
```

- [ ] **Step 2: Commit**

```bash
mkdir -p .github/workflows
git add .github/workflows/ci.yml
git commit -m "ci: add GitHub Actions workflow with quality gates"
```

---

### Task 11: Commit Strategy Doc and Design Spec

**Files:**
- Existing: `docs/SUSE-CRA-Compliance-Toolkit-Strategy.md`
- Existing: `docs/superpowers/specs/2026-04-03-phase1-repo-structure-design.md`

- [ ] **Step 1: Commit docs**

```bash
git add docs/SUSE-CRA-Compliance-Toolkit-Strategy.md docs/superpowers/specs/2026-04-03-phase1-repo-structure-design.md docs/superpowers/plans/2026-04-03-phase1-project-harness.md
git commit -m "docs: add strategy document, design spec, and implementation plan"
```

Note: Do NOT commit `docs/eu-cyber-resilience-act.pdf` (1.8MB binary — add it to `.gitignore` or use Git LFS if needed later). Add it to `.gitignore`:

- [ ] **Step 2: Add PDF to .gitignore**

Append to `.gitignore`:
```
# Large binary files
docs/*.pdf
```

- [ ] **Step 3: Commit .gitignore update**

```bash
git add .gitignore
git commit -m "chore: exclude PDF files from git tracking"
```

---

### Task 12: Final Verification

- [ ] **Step 1: Clean build from scratch**

Run:
```bash
task clean
task build
```

Expected: Binary builds to `bin/cra`.

- [ ] **Step 2: Run full quality suite**

Run:
```bash
task quality
```

Expected: All pass — fmt, vet, lint, test.

- [ ] **Step 3: Verify all subcommands**

Run:
```bash
./bin/cra --help
./bin/cra version
./bin/cra vex 2>&1; echo "exit: $?"
```

Expected:
- Help shows all subcommands
- `version` prints version info
- `vex` exits non-zero with "not implemented"

- [ ] **Step 4: Verify project structure**

Run:
```bash
find . -not -path './.git/*' -not -path './bin/*' | sort
```

Expected: All files from the spec's repository structure are present.
