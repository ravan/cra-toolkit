# Reachability Evidence Propagation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Propagate structured call-chain evidence from reachability analyzers through all five downstream consumers (PolicyKit, CSAF, Report, Evidence bundle, OpenVEX) so every output carries machine-usable reachability data.

**Architecture:** Promote `CallPath`/`CallNode` types from `pkg/vex/reachability/` to `pkg/formats/`, add new fields to `formats.VEXResult` (AnalysisMethod, CallPaths, Symbols, MaxCallDepth, EntryFiles), then update each consumer to read and use the structured data. The dependency graph remains acyclic: `formats` has no internal deps, everything else imports `formats`.

**Tech Stack:** Go, OPA/Rego, tree-sitter, cosign (signing), gemini CLI (LLM judge tests)

**Spec:** `docs/superpowers/specs/2026-04-05-reachability-evidence-propagation-design.md`

---

## File Map

| Action | File | Responsibility |
|--------|------|---------------|
| Create | `pkg/formats/callpath.go` | Shared `CallNode`, `CallPath` types with `String()`, `Depth()`, `EntryPoint()` |
| Create | `pkg/formats/callpath_test.go` | Unit tests for CallPath methods |
| Modify | `pkg/formats/vexstatement.go:45-53` | Add 5 new fields to `VEXResult` |
| Modify | `pkg/vex/reachability/result.go` | Replace local types with `formats.CallPath`/`formats.CallNode` aliases |
| Modify | `pkg/vex/reachability_filter.go:31-80` | Populate new VEXResult fields, add `analyzerMethod()` helper |
| Modify | `pkg/vex/reachability_filter_test.go` | Assert new fields in all test cases |
| Modify | `pkg/policykit/input.go:170-183` | Expand `buildVEX` to expose all fields, add `buildCallPathsInput()` |
| Modify | `pkg/policykit/input_test.go:40-47` | Assert new VEX fields in OPA input |
| Create | `policies/cra_reach_confidence.rego` | CRA-REACH-1: Reachability not_affected requires high confidence |
| Create | `policies/cra_reach_call_paths.rego` | CRA-REACH-2: Affected reachability must have call paths |
| Create | `policies/cra_reach_method.rego` | CRA-REACH-3: Pattern-match alone cannot justify not_affected |
| Modify | `pkg/csaf/notes.go:27-36` | Add `buildReachabilityNotes()`, call from `buildVulnNotes` |
| Modify | `pkg/csaf/notes_test.go` | Test reachability notes generation |
| Modify | `pkg/report/notification.go:51-53` | Replace plain evidence with `ReachabilityDetail()` output |
| Create | `pkg/report/reachability.go` | `ReachabilityDetail(v formats.VEXResult) string` helper |
| Create | `pkg/report/reachability_test.go` | Unit tests for ReachabilityDetail |
| Modify | `pkg/report/render.go:44-84` | Add reachability evidence block to vulnerability section |
| Modify | `pkg/formats/openvex/openvex.go:87-118` | Structured JSON impact statement for reachability results |
| Modify | `pkg/formats/openvex/openvex_test.go` | Test structured impact statement round-trip |
| Modify | `pkg/evidence/types.go:141-145` | Add `ReachabilityBased` to `VulnHandlingStats`, add `VEXEvidence` types |
| Modify | `pkg/evidence/collect.go:203-233` | Change `parseVEXData` to return `[]formats.VEXResult`, add `buildVEXEvidence()` |
| Modify | `pkg/evidence/assemble.go` | Add `vex_evidence.json` artifact input |

---

### Task 1: Promote CallPath/CallNode to pkg/formats

**Files:**
- Create: `pkg/formats/callpath.go`
- Create: `pkg/formats/callpath_test.go`

- [ ] **Step 1: Write failing tests for CallPath types**

Create `pkg/formats/callpath_test.go`:

```go
package formats_test

import (
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
)

func TestCallPath_String(t *testing.T) {
	tests := []struct {
		name  string
		path  formats.CallPath
		want  string
	}{
		{
			name: "two nodes with file and line",
			path: formats.CallPath{
				Nodes: []formats.CallNode{
					{Symbol: "main.handler", File: "cmd/main.go", Line: 42},
					{Symbol: "vuln.Parse", File: "vendor/vuln/parse.go", Line: 10},
				},
			},
			want: "main.handler (cmd/main.go:42) -> vuln.Parse (vendor/vuln/parse.go:10)",
		},
		{
			name: "node without file info",
			path: formats.CallPath{
				Nodes: []formats.CallNode{
					{Symbol: "main.handler", File: "cmd/main.go", Line: 42},
					{Symbol: "external.Func"},
				},
			},
			want: "main.handler (cmd/main.go:42) -> external.Func",
		},
		{
			name:  "empty path",
			path:  formats.CallPath{},
			want:  "",
		},
		{
			name: "single node",
			path: formats.CallPath{
				Nodes: []formats.CallNode{
					{Symbol: "main.handler", File: "cmd/main.go", Line: 1},
				},
			},
			want: "main.handler (cmd/main.go:1)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.path.String()
			if got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCallPath_Depth(t *testing.T) {
	tests := []struct {
		name string
		path formats.CallPath
		want int
	}{
		{"empty", formats.CallPath{}, 0},
		{"two nodes", formats.CallPath{Nodes: []formats.CallNode{{Symbol: "a"}, {Symbol: "b"}}}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.path.Depth(); got != tt.want {
				t.Errorf("Depth() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestCallPath_EntryPoint(t *testing.T) {
	path := formats.CallPath{
		Nodes: []formats.CallNode{
			{Symbol: "main.handler", File: "cmd/main.go", Line: 42},
			{Symbol: "vuln.Parse", File: "lib/parse.go", Line: 10},
		},
	}
	ep := path.EntryPoint()
	if ep.Symbol != "main.handler" {
		t.Errorf("EntryPoint().Symbol = %q, want main.handler", ep.Symbol)
	}
	if ep.File != "cmd/main.go" {
		t.Errorf("EntryPoint().File = %q, want cmd/main.go", ep.File)
	}
}

func TestCallPath_EntryPoint_EmptyPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected EntryPoint() on empty path to panic")
		}
	}()
	p := formats.CallPath{}
	p.EntryPoint()
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/formats/ -run TestCallPath -v`
Expected: FAIL — `CallPath` and `CallNode` types not defined in `formats` package

- [ ] **Step 3: Implement CallPath types**

Create `pkg/formats/callpath.go`:

```go
package formats

import (
	"fmt"
	"strings"
)

// CallNode represents a single node in a call path.
type CallNode struct {
	Symbol string // qualified name (e.g., "com.example.App.process")
	File   string // repo-relative file path
	Line   int    // 1-based; 0 if unknown
}

// CallPath represents a call chain from an entry point to a vulnerable symbol.
type CallPath struct {
	Nodes []CallNode
}

// String returns a human-readable representation of the call path.
func (p CallPath) String() string {
	parts := make([]string, len(p.Nodes))
	for i, n := range p.Nodes {
		if n.File != "" && n.Line > 0 {
			parts[i] = fmt.Sprintf("%s (%s:%d)", n.Symbol, n.File, n.Line)
		} else {
			parts[i] = n.Symbol
		}
	}
	return strings.Join(parts, " -> ")
}

// Depth returns the number of nodes in the call path.
func (p CallPath) Depth() int {
	return len(p.Nodes)
}

// EntryPoint returns the first node in the call path.
// Panics if the path is empty.
func (p CallPath) EntryPoint() CallNode {
	return p.Nodes[0]
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/formats/ -run TestCallPath -v`
Expected: PASS — all 4 test functions pass

- [ ] **Step 5: Commit**

```bash
git add pkg/formats/callpath.go pkg/formats/callpath_test.go
git commit -m "feat(formats): add CallPath and CallNode types"
```

---

### Task 2: Add new fields to VEXResult

**Files:**
- Modify: `pkg/formats/vexstatement.go:44-53`

- [ ] **Step 1: Write failing test for new VEXResult fields**

Add to `pkg/formats/callpath_test.go` (append to the file):

```go
func TestVEXResult_ReachabilityFields(t *testing.T) {
	r := formats.VEXResult{
		CVE:           "CVE-2024-1234",
		ComponentPURL: "pkg:maven/com.example/lib@1.0",
		Status:        formats.StatusAffected,
		Confidence:    formats.ConfidenceHigh,
		ResolvedBy:    "reachability_analysis",
		Evidence:      "symbol is called",
		AnalysisMethod: "tree_sitter",
		CallPaths: []formats.CallPath{
			{
				Nodes: []formats.CallNode{
					{Symbol: "App.main", File: "src/App.java", Line: 10},
					{Symbol: "Lib.vuln", File: "lib/Lib.java", Line: 20},
				},
			},
		},
		Symbols:      []string{"Lib.vuln"},
		MaxCallDepth: 2,
		EntryFiles:   []string{"src/App.java"},
	}

	if r.AnalysisMethod != "tree_sitter" {
		t.Errorf("AnalysisMethod = %q, want tree_sitter", r.AnalysisMethod)
	}
	if len(r.CallPaths) != 1 {
		t.Fatalf("CallPaths count = %d, want 1", len(r.CallPaths))
	}
	if r.CallPaths[0].Depth() != 2 {
		t.Errorf("CallPaths[0].Depth() = %d, want 2", r.CallPaths[0].Depth())
	}
	if len(r.Symbols) != 1 || r.Symbols[0] != "Lib.vuln" {
		t.Errorf("Symbols = %v, want [Lib.vuln]", r.Symbols)
	}
	if r.MaxCallDepth != 2 {
		t.Errorf("MaxCallDepth = %d, want 2", r.MaxCallDepth)
	}
	if len(r.EntryFiles) != 1 || r.EntryFiles[0] != "src/App.java" {
		t.Errorf("EntryFiles = %v, want [src/App.java]", r.EntryFiles)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/formats/ -run TestVEXResult_ReachabilityFields -v`
Expected: FAIL — `AnalysisMethod`, `CallPaths`, `Symbols`, `MaxCallDepth`, `EntryFiles` fields don't exist

- [ ] **Step 3: Add fields to VEXResult**

In `pkg/formats/vexstatement.go`, replace lines 44-53:

```go
// VEXResult represents the result of VEX determination for a single finding.
type VEXResult struct {
	CVE           string        // CVE identifier
	ComponentPURL string        // PURL of the component in the SBOM
	Status        VEXStatus     // determined VEX status
	Justification Justification // justification code
	Confidence    Confidence    // confidence level of the determination
	ResolvedBy    string        // name of the filter that resolved this finding
	Evidence      string        // human-readable evidence chain

	// Reachability evidence — populated when ResolvedBy == "reachability_analysis"
	AnalysisMethod string     // "tree_sitter", "govulncheck", "pattern_match"; empty for non-reachability
	CallPaths      []CallPath // structured call chains; nil if not from reachability or pattern_match
	Symbols        []string   // vulnerable symbols confirmed reachable
	MaxCallDepth   int        // max(path.Depth()) across all paths; 0 if none
	EntryFiles     []string   // deduplicated entry-point files (Nodes[0].File)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/formats/ -run TestVEXResult_ReachabilityFields -v`
Expected: PASS

- [ ] **Step 5: Run full package tests**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/formats/... -v`
Expected: PASS — no regressions

- [ ] **Step 6: Commit**

```bash
git add pkg/formats/vexstatement.go pkg/formats/callpath_test.go
git commit -m "feat(formats): add reachability evidence fields to VEXResult"
```

---

### Task 3: Migrate reachability package to use formats types

**Files:**
- Modify: `pkg/vex/reachability/result.go`

- [ ] **Step 1: Run existing reachability tests before modification**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/vex/... -v -count=1 2>&1 | tail -30`
Expected: PASS — establishes baseline

- [ ] **Step 2: Replace local types with formats aliases**

Replace the entire content of `pkg/vex/reachability/result.go` with:

```go
package reachability

import "github.com/ravan/suse-cra-toolkit/pkg/formats"

// Result holds the outcome of a reachability analysis.
type Result struct {
	Reachable  bool               // whether the vulnerable code is reachable
	Confidence formats.Confidence // confidence level of the determination
	Evidence   string             // human-readable evidence description
	Symbols    []string           // symbols found to be reachable (if any)
	Paths      []formats.CallPath // call paths from entry points to vulnerable symbols
}

// CallPath is an alias for formats.CallPath for backward compatibility.
type CallPath = formats.CallPath

// CallNode is an alias for formats.CallNode for backward compatibility.
type CallNode = formats.CallNode
```

- [ ] **Step 3: Run all vex tests to verify no regressions**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/vex/... -v -count=1 2>&1 | tail -30`
Expected: PASS — type aliases are fully transparent; all existing tests pass unchanged

- [ ] **Step 4: Commit**

```bash
git add pkg/vex/reachability/result.go
git commit -m "refactor(reachability): alias CallPath/CallNode to formats types"
```

---

### Task 4: Populate new VEXResult fields in reachability filter

**Files:**
- Modify: `pkg/vex/reachability_filter.go`
- Modify: `pkg/vex/reachability_filter_test.go`

- [ ] **Step 1: Write failing tests for new fields**

Add to `pkg/vex/reachability_filter_test.go` (new test function at end of file):

```go
func TestReachabilityFilter_StructuredFields(t *testing.T) {
	t.Run("tree-sitter analyzer populates all fields", func(t *testing.T) {
		analyzer := &stubAnalyzer{
			lang: "python",
			result: reachability.Result{
				Reachable:  true,
				Confidence: formats.ConfidenceHigh,
				Evidence:   "vulnerable symbol is called",
				Symbols:    []string{"yaml.load", "yaml.unsafe_load"},
				Paths: []reachability.CallPath{
					{
						Nodes: []reachability.CallNode{
							{Symbol: "app.main", File: "src/app.py", Line: 10},
							{Symbol: "app.process", File: "src/app.py", Line: 25},
							{Symbol: "yaml.load", File: "vendor/yaml/__init__.py", Line: 100},
						},
					},
					{
						Nodes: []reachability.CallNode{
							{Symbol: "cli.run", File: "src/cli.py", Line: 5},
							{Symbol: "yaml.unsafe_load", File: "vendor/yaml/__init__.py", Line: 200},
						},
					},
				},
			},
		}

		f := vex.NewReachabilityFilter("/tmp/source", map[string]reachability.Analyzer{
			"python": analyzer,
		})

		finding := formats.Finding{
			CVE:          "CVE-2020-1747",
			AffectedPURL: "pkg:pypi/pyyaml@5.3",
			AffectedName: "PyYAML",
			Language:     "python",
		}

		result, resolved := f.Evaluate(&finding, nil)
		if !resolved {
			t.Fatal("expected filter to resolve")
		}

		if len(result.CallPaths) != 2 {
			t.Fatalf("CallPaths count = %d, want 2", len(result.CallPaths))
		}
		if result.CallPaths[0].Depth() != 3 {
			t.Errorf("CallPaths[0].Depth() = %d, want 3", result.CallPaths[0].Depth())
		}
		if len(result.Symbols) != 2 {
			t.Errorf("Symbols count = %d, want 2", len(result.Symbols))
		}
		if result.MaxCallDepth != 3 {
			t.Errorf("MaxCallDepth = %d, want 3", result.MaxCallDepth)
		}
		if len(result.EntryFiles) != 2 {
			t.Errorf("EntryFiles count = %d, want 2", len(result.EntryFiles))
		}
		// Entry files should be deduplicated and contain both entry points.
		entrySet := map[string]bool{}
		for _, ef := range result.EntryFiles {
			entrySet[ef] = true
		}
		if !entrySet["src/app.py"] || !entrySet["src/cli.py"] {
			t.Errorf("EntryFiles = %v, want src/app.py and src/cli.py", result.EntryFiles)
		}
		if result.AnalysisMethod != "tree_sitter" {
			t.Errorf("AnalysisMethod = %q, want tree_sitter", result.AnalysisMethod)
		}
	})

	t.Run("generic analyzer has pattern_match method and nil paths", func(t *testing.T) {
		analyzer := &stubAnalyzer{
			lang: "generic",
			result: reachability.Result{
				Reachable:  true,
				Confidence: formats.ConfidenceMedium,
				Evidence:   "import found via grep",
				Symbols:    []string{"yaml.load"},
				Paths:      nil,
			},
		}

		f := vex.NewReachabilityFilter("/tmp/source", map[string]reachability.Analyzer{
			"generic": analyzer,
		})

		finding := formats.Finding{
			CVE:          "CVE-2020-1747",
			AffectedPURL: "pkg:pypi/pyyaml@5.3",
			Language:     "unknown-lang",
		}

		result, resolved := f.Evaluate(&finding, nil)
		if !resolved {
			t.Fatal("expected filter to resolve")
		}

		if result.AnalysisMethod != "pattern_match" {
			t.Errorf("AnalysisMethod = %q, want pattern_match", result.AnalysisMethod)
		}
		if result.CallPaths != nil {
			t.Errorf("CallPaths = %v, want nil for generic analyzer", result.CallPaths)
		}
		if result.MaxCallDepth != 0 {
			t.Errorf("MaxCallDepth = %d, want 0", result.MaxCallDepth)
		}
		if len(result.Symbols) != 1 || result.Symbols[0] != "yaml.load" {
			t.Errorf("Symbols = %v, want [yaml.load]", result.Symbols)
		}
	})

	t.Run("not-reachable still gets structured fields", func(t *testing.T) {
		analyzer := &stubAnalyzer{
			lang: "go",
			result: reachability.Result{
				Reachable:  false,
				Confidence: formats.ConfidenceHigh,
				Evidence:   "vulnerable function not called",
				Symbols:    []string{"text.Parse"},
			},
		}

		f := vex.NewReachabilityFilter("/tmp/source", map[string]reachability.Analyzer{
			"go": analyzer,
		})

		finding := formats.Finding{
			CVE:          "CVE-2022-32149",
			AffectedPURL: "pkg:golang/golang.org/x/text@v0.3.7",
			Language:     "go",
		}

		result, resolved := f.Evaluate(&finding, nil)
		if !resolved {
			t.Fatal("expected filter to resolve")
		}

		if result.AnalysisMethod != "govulncheck" {
			t.Errorf("AnalysisMethod = %q, want govulncheck", result.AnalysisMethod)
		}
		if len(result.Symbols) != 1 || result.Symbols[0] != "text.Parse" {
			t.Errorf("Symbols = %v, want [text.Parse]", result.Symbols)
		}
		if result.CallPaths != nil {
			t.Errorf("CallPaths should be nil for not-reachable, got %v", result.CallPaths)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/vex/ -run TestReachabilityFilter_StructuredFields -v`
Expected: FAIL — `AnalysisMethod`, `CallPaths`, `Symbols`, `MaxCallDepth`, `EntryFiles` not populated

- [ ] **Step 3: Implement filter changes**

Replace `pkg/vex/reachability_filter.go` entirely:

```go
package vex

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability"
)

// reachabilityFilter bridges reachability analyzers into the Filter interface.
type reachabilityFilter struct {
	sourceDir string
	analyzers map[string]reachability.Analyzer
}

// NewReachabilityFilter returns a Filter that uses reachability analyzers to
// determine whether vulnerable code is actually called. If no analyzer matches
// the finding's language, the "generic" analyzer is used as a fallback.
func NewReachabilityFilter(sourceDir string, analyzers map[string]reachability.Analyzer) Filter {
	return &reachabilityFilter{
		sourceDir: sourceDir,
		analyzers: analyzers,
	}
}

func (f *reachabilityFilter) Name() string { return "reachability" }

func (f *reachabilityFilter) Evaluate(finding *formats.Finding, components []formats.Component) (Result, bool) {
	analyzer, ok := f.analyzers[finding.Language]
	if !ok {
		// Fall back to "generic" analyzer.
		analyzer, ok = f.analyzers["generic"]
		if !ok {
			// No analyzer available; cannot resolve.
			return Result{}, false
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	result, err := analyzer.Analyze(ctx, f.sourceDir, finding)
	if err != nil {
		// Analysis failed; cannot resolve.
		return Result{}, false
	}

	method := analyzerMethod(analyzer)

	if result.Reachable {
		evidence := result.Evidence
		// Append structured path info if available.
		if len(result.Paths) > 0 {
			var pathStrs []string
			for _, p := range result.Paths {
				pathStrs = append(pathStrs, p.String())
			}
			evidence = fmt.Sprintf("%s\nCall paths:\n  %s", evidence, strings.Join(pathStrs, "\n  "))
		}
		return Result{
			CVE:            finding.CVE,
			ComponentPURL:  finding.AffectedPURL,
			Status:         formats.StatusAffected,
			Confidence:     result.Confidence,
			ResolvedBy:     "reachability_analysis",
			Evidence:       evidence,
			AnalysisMethod: method,
			CallPaths:      result.Paths,
			Symbols:        result.Symbols,
			MaxCallDepth:   maxDepth(result.Paths),
			EntryFiles:     entryFiles(result.Paths),
		}, true
	}

	return Result{
		CVE:            finding.CVE,
		ComponentPURL:  finding.AffectedPURL,
		Status:         formats.StatusNotAffected,
		Justification:  formats.JustificationVulnerableCodeNotInExecutePath,
		Confidence:     result.Confidence,
		ResolvedBy:     "reachability_analysis",
		Evidence:       fmt.Sprintf("Reachability analysis: %s", result.Evidence),
		AnalysisMethod: method,
		CallPaths:      result.Paths,
		Symbols:        result.Symbols,
		MaxCallDepth:   maxDepth(result.Paths),
		EntryFiles:     entryFiles(result.Paths),
	}, true
}

// analyzerMethod returns the analysis method string based on the analyzer's language.
func analyzerMethod(a reachability.Analyzer) string {
	switch a.Language() {
	case "go":
		return "govulncheck"
	case "generic":
		return "pattern_match"
	default:
		return "tree_sitter"
	}
}

// maxDepth returns the maximum depth across all call paths.
func maxDepth(paths []formats.CallPath) int {
	max := 0
	for _, p := range paths {
		if d := p.Depth(); d > max {
			max = d
		}
	}
	return max
}

// entryFiles returns deduplicated entry-point files from call paths.
func entryFiles(paths []formats.CallPath) []string {
	if len(paths) == 0 {
		return nil
	}
	seen := make(map[string]bool)
	var files []string
	for _, p := range paths {
		if len(p.Nodes) > 0 {
			f := p.Nodes[0].File
			if f != "" && !seen[f] {
				seen[f] = true
				files = append(files, f)
			}
		}
	}
	return files
}
```

- [ ] **Step 4: Run all reachability filter tests**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/vex/ -run TestReachabilityFilter -v`
Expected: PASS — all existing and new tests pass

- [ ] **Step 5: Commit**

```bash
git add pkg/vex/reachability_filter.go pkg/vex/reachability_filter_test.go
git commit -m "feat(vex): populate structured reachability fields in filter"
```

---

### Task 5: Expand PolicyKit OPA input with all VEX fields

**Files:**
- Modify: `pkg/policykit/input.go:170-183`
- Modify: `pkg/policykit/input_test.go`

- [ ] **Step 1: Write failing test for expanded VEX input**

Add a new test function at the end of `pkg/policykit/input_test.go`:

```go
func TestBuildInput_VEXReachabilityFields(t *testing.T) {
	arts := &ParsedArtifacts{
		Components: []formats.Component{
			{Name: "PyYAML", Version: "5.3", PURL: "pkg:pypi/pyyaml@5.3", Type: "python"},
		},
		Findings: []formats.Finding{
			{
				CVE:          "CVE-2020-1747",
				AffectedPURL: "pkg:pypi/pyyaml@5.3",
				AffectedName: "PyYAML",
				Severity:     "critical",
				CVSS:         9.8,
			},
		},
		VEXResults: []formats.VEXResult{
			{
				CVE:            "CVE-2020-1747",
				ComponentPURL:  "pkg:pypi/pyyaml@5.3",
				Status:         formats.StatusAffected,
				Confidence:     formats.ConfidenceHigh,
				ResolvedBy:     "reachability_analysis",
				Evidence:       "yaml.load is called",
				AnalysisMethod: "tree_sitter",
				Symbols:        []string{"yaml.load"},
				MaxCallDepth:   3,
				EntryFiles:     []string{"src/app.py"},
				CallPaths: []formats.CallPath{
					{
						Nodes: []formats.CallNode{
							{Symbol: "app.main", File: "src/app.py", Line: 10},
							{Symbol: "app.process", File: "src/app.py", Line: 25},
							{Symbol: "yaml.load", File: "yaml/__init__.py", Line: 100},
						},
					},
				},
			},
		},
	}

	input := BuildInput(arts)

	vexSection, ok := input["vex"].(map[string]any)
	if !ok {
		t.Fatal("expected vex key to be map[string]any")
	}
	stmts, ok := vexSection["statements"].([]map[string]any)
	if !ok {
		t.Fatal("expected vex.statements to be []map[string]any")
	}
	if len(stmts) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(stmts))
	}

	s := stmts[0]

	// Verify all new fields are present.
	if s["confidence"] != "high" {
		t.Errorf("confidence = %v, want high", s["confidence"])
	}
	if s["resolved_by"] != "reachability_analysis" {
		t.Errorf("resolved_by = %v, want reachability_analysis", s["resolved_by"])
	}
	if s["analysis_method"] != "tree_sitter" {
		t.Errorf("analysis_method = %v, want tree_sitter", s["analysis_method"])
	}
	if s["max_call_depth"] != 3 {
		t.Errorf("max_call_depth = %v, want 3", s["max_call_depth"])
	}

	symbols, ok := s["symbols"].([]string)
	if !ok {
		t.Fatal("expected symbols to be []string")
	}
	if len(symbols) != 1 || symbols[0] != "yaml.load" {
		t.Errorf("symbols = %v, want [yaml.load]", symbols)
	}

	entryFiles, ok := s["entry_files"].([]string)
	if !ok {
		t.Fatal("expected entry_files to be []string")
	}
	if len(entryFiles) != 1 || entryFiles[0] != "src/app.py" {
		t.Errorf("entry_files = %v, want [src/app.py]", entryFiles)
	}

	callPaths, ok := s["call_paths"].([][]map[string]any)
	if !ok {
		t.Fatal("expected call_paths to be [][]map[string]any")
	}
	if len(callPaths) != 1 {
		t.Fatalf("call_paths count = %d, want 1", len(callPaths))
	}
	if len(callPaths[0]) != 3 {
		t.Fatalf("call_paths[0] node count = %d, want 3", len(callPaths[0]))
	}
	node := callPaths[0][0]
	if node["symbol"] != "app.main" {
		t.Errorf("call_paths[0][0].symbol = %v, want app.main", node["symbol"])
	}
	if node["file"] != "src/app.py" {
		t.Errorf("call_paths[0][0].file = %v, want src/app.py", node["file"])
	}
	if node["line"] != 10 {
		t.Errorf("call_paths[0][0].line = %v, want 10", node["line"])
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/policykit/ -run TestBuildInput_VEXReachabilityFields -v`
Expected: FAIL — new fields not present in OPA input

- [ ] **Step 3: Expand buildVEX and add helper**

In `pkg/policykit/input.go`, replace the `buildVEX` function (lines 170-183) with:

```go
func buildVEX(a *ParsedArtifacts) map[string]any {
	statements := make([]map[string]any, 0, len(a.VEXResults))
	for _, v := range a.VEXResults {
		statements = append(statements, map[string]any{
			"cve":             v.CVE,
			"purl":            v.ComponentPURL,
			"status":          string(v.Status),
			"justification":   string(v.Justification),
			"confidence":      v.Confidence.String(),
			"resolved_by":     v.ResolvedBy,
			"analysis_method": v.AnalysisMethod,
			"max_call_depth":  v.MaxCallDepth,
			"entry_files":     v.EntryFiles,
			"symbols":         v.Symbols,
			"call_paths":      buildCallPathsInput(v.CallPaths),
		})
	}
	return map[string]any{
		"statements": statements,
	}
}

func buildCallPathsInput(paths []formats.CallPath) [][]map[string]any {
	if paths == nil {
		return nil
	}
	result := make([][]map[string]any, len(paths))
	for i, p := range paths {
		nodes := make([]map[string]any, len(p.Nodes))
		for j, n := range p.Nodes {
			nodes[j] = map[string]any{
				"symbol": n.Symbol,
				"file":   n.File,
				"line":   n.Line,
			}
		}
		result[i] = nodes
	}
	return result
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/policykit/ -run TestBuildInput -v`
Expected: PASS — both existing and new tests pass

- [ ] **Step 5: Commit**

```bash
git add pkg/policykit/input.go pkg/policykit/input_test.go
git commit -m "feat(policykit): expose reachability fields in OPA input"
```

---

### Task 6: Add reachability quality gate Rego policies

**Files:**
- Create: `policies/cra_reach_confidence.rego`
- Create: `policies/cra_reach_call_paths.rego`
- Create: `policies/cra_reach_method.rego`
- Modify: `pkg/policykit/integration_test.go`

**Important:** The OPA engine expects one `result` variable per package (it looks up `pkgMap["result"]`). Each policy rule must be its own `.rego` file with its own `package` declaration.

- [ ] **Step 1: Write the policy integration test**

Add a new test function at the end of `pkg/policykit/integration_test.go`:

```go
func TestIntegration_ReachabilityPolicies(t *testing.T) {
	dir := filepath.Join(fixtureBase, "policykit-all-pass")

	// Use policykit-all-pass as a base, but we'll build input manually
	// to control reachability fields precisely.
	opts := &policykit.Options{
		SBOMPath:     filepath.Join(dir, "sbom.cdx.json"),
		ScanPaths:    []string{filepath.Join(dir, "grype.json")},
		VEXPath:      filepath.Join(dir, "vex-results.json"),
		KEVPath:      filepath.Join(dir, "kev.json"),
		OutputFormat: "json",
	}
	if _, err := os.Stat(filepath.Join(dir, "product-config.yaml")); err == nil {
		opts.ProductConfig = filepath.Join(dir, "product-config.yaml")
	}

	// Run the base scenario to confirm it still passes.
	var buf bytes.Buffer
	err := policykit.Run(opts, &buf)
	require.NoError(t, err)

	// Parse results to confirm reachability rules are present.
	var report struct {
		Results []struct {
			RuleID string `json:"rule_id"`
			Status string `json:"status"`
		} `json:"results"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &report))

	// The all-pass scenario has no reachability VEX results, so REACH rules should PASS
	// (no violations when there are no reachability statements).
	reachRules := map[string]bool{}
	for _, r := range report.Results {
		if r.RuleID == "CRA-REACH-1" || r.RuleID == "CRA-REACH-2" || r.RuleID == "CRA-REACH-3" {
			reachRules[r.RuleID] = true
			assert.Equal(t, "PASS", r.Status, "rule %s should PASS when no reachability statements", r.RuleID)
		}
	}
	assert.True(t, reachRules["CRA-REACH-1"], "CRA-REACH-1 rule should be present in results")
	assert.True(t, reachRules["CRA-REACH-2"], "CRA-REACH-2 rule should be present in results")
	assert.True(t, reachRules["CRA-REACH-3"], "CRA-REACH-3 rule should be present in results")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/policykit/ -run TestIntegration_ReachabilityPolicies -v`
Expected: FAIL — CRA-REACH-1/2/3 rules don't exist yet

- [ ] **Step 3: Create CRA-REACH-1 policy (confidence gate)**

Create `policies/cra_reach_confidence.rego`:

```rego
package cra.reach_confidence

import rego.v1

reach_not_affected := [s |
	some s in input.vex.statements
	s.status == "not_affected"
	s.resolved_by == "reachability_analysis"
]

low_confidence_cves := [s.cve |
	some s in reach_not_affected
	s.confidence != "high"
]

default result := {
	"rule_id": "CRA-REACH-1",
	"name": "Reachability not_affected claims require high confidence",
	"cra_reference": "Annex I Part I.2(a)",
	"status": "FAIL",
	"severity": "high",
	"evidence": {},
}

result := r if {
	count(low_confidence_cves) == 0
	r := {
		"rule_id": "CRA-REACH-1",
		"name": "Reachability not_affected claims require high confidence",
		"cra_reference": "Annex I Part I.2(a)",
		"status": "PASS",
		"severity": "high",
		"evidence": {
			"total_reachability_not_affected": count(reach_not_affected),
			"low_confidence_cves": [],
		},
	}
}

result := r if {
	count(low_confidence_cves) > 0
	r := {
		"rule_id": "CRA-REACH-1",
		"name": "Reachability not_affected claims require high confidence",
		"cra_reference": "Annex I Part I.2(a)",
		"status": "FAIL",
		"severity": "high",
		"evidence": {
			"total_reachability_not_affected": count(reach_not_affected),
			"low_confidence_cves": low_confidence_cves,
		},
	}
}
```

- [ ] **Step 4: Create CRA-REACH-2 policy (call path presence)**

Create `policies/cra_reach_call_paths.rego`:

```rego
package cra.reach_call_paths

import rego.v1

reach_affected := [s |
	some s in input.vex.statements
	s.status == "affected"
	s.resolved_by == "reachability_analysis"
]

missing_paths_cves := [s.cve |
	some s in reach_affected
	count(s.call_paths) == 0
]

default result := {
	"rule_id": "CRA-REACH-2",
	"name": "Reachability affected claims must have supporting call paths",
	"cra_reference": "Annex I Part I.2(a)",
	"status": "FAIL",
	"severity": "high",
	"evidence": {},
}

result := r if {
	count(missing_paths_cves) == 0
	r := {
		"rule_id": "CRA-REACH-2",
		"name": "Reachability affected claims must have supporting call paths",
		"cra_reference": "Annex I Part I.2(a)",
		"status": "PASS",
		"severity": "high",
		"evidence": {
			"total_reachability_affected": count(reach_affected),
			"missing_call_paths_cves": [],
		},
	}
}

result := r if {
	count(missing_paths_cves) > 0
	r := {
		"rule_id": "CRA-REACH-2",
		"name": "Reachability affected claims must have supporting call paths",
		"cra_reference": "Annex I Part I.2(a)",
		"status": "FAIL",
		"severity": "high",
		"evidence": {
			"total_reachability_affected": count(reach_affected),
			"missing_call_paths_cves": missing_paths_cves,
		},
	}
}
```

- [ ] **Step 5: Create CRA-REACH-3 policy (analysis method gate)**

Create `policies/cra_reach_method.rego`:

```rego
package cra.reach_method

import rego.v1

reach_not_affected := [s |
	some s in input.vex.statements
	s.status == "not_affected"
	s.resolved_by == "reachability_analysis"
]

pattern_match_cves := [s.cve |
	some s in reach_not_affected
	s.analysis_method == "pattern_match"
]

default result := {
	"rule_id": "CRA-REACH-3",
	"name": "Pattern-match reachability alone cannot justify not_affected",
	"cra_reference": "Annex I Part I.2(a)",
	"status": "FAIL",
	"severity": "medium",
	"evidence": {},
}

result := r if {
	count(pattern_match_cves) == 0
	r := {
		"rule_id": "CRA-REACH-3",
		"name": "Pattern-match reachability alone cannot justify not_affected",
		"cra_reference": "Annex I Part I.2(a)",
		"status": "PASS",
		"severity": "medium",
		"evidence": {
			"pattern_match_not_affected_cves": [],
		},
	}
}

result := r if {
	count(pattern_match_cves) > 0
	r := {
		"rule_id": "CRA-REACH-3",
		"name": "Pattern-match reachability alone cannot justify not_affected",
		"cra_reference": "Annex I Part I.2(a)",
		"status": "FAIL",
		"severity": "medium",
		"evidence": {
			"pattern_match_not_affected_cves": pattern_match_cves,
		},
	}
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/policykit/ -run TestIntegration_ReachabilityPolicies -v`
Expected: PASS — all reachability rules present and passing

- [ ] **Step 7: Update integration test fixtures for new rule count**

The 3 new Rego policies increase total results from 15 to 18. Update all `expected.json` files:

```bash
cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit
for f in testdata/integration/policykit-*/expected.json; do
  sed -i '' 's/"total_results": 15/"total_results": 18/' "$f"
done
```

- [ ] **Step 8: Run full policykit tests to check for regressions**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/policykit/ -v -count=1`
Expected: PASS — existing integration tests still pass with updated count; new rules PASS vacuously when no reachability statements exist

- [ ] **Step 9: Commit**

```bash
git add policies/cra_reach_confidence.rego policies/cra_reach_call_paths.rego policies/cra_reach_method.rego pkg/policykit/integration_test.go testdata/integration/policykit-*/expected.json
git commit -m "feat(policykit): add reachability quality gate policies (3 rules)"
```

---

### Task 7: Add CSAF reachability notes

**Files:**
- Modify: `pkg/csaf/notes.go`
- Modify: `pkg/csaf/notes_test.go`

- [ ] **Step 1: Write failing tests for reachability notes**

Add to `pkg/csaf/notes_test.go`:

```go
func TestBuildVulnNotes_ReachabilityPaths(t *testing.T) {
	finding := formats.Finding{
		CVE: "CVE-2020-1747",
	}
	vexResult := formats.VEXResult{
		CVE:            "CVE-2020-1747",
		Confidence:     formats.ConfidenceHigh,
		ResolvedBy:     "reachability_analysis",
		AnalysisMethod: "tree_sitter",
		Evidence:       "yaml.load is called",
		Symbols:        []string{"yaml.load"},
		MaxCallDepth:   2,
		EntryFiles:     []string{"src/app.py"},
		CallPaths: []formats.CallPath{
			{
				Nodes: []formats.CallNode{
					{Symbol: "app.main", File: "src/app.py", Line: 10},
					{Symbol: "yaml.load", File: "yaml/__init__.py", Line: 100},
				},
			},
		},
	}

	notes := buildVulnNotes(&finding, &vexResult)

	// Should have: existing evidence note + 1 call path note + 1 summary note = 3
	if len(notes) < 3 {
		t.Fatalf("expected at least 3 notes, got %d: %v", len(notes), notes)
	}

	// Find call path note
	var callPathNote *note
	var summaryNote *note
	for i := range notes {
		if notes[i].Title == "Reachability Call Path 1" {
			callPathNote = &notes[i]
		}
		if notes[i].Title == "Reachability Analysis Summary" {
			summaryNote = &notes[i]
		}
	}

	if callPathNote == nil {
		t.Fatal("expected a 'Reachability Call Path 1' note")
	}
	if callPathNote.Category != "details" {
		t.Errorf("call path note category = %q, want details", callPathNote.Category)
	}
	// Verify JSON body is valid
	var parsed map[string]any
	if err := json.Unmarshal([]byte(callPathNote.Text), &parsed); err != nil {
		t.Fatalf("call path note text is not valid JSON: %v\nText: %s", err, callPathNote.Text)
	}
	if _, ok := parsed["call_path"]; !ok {
		t.Error("call path JSON missing 'call_path' key")
	}

	if summaryNote == nil {
		t.Fatal("expected a 'Reachability Analysis Summary' note")
	}
	if !strings.Contains(summaryNote.Text, "confidence=high") {
		t.Errorf("summary note missing confidence, got: %s", summaryNote.Text)
	}
	if !strings.Contains(summaryNote.Text, "yaml.load") {
		t.Errorf("summary note missing symbol, got: %s", summaryNote.Text)
	}
}

func TestBuildVulnNotes_NoReachabilityNotes_ForNonReachability(t *testing.T) {
	finding := formats.Finding{CVE: "CVE-2022-32149"}
	vexResult := formats.VEXResult{
		CVE:        "CVE-2022-32149",
		Confidence: formats.ConfidenceHigh,
		ResolvedBy: "version",
		Evidence:   "version not in affected range",
	}

	notes := buildVulnNotes(&finding, &vexResult)

	for _, n := range notes {
		if strings.Contains(n.Title, "Reachability") {
			t.Errorf("non-reachability result should not produce reachability notes, got: %v", n)
		}
	}
}
```

Note: you'll need to add `"encoding/json"` to the imports in notes_test.go.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/csaf/ -run TestBuildVulnNotes_Reachability -v`
Expected: FAIL — reachability notes not generated

- [ ] **Step 3: Implement reachability notes**

Replace `pkg/csaf/notes.go` entirely:

```go
package csaf

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
)

func buildDocumentNotes(findings []formats.Finding) []note {
	var cves []string
	seen := make(map[string]bool)
	for i := range findings {
		f := &findings[i]
		if !seen[f.CVE] {
			seen[f.CVE] = true
			cves = append(cves, f.CVE)
		}
	}
	return []note{{
		Category: "summary",
		Title:    "Advisory Summary",
		Text:     fmt.Sprintf("Security advisory addressing %d vulnerability(ies): %s.", len(cves), strings.Join(cves, ", ")),
	}}
}

func buildVulnNotes(finding *formats.Finding, vexResult *formats.VEXResult) []note {
	var notes []note
	if finding.Description != "" {
		notes = append(notes, note{Category: "description", Text: finding.Description})
	}
	if vexResult.Confidence >= formats.ConfidenceHigh && vexResult.Evidence != "" {
		notes = append(notes, note{Category: "details", Title: "VEX Assessment", Text: vexResult.Evidence})
	}
	if vexResult.ResolvedBy == "reachability_analysis" {
		notes = append(notes, buildReachabilityNotes(vexResult)...)
	}
	return notes
}

func buildReachabilityNotes(vexResult *formats.VEXResult) []note {
	var notes []note

	// One note per call path with JSON body.
	for i, p := range vexResult.CallPaths {
		pathNodes := make([]map[string]any, len(p.Nodes))
		for j, n := range p.Nodes {
			pathNodes[j] = map[string]any{
				"symbol": n.Symbol,
				"file":   n.File,
				"line":   n.Line,
			}
		}
		body := map[string]any{
			"call_path":  pathNodes,
			"depth":      p.Depth(),
			"confidence": vexResult.Confidence.String(),
		}
		jsonBytes, _ := json.Marshal(body)
		notes = append(notes, note{
			Category: "details",
			Title:    fmt.Sprintf("Reachability Call Path %d", i+1),
			Text:     string(jsonBytes),
		})
	}

	// Summary note.
	symbols := strings.Join(vexResult.Symbols, ",")
	entryFiles := strings.Join(vexResult.EntryFiles, ",")
	summary := fmt.Sprintf("confidence=%s symbols=%s max_depth=%d entry_files=%s",
		vexResult.Confidence.String(), symbols, vexResult.MaxCallDepth, entryFiles)
	notes = append(notes, note{
		Category: "details",
		Title:    "Reachability Analysis Summary",
		Text:     summary,
	})

	return notes
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/csaf/ -run TestBuildVulnNotes -v`
Expected: PASS — all existing and new tests pass

- [ ] **Step 5: Commit**

```bash
git add pkg/csaf/notes.go pkg/csaf/notes_test.go
git commit -m "feat(csaf): add structured reachability call path notes"
```

---

### Task 8: Add report reachability evidence rendering

**Files:**
- Create: `pkg/report/reachability.go`
- Create: `pkg/report/reachability_test.go`
- Modify: `pkg/report/notification.go:51-53`
- Modify: `pkg/report/render.go:44-84`

- [ ] **Step 1: Write failing tests for ReachabilityDetail**

Create `pkg/report/reachability_test.go`:

```go
package report

import (
	"strings"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
)

func TestReachabilityDetail_WithPaths(t *testing.T) {
	v := formats.VEXResult{
		ResolvedBy:     "reachability_analysis",
		AnalysisMethod: "tree_sitter",
		Confidence:     formats.ConfidenceHigh,
		Symbols:        []string{"yaml.load"},
		CallPaths: []formats.CallPath{
			{
				Nodes: []formats.CallNode{
					{Symbol: "app.main", File: "src/app.py", Line: 10},
					{Symbol: "app.process", File: "src/app.py", Line: 25},
					{Symbol: "yaml.load", File: "yaml/__init__.py", Line: 100},
				},
			},
		},
		MaxCallDepth: 3,
	}

	got := ReachabilityDetail(v)

	if !strings.Contains(got, "Symbols: yaml.load") {
		t.Errorf("expected 'Symbols: yaml.load', got:\n%s", got)
	}
	if !strings.Contains(got, "Call paths (1):") {
		t.Errorf("expected 'Call paths (1):', got:\n%s", got)
	}
	if !strings.Contains(got, "Path 1 (depth 3):") {
		t.Errorf("expected 'Path 1 (depth 3):', got:\n%s", got)
	}
	if !strings.Contains(got, "app.main") {
		t.Errorf("expected 'app.main' in output, got:\n%s", got)
	}
	if !strings.Contains(got, "[src/app.py:10]") {
		t.Errorf("expected '[src/app.py:10]' in output, got:\n%s", got)
	}
	// Verify indentation uses → for non-first nodes.
	if !strings.Contains(got, "→ app.process") {
		t.Errorf("expected '→ app.process' indented, got:\n%s", got)
	}
}

func TestReachabilityDetail_NoPaths(t *testing.T) {
	v := formats.VEXResult{
		ResolvedBy:     "reachability_analysis",
		AnalysisMethod: "tree_sitter",
		Confidence:     formats.ConfidenceHigh,
		Status:         formats.StatusNotAffected,
		Symbols:        []string{"yaml.load"},
	}

	got := ReachabilityDetail(v)

	if !strings.Contains(got, "No call path found") {
		t.Errorf("expected 'No call path found', got:\n%s", got)
	}
	if !strings.Contains(got, "Symbols checked: yaml.load") {
		t.Errorf("expected 'Symbols checked: yaml.load', got:\n%s", got)
	}
	if !strings.Contains(got, "Confidence: high") {
		t.Errorf("expected 'Confidence: high', got:\n%s", got)
	}
}

func TestReachabilityDetail_NotReachability(t *testing.T) {
	v := formats.VEXResult{
		ResolvedBy: "version",
		Evidence:   "version not in affected range",
	}

	got := ReachabilityDetail(v)

	if got != "" {
		t.Errorf("expected empty string for non-reachability result, got: %q", got)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/report/ -run TestReachabilityDetail -v`
Expected: FAIL — `ReachabilityDetail` not defined

- [ ] **Step 3: Implement ReachabilityDetail**

Create `pkg/report/reachability.go`:

```go
package report

import (
	"fmt"
	"strings"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
)

// ReachabilityDetail renders a human-readable reachability evidence block
// for an auditor. Returns empty string for non-reachability results.
func ReachabilityDetail(v formats.VEXResult) string {
	if v.ResolvedBy != "reachability_analysis" {
		return ""
	}

	var b strings.Builder
	b.WriteString("Reachability Evidence:\n")

	if len(v.CallPaths) == 0 {
		b.WriteString("  No call path found from application entry points to vulnerable symbol.\n")
		if len(v.Symbols) > 0 {
			b.WriteString(fmt.Sprintf("  Symbols checked: %s\n", strings.Join(v.Symbols, ", ")))
		}
		b.WriteString(fmt.Sprintf("  Confidence: %s\n", v.Confidence.String()))
		return b.String()
	}

	if len(v.Symbols) > 0 {
		b.WriteString(fmt.Sprintf("  Symbols: %s\n", strings.Join(v.Symbols, ", ")))
	}
	b.WriteString(fmt.Sprintf("  Call paths (%d):\n", len(v.CallPaths)))

	for i, p := range v.CallPaths {
		b.WriteString(fmt.Sprintf("    Path %d (depth %d):\n", i+1, p.Depth()))
		for j, n := range p.Nodes {
			loc := "<dependency>:0"
			if n.File != "" {
				loc = fmt.Sprintf("%s:%d", n.File, n.Line)
			}
			if j == 0 {
				b.WriteString(fmt.Sprintf("      %s  [%s]\n", n.Symbol, loc))
			} else {
				indent := strings.Repeat("  ", j)
				b.WriteString(fmt.Sprintf("      %s→ %s  [%s]\n", indent, n.Symbol, loc))
			}
		}
	}

	return b.String()
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/report/ -run TestReachabilityDetail -v`
Expected: PASS

- [ ] **Step 5: Wire ReachabilityDetail into notification and render**

In `pkg/report/notification.go`, replace lines 51-53:

```go
		if vr, ok := vexByCV[v.CVE]; ok && vr.Evidence != "" {
			e.MitigatingMeasures = []string{vr.Evidence}
		}
```

with:

```go
		if vr, ok := vexByCV[v.CVE]; ok {
			if detail := ReachabilityDetail(vr); detail != "" {
				e.MitigatingMeasures = []string{detail}
			} else if vr.Evidence != "" {
				e.MitigatingMeasures = []string{vr.Evidence}
			}
		}
```

In `pkg/report/render.go`, add after line 68 (after the `CorrectiveActions` block, before `// Final report fields.`):

```go
		if len(v.MitigatingMeasures) > 0 {
			b.WriteString(fmt.Sprintf("- **Mitigating Measures:**\n"))
			for _, m := range v.MitigatingMeasures {
				b.WriteString(fmt.Sprintf("  ```\n%s  ```\n", m))
			}
		}
```

- [ ] **Step 6: Run full report tests**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/report/ -v -count=1`
Expected: PASS — no regressions

- [ ] **Step 7: Commit**

```bash
git add pkg/report/reachability.go pkg/report/reachability_test.go pkg/report/notification.go pkg/report/render.go
git commit -m "feat(report): add reachability evidence rendering for Art. 14"
```

---

### Task 9: Add OpenVEX structured impact statement

**Files:**
- Modify: `pkg/formats/openvex/openvex.go:87-118`
- Modify: `pkg/formats/openvex/openvex_test.go`

- [ ] **Step 1: Write failing test for structured impact statement**

Add to `pkg/formats/openvex/openvex_test.go`:

```go
func TestWriter_ReachabilityStructuredImpact(t *testing.T) {
	results := []formats.VEXResult{
		{
			CVE:            "CVE-2020-1747",
			ComponentPURL:  "pkg:pypi/pyyaml@5.3",
			Status:         formats.StatusAffected,
			Confidence:     formats.ConfidenceHigh,
			ResolvedBy:     "reachability_analysis",
			AnalysisMethod: "tree_sitter",
			Evidence:       "yaml.load is called",
			Symbols:        []string{"yaml.load"},
			MaxCallDepth:   2,
			EntryFiles:     []string{"src/app.py"},
			CallPaths: []formats.CallPath{
				{
					Nodes: []formats.CallNode{
						{Symbol: "app.main", File: "src/app.py", Line: 10},
						{Symbol: "yaml.load", File: "yaml/__init__.py", Line: 100},
					},
				},
			},
		},
		{
			CVE:           "CVE-2023-9999",
			ComponentPURL: "pkg:golang/example.com/lib@v1.0.0",
			Status:        formats.StatusNotAffected,
			Justification: formats.JustificationVulnerableCodeNotPresent,
			ResolvedBy:    "version",
			Evidence:      "version not in affected range",
		},
	}

	var buf bytes.Buffer
	w := openvex.Writer{}
	if err := w.Write(&buf, results); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Parse the output JSON.
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	stmts, ok := doc["statements"].([]any)
	if !ok || len(stmts) != 2 {
		t.Fatalf("expected 2 statements, got %v", doc["statements"])
	}

	// First statement (reachability) should have JSON impact_statement.
	s1 := stmts[0].(map[string]any)
	impact1 := s1["impact_statement"].(string)
	var parsed map[string]any
	if err := json.Unmarshal([]byte(impact1), &parsed); err != nil {
		t.Fatalf("reachability impact_statement is not valid JSON: %v\nGot: %s", err, impact1)
	}
	if parsed["analysis_method"] != "tree_sitter" {
		t.Errorf("analysis_method = %v, want tree_sitter", parsed["analysis_method"])
	}
	if parsed["confidence"] != "high" {
		t.Errorf("confidence = %v, want high", parsed["confidence"])
	}
	if parsed["summary"] != "yaml.load is called" {
		t.Errorf("summary = %v, want 'yaml.load is called'", parsed["summary"])
	}
	callPaths, ok := parsed["call_paths"].([]any)
	if !ok || len(callPaths) != 1 {
		t.Fatalf("call_paths count = %v, want 1", parsed["call_paths"])
	}

	// Second statement (non-reachability) should have plain-text impact_statement.
	s2 := stmts[1].(map[string]any)
	impact2 := s2["impact_statement"].(string)
	if impact2 != "version not in affected range" {
		t.Errorf("non-reachability impact_statement = %q, want plain text", impact2)
	}
	// Verify it's NOT JSON.
	var dummy map[string]any
	if err := json.Unmarshal([]byte(impact2), &dummy); err == nil {
		t.Error("non-reachability impact_statement should not be JSON")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/formats/openvex/ -run TestWriter_ReachabilityStructuredImpact -v`
Expected: FAIL — impact_statement is plain text, not JSON

- [ ] **Step 3: Implement structured impact statement**

In `pkg/formats/openvex/openvex.go`, replace the `Write` method (lines 87-118) with:

```go
// Write serializes VEX results to OpenVEX JSON format.
func (w Writer) Write(out io.Writer, results []formats.VEXResult) error {
	stmts := make([]statement, 0, len(results))
	for _, r := range results {
		s := statement{
			Vulnerability: vulnerability{Name: r.CVE},
			Products: []product{
				{ID: r.ComponentPURL},
			},
			Status:        statusToOpenVEX(r.Status),
			Justification: justificationToOpenVEX(r.Justification),
		}
		if r.ResolvedBy == "reachability_analysis" {
			s.ImpactStatement = buildReachabilityImpact(r)
		} else {
			s.ImpactStatement = r.Evidence
		}
		stmts = append(stmts, s)
	}

	doc := document{
		Context:    contextURL,
		ID:         "https://suse.com/vex/" + time.Now().UTC().Format("20060102T150405Z"),
		Author:     "SUSE CRA Toolkit",
		Role:       "Document Creator",
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Version:    1,
		Statements: stmts,
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("openvex: encode JSON: %w", err)
	}
	return nil
}

func buildReachabilityImpact(r formats.VEXResult) string {
	callPaths := make([][]map[string]any, len(r.CallPaths))
	for i, p := range r.CallPaths {
		nodes := make([]map[string]any, len(p.Nodes))
		for j, n := range p.Nodes {
			nodes[j] = map[string]any{
				"symbol": n.Symbol,
				"file":   n.File,
				"line":   n.Line,
			}
		}
		callPaths[i] = nodes
	}

	impact := map[string]any{
		"summary":         r.Evidence,
		"analysis_method": r.AnalysisMethod,
		"confidence":      r.Confidence.String(),
		"symbols":         r.Symbols,
		"max_call_depth":  r.MaxCallDepth,
		"entry_files":     r.EntryFiles,
		"call_paths":      callPaths,
	}

	b, _ := json.MarshalIndent(impact, "", "  ")
	return string(b)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/formats/openvex/ -v`
Expected: PASS — all existing and new tests pass

- [ ] **Step 5: Commit**

```bash
git add pkg/formats/openvex/openvex.go pkg/formats/openvex/openvex_test.go
git commit -m "feat(openvex): structured JSON impact statement for reachability"
```

---

### Task 10: Add evidence bundle VEXEvidence types and vex_evidence.json

**Files:**
- Modify: `pkg/evidence/types.go`
- Modify: `pkg/evidence/collect.go`

- [ ] **Step 1: Write failing test for VEXEvidence type and builder**

Create or add to an appropriate test file. Since evidence package uses internal tests, add to the existing test structure. Create `pkg/evidence/vex_evidence_test.go`:

```go
package evidence

import (
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
)

func TestBuildVEXEvidence(t *testing.T) {
	results := []formats.VEXResult{
		{
			CVE:            "CVE-2020-1747",
			ComponentPURL:  "pkg:pypi/pyyaml@5.3",
			Status:         formats.StatusAffected,
			Justification:  "",
			Confidence:     formats.ConfidenceHigh,
			ResolvedBy:     "reachability_analysis",
			AnalysisMethod: "tree_sitter",
			Evidence:       "yaml.load is called",
			Symbols:        []string{"yaml.load"},
			MaxCallDepth:   2,
			EntryFiles:     []string{"src/app.py"},
			CallPaths: []formats.CallPath{
				{
					Nodes: []formats.CallNode{
						{Symbol: "app.main", File: "src/app.py", Line: 10},
						{Symbol: "yaml.load", File: "yaml/__init__.py", Line: 100},
					},
				},
			},
		},
		{
			CVE:           "CVE-2023-9999",
			ComponentPURL: "pkg:golang/example.com/lib@v1.0.0",
			Status:        formats.StatusNotAffected,
			Justification: formats.JustificationVulnerableCodeNotPresent,
			ResolvedBy:    "version",
			Evidence:      "version not in affected range",
		},
	}

	evidence := buildVEXEvidence(results)

	if len(evidence) != 2 {
		t.Fatalf("expected 2 evidence entries, got %d", len(evidence))
	}

	// First entry: reachability with call paths
	e1 := evidence[0]
	if e1.CVE != "CVE-2020-1747" {
		t.Errorf("e1.CVE = %q, want CVE-2020-1747", e1.CVE)
	}
	if e1.ResolvedBy != "reachability_analysis" {
		t.Errorf("e1.ResolvedBy = %q, want reachability_analysis", e1.ResolvedBy)
	}
	if len(e1.CallPaths) != 1 {
		t.Fatalf("e1.CallPaths count = %d, want 1", len(e1.CallPaths))
	}
	if e1.CallPaths[0].Depth != 2 {
		t.Errorf("e1.CallPaths[0].Depth = %d, want 2", e1.CallPaths[0].Depth)
	}
	if len(e1.CallPaths[0].Nodes) != 2 {
		t.Fatalf("e1.CallPaths[0].Nodes count = %d, want 2", len(e1.CallPaths[0].Nodes))
	}
	if e1.CallPaths[0].Nodes[0].Symbol != "app.main" {
		t.Errorf("node[0].Symbol = %q, want app.main", e1.CallPaths[0].Nodes[0].Symbol)
	}
	if e1.MaxCallDepth != 2 {
		t.Errorf("e1.MaxCallDepth = %d, want 2", e1.MaxCallDepth)
	}

	// Second entry: non-reachability, no call paths
	e2 := evidence[1]
	if e2.CVE != "CVE-2023-9999" {
		t.Errorf("e2.CVE = %q, want CVE-2023-9999", e2.CVE)
	}
	if len(e2.CallPaths) != 0 {
		t.Errorf("e2.CallPaths should be empty, got %d", len(e2.CallPaths))
	}
}

func TestBuildVulnHandlingStats_ReachabilityBased(t *testing.T) {
	results := []formats.VEXResult{
		{CVE: "CVE-1", Status: formats.StatusAffected, ResolvedBy: "reachability_analysis"},
		{CVE: "CVE-2", Status: formats.StatusNotAffected, ResolvedBy: "version"},
		{CVE: "CVE-3", Status: formats.StatusNotAffected, ResolvedBy: "reachability_analysis"},
	}

	stats := buildVulnHandlingStats(results)

	if stats.TotalAssessed != 3 {
		t.Errorf("TotalAssessed = %d, want 3", stats.TotalAssessed)
	}
	if stats.ReachabilityBased != 2 {
		t.Errorf("ReachabilityBased = %d, want 2", stats.ReachabilityBased)
	}
	if stats.StatusDistribution["affected"] != 1 {
		t.Errorf("StatusDistribution[affected] = %d, want 1", stats.StatusDistribution["affected"])
	}
	if stats.StatusDistribution["not_affected"] != 2 {
		t.Errorf("StatusDistribution[not_affected] = %d, want 2", stats.StatusDistribution["not_affected"])
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/evidence/ -run "TestBuildVEXEvidence|TestBuildVulnHandlingStats" -v`
Expected: FAIL — functions not defined

- [ ] **Step 3: Add VEXEvidence types to types.go**

In `pkg/evidence/types.go`, add after `VulnHandlingStats` (after line 145):

```go
// VulnHandlingStats holds statistics extracted from a real VEX document.
type VulnHandlingStats struct {
	TotalAssessed      int            `json:"total_assessed"`
	StatusDistribution map[string]int `json:"status_distribution"`
	ReachabilityBased  int            `json:"reachability_based"`
}
```

(Replace the existing `VulnHandlingStats` definition at lines 142-145.)

Also add after line 241 (after `vexInfo` struct):

```go
// VEXEvidence holds complete per-vulnerability evidence for the bundle.
type VEXEvidence struct {
	CVE           string          `json:"cve"`
	ComponentPURL string          `json:"component_purl"`
	Status        string          `json:"status"`
	Justification string          `json:"justification"`
	Confidence    string          `json:"confidence"`
	ResolvedBy    string          `json:"resolved_by"`
	Evidence      string          `json:"evidence"`
	Symbols       []string        `json:"symbols"`
	CallPaths     []CallPathEntry `json:"call_paths"`
	MaxCallDepth  int             `json:"max_call_depth"`
	EntryFiles    []string        `json:"entry_files"`
}

// CallPathEntry is a serializable call path for the evidence bundle.
type CallPathEntry struct {
	Nodes []CallNodeEntry `json:"nodes"`
	Depth int             `json:"depth"`
}

// CallNodeEntry is a serializable call node for the evidence bundle.
type CallNodeEntry struct {
	Symbol string `json:"symbol"`
	File   string `json:"file"`
	Line   int    `json:"line"`
}
```

- [ ] **Step 4: Add buildVEXEvidence and buildVulnHandlingStats to collect.go**

Add at the end of `pkg/evidence/collect.go` (before the closing of the file):

```go
// buildVEXEvidence converts VEXResults to serializable evidence entries.
func buildVEXEvidence(results []formats.VEXResult) []VEXEvidence { //nolint:unused // used in tasks 3-6
	evidence := make([]VEXEvidence, len(results))
	for i, r := range results {
		var paths []CallPathEntry
		for _, p := range r.CallPaths {
			nodes := make([]CallNodeEntry, len(p.Nodes))
			for j, n := range p.Nodes {
				nodes[j] = CallNodeEntry{
					Symbol: n.Symbol,
					File:   n.File,
					Line:   n.Line,
				}
			}
			paths = append(paths, CallPathEntry{
				Nodes: nodes,
				Depth: p.Depth(),
			})
		}
		evidence[i] = VEXEvidence{
			CVE:           r.CVE,
			ComponentPURL: r.ComponentPURL,
			Status:        string(r.Status),
			Justification: string(r.Justification),
			Confidence:    r.Confidence.String(),
			ResolvedBy:    r.ResolvedBy,
			Evidence:      r.Evidence,
			Symbols:       r.Symbols,
			CallPaths:     paths,
			MaxCallDepth:  r.MaxCallDepth,
			EntryFiles:    r.EntryFiles,
		}
	}
	return evidence
}

// buildVulnHandlingStats computes handling statistics from VEX results.
func buildVulnHandlingStats(results []formats.VEXResult) VulnHandlingStats { //nolint:unused // used in tasks 3-6
	stats := VulnHandlingStats{
		TotalAssessed:      len(results),
		StatusDistribution: make(map[string]int),
	}
	for _, r := range results {
		stats.StatusDistribution[string(r.Status)]++
		if r.ResolvedBy == "reachability_analysis" {
			stats.ReachabilityBased++
		}
	}
	return stats
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/evidence/ -run "TestBuildVEXEvidence|TestBuildVulnHandlingStats" -v`
Expected: PASS

- [ ] **Step 6: Run full quality gate**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && task quality`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add pkg/evidence/types.go pkg/evidence/collect.go pkg/evidence/vex_evidence_test.go
git commit -m "feat(evidence): add VEXEvidence types and builder for evidence bundle"
```

---

### Task 11: Final integration verification

- [ ] **Step 1: Run full project quality gate**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && task quality`
Expected: PASS — all linting, formatting, and tests pass

- [ ] **Step 2: Run just the new/modified tests to confirm coverage**

Run:
```bash
cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && \
go test ./pkg/formats/ -run TestCallPath -v && \
go test ./pkg/formats/ -run TestVEXResult -v && \
go test ./pkg/vex/ -run TestReachabilityFilter -v && \
go test ./pkg/policykit/ -run "TestBuildInput_VEXReachabilityFields|TestIntegration_ReachabilityPolicies" -v && \
go test ./pkg/csaf/ -run TestBuildVulnNotes -v && \
go test ./pkg/report/ -run TestReachabilityDetail -v && \
go test ./pkg/formats/openvex/ -run TestWriter_ReachabilityStructuredImpact -v && \
go test ./pkg/evidence/ -run "TestBuildVEXEvidence|TestBuildVulnHandlingStats" -v
```
Expected: ALL PASS

- [ ] **Step 3: Verify dependency graph has no cycles**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go build ./...`
Expected: Clean build, no import cycles
