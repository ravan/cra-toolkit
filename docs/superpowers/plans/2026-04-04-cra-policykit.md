# cra-policykit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement CRA Annex I policy evaluation using embedded OPA/Rego policies that produce PASS/FAIL/SKIP/HUMAN compliance reports.

**Architecture:** 5-stage pipeline (parse artifacts → fetch KEV → build OPA input → evaluate Rego policies → assemble report). Each policy is a standalone `.rego` file. OPA evaluates them via the `rego` Go package. Output is JSON or markdown.

**Tech Stack:** Go, OPA/Rego (`github.com/open-policy-agent/opa/v1/rego`), `gopkg.in/yaml.v3`, embedded `policies/*.rego` via `embed.FS`.

**Spec:** `docs/superpowers/specs/2026-04-04-cra-policykit-design.md`

---

## File Map

| File | Responsibility |
|------|---------------|
| `pkg/policykit/policykit.go` | Pipeline orchestration (`Options`, `Run()`) |
| `pkg/policykit/input.go` | Build unified OPA input document from parsed artifacts |
| `pkg/policykit/engine.go` | OPA engine: load Rego policies, evaluate, collect results |
| `pkg/policykit/kev.go` | CISA KEV catalog: fetch, cache, parse, lookup |
| `pkg/policykit/report.go` | Report types, JSON serialization, markdown rendering |
| `pkg/policykit/provenance.go` | SLSA provenance attestation parsing |
| `pkg/policykit/signature.go` | Signature file detection and parsing |
| `pkg/policykit/human.go` | Human-flagged items (static checklist) |
| `policies/cra_sbom_valid.rego` | CRA-AI-1.1: SBOM validation |
| `policies/cra_no_kev.rego` | CRA-AI-2.1: KEV cross-check |
| `policies/cra_vex_coverage.rego` | CRA-AI-2.2: VEX coverage for critical/high CVEs |
| `policies/cra_provenance.rego` | CRA-AI-3.1: Build provenance SLSA L1+ |
| `policies/cra_signatures.rego` | CRA-AI-3.2: Cryptographic signatures |
| `policies/cra_support_period.rego` | CRA-AI-4.1: Support period >= 5 years |
| `policies/cra_update_mechanism.rego` | CRA-AI-4.2: Secure update mechanism |
| `internal/cli/policykit.go` | CLI wiring with flags |
| `Taskfile.yml` | New test targets |
| `pkg/policykit/input_test.go` | Input document assembly tests |
| `pkg/policykit/engine_test.go` | OPA engine tests |
| `pkg/policykit/kev_test.go` | KEV parsing tests |
| `pkg/policykit/report_test.go` | Report assembly + markdown tests |
| `pkg/policykit/provenance_test.go` | Provenance parsing tests |
| `pkg/policykit/signature_test.go` | Signature parsing tests |
| `pkg/policykit/integration_test.go` | End-to-end integration tests |
| `pkg/policykit/llm_judge_test.go` | LLM quality judge tests |
| `testdata/integration/policykit-*/` | 6 integration test fixture directories |

---

### Task 1: Add OPA dependency and report types

**Files:**
- Modify: `go.mod`
- Create: `pkg/policykit/report.go`
- Create: `pkg/policykit/report_test.go`

- [ ] **Step 1: Write the failing test for report types and JSON serialization**

Create `pkg/policykit/report_test.go`:

```go
package policykit_test

import (
	"encoding/json"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/policykit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReport_JSONSerialization(t *testing.T) {
	report := policykit.Report{
		ReportID:       "policykit-2026-04-04T10:30:00Z",
		ToolkitVersion: "0.1.0",
		Timestamp:      "2026-04-04T10:30:00Z",
		Summary: policykit.Summary{
			Total:  3,
			Passed: 1,
			Failed: 1,
			Skipped: 0,
			Human:  1,
		},
		Results: []policykit.PolicyResult{
			{
				RuleID:       "CRA-AI-1.1",
				Name:         "SBOM exists and is valid",
				CRAReference: "Annex I Part II.1",
				Status:       "PASS",
				Severity:     "critical",
				Evidence: map[string]any{
					"sbom_format":    "cyclonedx",
					"component_count": float64(142),
				},
			},
			{
				RuleID:       "CRA-AI-2.1",
				Name:         "No known exploited vulnerabilities",
				CRAReference: "Annex I Part I.2(a)",
				Status:       "FAIL",
				Severity:     "critical",
				Evidence: map[string]any{
					"kev_matches": []any{"CVE-2024-3094"},
				},
			},
			{
				RuleID:       "CRA-HU-1.1",
				Name:         "Appropriate cybersecurity level",
				CRAReference: "Annex I Part I.1",
				Status:       "HUMAN",
				Severity:     "high",
				Guidance:     "Verify risk assessment performed and cybersecurity measures are proportionate to identified risks.",
			},
		},
	}

	data, err := json.MarshalIndent(report, "", "  ")
	require.NoError(t, err)

	var decoded policykit.Report
	require.NoError(t, json.Unmarshal(data, &decoded))

	assert.Equal(t, "policykit-2026-04-04T10:30:00Z", decoded.ReportID)
	assert.Equal(t, 3, decoded.Summary.Total)
	assert.Equal(t, 1, decoded.Summary.Passed)
	assert.Equal(t, 1, decoded.Summary.Failed)
	assert.Len(t, decoded.Results, 3)
	assert.Equal(t, "PASS", decoded.Results[0].Status)
	assert.Equal(t, "FAIL", decoded.Results[1].Status)
	assert.Equal(t, "HUMAN", decoded.Results[2].Status)
}

func TestReport_ComputeSummary(t *testing.T) {
	results := []policykit.PolicyResult{
		{Status: "PASS"}, {Status: "PASS"},
		{Status: "FAIL"},
		{Status: "SKIP"},
		{Status: "HUMAN"}, {Status: "HUMAN"},
	}

	summary := policykit.ComputeSummary(results)
	assert.Equal(t, 6, summary.Total)
	assert.Equal(t, 2, summary.Passed)
	assert.Equal(t, 1, summary.Failed)
	assert.Equal(t, 1, summary.Skipped)
	assert.Equal(t, 2, summary.Human)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -race -count=1 -run TestReport ./pkg/policykit/...`
Expected: FAIL — types not defined

- [ ] **Step 3: Write the report types implementation**

Create `pkg/policykit/report.go`:

```go
// Package policykit implements CRA Annex I policy evaluation using embedded OPA/Rego policies.
// It evaluates SBOM, VEX, and provenance artifacts against machine-checkable CRA rules.
package policykit

import "encoding/json"

// Report is the top-level policy evaluation output.
type Report struct {
	ReportID       string         `json:"report_id"`
	ToolkitVersion string         `json:"toolkit_version"`
	Timestamp      string         `json:"timestamp"`
	Summary        Summary        `json:"summary"`
	Results        []PolicyResult `json:"results"`
}

// Summary counts results by status.
type Summary struct {
	Total   int `json:"total"`
	Passed  int `json:"passed"`
	Failed  int `json:"failed"`
	Skipped int `json:"skipped"`
	Human   int `json:"human"`
}

// PolicyResult is the outcome of a single policy evaluation.
type PolicyResult struct {
	RuleID       string         `json:"rule_id"`
	Name         string         `json:"name"`
	CRAReference string         `json:"cra_reference"`
	Status       string         `json:"status"`
	Severity     string         `json:"severity"`
	Evidence     map[string]any `json:"evidence,omitempty"`
	Guidance     string         `json:"guidance,omitempty"`
}

// ComputeSummary tallies results by status.
func ComputeSummary(results []PolicyResult) Summary {
	s := Summary{Total: len(results)}
	for i := range results {
		switch results[i].Status {
		case "PASS":
			s.Passed++
		case "FAIL":
			s.Failed++
		case "SKIP":
			s.Skipped++
		case "HUMAN":
			s.Human++
		}
	}
	return s
}

// MarshalJSON produces indented JSON for the report.
func (r *Report) MarshalJSON() ([]byte, error) {
	type Alias Report
	return json.Marshal((*Alias)(r))
}
```

Delete the old stub in `pkg/policykit/policykit.go` — replace it entirely (we'll rebuild it in Task 7).

Replace `pkg/policykit/policykit.go` with:

```go
package policykit

import "errors"

// ErrNotImplemented is returned by stub functions that are not yet implemented.
var ErrNotImplemented = errors.New("policykit: not implemented")
```

- [ ] **Step 4: Add OPA dependency**

Run:
```bash
cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit
go get github.com/open-policy-agent/opa/v1@latest
go mod tidy
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test -race -count=1 -run TestReport ./pkg/policykit/...`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add pkg/policykit/report.go pkg/policykit/report_test.go pkg/policykit/policykit.go go.mod go.sum
git commit -m "feat(policykit): add report types and OPA dependency"
```

---

### Task 2: Markdown report renderer

**Files:**
- Modify: `pkg/policykit/report.go`
- Modify: `pkg/policykit/report_test.go`

- [ ] **Step 1: Write the failing test for markdown rendering**

Add to `pkg/policykit/report_test.go`:

```go
func TestReport_RenderMarkdown(t *testing.T) {
	report := policykit.Report{
		ReportID:       "policykit-2026-04-04T10:30:00Z",
		ToolkitVersion: "0.1.0",
		Timestamp:      "2026-04-04T10:30:00Z",
		Summary: policykit.Summary{
			Total: 4, Passed: 1, Failed: 1, Skipped: 1, Human: 1,
		},
		Results: []policykit.PolicyResult{
			{
				RuleID: "CRA-AI-2.1", Name: "No known exploited vulnerabilities",
				CRAReference: "Annex I Part I.2(a)", Status: "FAIL", Severity: "critical",
				Evidence: map[string]any{"kev_matches": []any{"CVE-2024-3094"}},
			},
			{
				RuleID: "CRA-AI-1.1", Name: "SBOM exists and is valid",
				CRAReference: "Annex I Part II.1", Status: "PASS", Severity: "critical",
				Evidence: map[string]any{"component_count": float64(42)},
			},
			{
				RuleID: "CRA-AI-3.1", Name: "Build provenance exists (SLSA L1+)",
				CRAReference: "Art. 13", Status: "SKIP", Severity: "high",
				Evidence: map[string]any{"reason": "No provenance attestation provided (--provenance flag)"},
			},
			{
				RuleID: "CRA-HU-1.1", Name: "Appropriate cybersecurity level",
				CRAReference: "Annex I Part I.1", Status: "HUMAN", Severity: "high",
				Guidance: "Verify risk assessment performed.",
			},
		},
	}

	md := policykit.RenderMarkdown(&report)

	assert.Contains(t, md, "# CRA PolicyKit Compliance Report")
	assert.Contains(t, md, "policykit-2026-04-04T10:30:00Z")
	assert.Contains(t, md, "| PASS")
	assert.Contains(t, md, "| FAIL")
	assert.Contains(t, md, "FAIL: CRA-AI-2.1")
	assert.Contains(t, md, "PASS: CRA-AI-1.1")
	assert.Contains(t, md, "SKIP: CRA-AI-3.1")
	assert.Contains(t, md, "## Requires Human Review")
	assert.Contains(t, md, "CRA-HU-1.1")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -race -count=1 -run TestReport_RenderMarkdown ./pkg/policykit/...`
Expected: FAIL — `RenderMarkdown` not defined

- [ ] **Step 3: Implement markdown renderer**

Add to `pkg/policykit/report.go`:

```go
import (
	"encoding/json"
	"fmt"
	"strings"
)

// RenderMarkdown produces a human-readable markdown report for auditors.
func RenderMarkdown(r *Report) string {
	var b strings.Builder

	b.WriteString("# CRA PolicyKit Compliance Report\n\n")
	b.WriteString(fmt.Sprintf("**Report ID:** %s\n", r.ReportID))
	b.WriteString(fmt.Sprintf("**Generated:** %s\n", r.Timestamp))
	b.WriteString(fmt.Sprintf("**Toolkit Version:** %s\n\n", r.ToolkitVersion))

	// Summary table
	b.WriteString("## Summary\n\n")
	b.WriteString("| Status | Count |\n|--------|-------|\n")
	b.WriteString(fmt.Sprintf("| PASS   | %d     |\n", r.Summary.Passed))
	b.WriteString(fmt.Sprintf("| FAIL   | %d     |\n", r.Summary.Failed))
	b.WriteString(fmt.Sprintf("| SKIP   | %d     |\n", r.Summary.Skipped))
	b.WriteString(fmt.Sprintf("| HUMAN  | %d     |\n\n", r.Summary.Human))

	// Machine-checked: FAIL first, then PASS, then SKIP
	b.WriteString("## Machine-Checked Policies\n\n")
	for _, status := range []string{"FAIL", "PASS", "SKIP"} {
		for i := range r.Results {
			res := &r.Results[i]
			if res.Status != status {
				continue
			}
			b.WriteString(fmt.Sprintf("### %s: %s — %s\n", res.Status, res.RuleID, res.Name))
			b.WriteString(fmt.Sprintf("**CRA Reference:** %s | **Severity:** %s\n\n", res.CRAReference, strings.Title(res.Severity))) //nolint:staticcheck // strings.Title is fine for single words
			if len(res.Evidence) > 0 {
				for k, v := range res.Evidence {
					b.WriteString(fmt.Sprintf("- **%s:** %v\n", k, v))
				}
				b.WriteString("\n")
			}
		}
	}

	// Human review
	var humanResults []PolicyResult
	for i := range r.Results {
		if r.Results[i].Status == "HUMAN" {
			humanResults = append(humanResults, r.Results[i])
		}
	}
	if len(humanResults) > 0 {
		b.WriteString("## Requires Human Review\n\n")
		for i := range humanResults {
			res := &humanResults[i]
			b.WriteString(fmt.Sprintf("### %s — %s\n", res.RuleID, res.Name))
			b.WriteString(fmt.Sprintf("**CRA Reference:** %s | **Severity:** %s\n\n", res.CRAReference, strings.Title(res.Severity))) //nolint:staticcheck
			if res.Guidance != "" {
				b.WriteString(res.Guidance + "\n\n")
			}
		}
	}

	return b.String()
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -race -count=1 -run TestReport ./pkg/policykit/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/policykit/report.go pkg/policykit/report_test.go
git commit -m "feat(policykit): add markdown report renderer"
```

---

### Task 3: KEV catalog fetching and parsing

**Files:**
- Create: `pkg/policykit/kev.go`
- Create: `pkg/policykit/kev_test.go`
- Create: `testdata/policykit/kev-snapshot.json`

- [ ] **Step 1: Download a real CISA KEV snapshot for test data**

Run:
```bash
curl -sL "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
# Keep only first 20 entries + ensure CVE-2024-3094 is included
subset = data['vulnerabilities'][:20]
cve_ids = {v['cveID'] for v in subset}
if 'CVE-2024-3094' not in cve_ids:
    for v in data['vulnerabilities']:
        if v['cveID'] == 'CVE-2024-3094':
            subset.append(v)
            break
data['vulnerabilities'] = subset
json.dump(data, sys.stdout, indent=2)
" > testdata/policykit/kev-snapshot.json
```

This creates a real KEV subset containing CVE-2024-3094 (xz-utils backdoor) for testing.

- [ ] **Step 2: Write the failing test for KEV parsing**

Create `pkg/policykit/kev_test.go`:

```go
package policykit_test

import (
	"os"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/policykit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseKEV_RealSnapshot(t *testing.T) {
	f, err := os.Open("../../testdata/policykit/kev-snapshot.json")
	require.NoError(t, err)
	defer f.Close()

	catalog, err := policykit.ParseKEV(f)
	require.NoError(t, err)

	assert.NotEmpty(t, catalog.CatalogDate)
	assert.NotEmpty(t, catalog.CVEs)
	assert.True(t, catalog.Contains("CVE-2024-3094"), "KEV snapshot must contain CVE-2024-3094 (xz-utils)")
	assert.False(t, catalog.Contains("CVE-9999-99999"), "non-existent CVE must not match")
}

func TestParseKEV_MalformedJSON(t *testing.T) {
	f, err := os.CreateTemp("", "kev-bad-*.json")
	require.NoError(t, err)
	defer os.Remove(f.Name())
	_, _ = f.WriteString(`{"not": "a kev catalog"}`)
	f.Seek(0, 0)

	catalog, err := policykit.ParseKEV(f)
	require.NoError(t, err)
	assert.Empty(t, catalog.CVEs)
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test -race -count=1 -run TestParseKEV ./pkg/policykit/...`
Expected: FAIL — `ParseKEV` not defined

- [ ] **Step 4: Implement KEV parsing**

Create `pkg/policykit/kev.go`:

```go
package policykit

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	kevURL      = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	kevCacheTTL = 24 * time.Hour
)

// KEVCatalog holds parsed CISA KEV data for O(1) CVE lookup.
type KEVCatalog struct {
	CatalogDate string
	CVEs        map[string]bool
}

// Contains checks if a CVE ID is in the KEV catalog.
func (k *KEVCatalog) Contains(cve string) bool {
	return k.CVEs[cve]
}

// MatchFindings returns all CVE IDs from cves that appear in the KEV catalog.
func (k *KEVCatalog) MatchFindings(cves []string) []string {
	var matches []string
	for _, cve := range cves {
		if k.CVEs[cve] {
			matches = append(matches, cve)
		}
	}
	return matches
}

// ParseKEV parses a CISA KEV JSON catalog from a reader.
func ParseKEV(r io.Reader) (*KEVCatalog, error) {
	var raw struct {
		CatalogVersion  string `json:"catalogVersion"`
		DateReleased    string `json:"dateReleased"`
		Vulnerabilities []struct {
			CveID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		return nil, fmt.Errorf("kev: decode JSON: %w", err)
	}

	catalog := &KEVCatalog{
		CatalogDate: raw.DateReleased,
		CVEs:        make(map[string]bool, len(raw.Vulnerabilities)),
	}
	for _, v := range raw.Vulnerabilities {
		catalog.CVEs[v.CveID] = true
	}
	return catalog, nil
}

// LoadKEV loads the KEV catalog from a local file override, cache, or network fetch.
func LoadKEV(localPath string) (*KEVCatalog, error) {
	if localPath != "" {
		f, err := os.Open(localPath) //nolint:gosec // CLI flag path
		if err != nil {
			return nil, fmt.Errorf("kev: open local file: %w", err)
		}
		defer f.Close() //nolint:errcheck
		return ParseKEV(f)
	}

	// Try cache
	cachePath := kevCachePath()
	if info, err := os.Stat(cachePath); err == nil {
		if time.Since(info.ModTime()) < kevCacheTTL {
			f, err := os.Open(cachePath) //nolint:gosec
			if err == nil {
				defer f.Close() //nolint:errcheck
				return ParseKEV(f)
			}
		}
	}

	// Fetch from network
	resp, err := http.Get(kevURL) //nolint:gosec,noctx // well-known URL
	if err != nil {
		return nil, fmt.Errorf("kev: fetch from CISA: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kev: CISA returned HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("kev: read response: %w", err)
	}

	// Cache it
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err == nil {
		_ = os.WriteFile(cachePath, data, 0o644) //nolint:gosec
	}

	return ParseKEV(bytes.NewReader(data))
}

func kevCachePath() string {
	cacheDir := os.Getenv("XDG_CACHE_HOME")
	if cacheDir == "" {
		home, _ := os.UserHomeDir()
		cacheDir = filepath.Join(home, ".cache")
	}
	return filepath.Join(cacheDir, "suse-cra-toolkit", "kev.json")
}
```

Add `"bytes"` to the import block.

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test -race -count=1 -run TestParseKEV ./pkg/policykit/...`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add pkg/policykit/kev.go pkg/policykit/kev_test.go testdata/policykit/kev-snapshot.json
git commit -m "feat(policykit): add CISA KEV catalog fetching and parsing"
```

---

### Task 4: Provenance and signature parsing

**Files:**
- Create: `pkg/policykit/provenance.go`
- Create: `pkg/policykit/provenance_test.go`
- Create: `pkg/policykit/signature.go`
- Create: `pkg/policykit/signature_test.go`
- Create: `testdata/policykit/slsa-provenance-v1.json`
- Create: `testdata/policykit/cosign-bundle.json`

- [ ] **Step 1: Create real test fixtures**

Create `testdata/policykit/slsa-provenance-v1.json` — a real SLSA v1.0 provenance attestation (based on public GitHub Actions SLSA provenance format):

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "my-product",
      "digest": { "sha256": "abc123def456" }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://actions.github.io/buildtypes/workflow/v1",
      "externalParameters": {
        "workflow": {
          "ref": "refs/heads/main",
          "repository": "https://github.com/acme/my-product"
        }
      }
    },
    "runDetails": {
      "builder": {
        "id": "https://github.com/actions/runner"
      }
    }
  }
}
```

Create `testdata/policykit/cosign-bundle.json` — a minimal cosign bundle structure:

```json
{
  "mediaType": "application/vnd.dev.cosign.bundle.v0.3+json",
  "verificationMaterial": {
    "publicKey": {
      "hint": "test-key-id"
    }
  },
  "messageSignature": {
    "messageDigest": {
      "algorithm": "SHA2_256",
      "digest": "YWJjMTIzZGVmNDU2"
    },
    "signature": "MEUCIQD..."
  }
}
```

- [ ] **Step 2: Write failing tests for provenance parsing**

Create `pkg/policykit/provenance_test.go`:

```go
package policykit_test

import (
	"os"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/policykit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseProvenance_SLSA_V1(t *testing.T) {
	f, err := os.Open("../../testdata/policykit/slsa-provenance-v1.json")
	require.NoError(t, err)
	defer f.Close()

	prov, err := policykit.ParseProvenance(f)
	require.NoError(t, err)

	assert.True(t, prov.Exists)
	assert.Equal(t, "https://github.com/actions/runner", prov.BuilderID)
	assert.Equal(t, "https://github.com/acme/my-product", prov.SourceRepo)
	assert.Contains(t, prov.BuildType, "slsa.dev/provenance")
}

func TestParseProvenance_InvalidJSON(t *testing.T) {
	f, err := os.CreateTemp("", "prov-bad-*.json")
	require.NoError(t, err)
	defer os.Remove(f.Name())
	_, _ = f.WriteString(`not json`)
	f.Seek(0, 0)

	_, err = policykit.ParseProvenance(f)
	assert.Error(t, err)
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test -race -count=1 -run TestParseProvenance ./pkg/policykit/...`
Expected: FAIL

- [ ] **Step 4: Implement provenance parsing**

Create `pkg/policykit/provenance.go`:

```go
package policykit

import (
	"encoding/json"
	"fmt"
	"io"
)

// Provenance holds parsed SLSA provenance attestation data.
type Provenance struct {
	Exists     bool   `json:"exists"`
	BuilderID  string `json:"builder_id,omitempty"`
	SourceRepo string `json:"source_repo,omitempty"`
	BuildType  string `json:"build_type,omitempty"`
}

// ParseProvenance parses a SLSA provenance attestation (v0.2 or v1.0).
func ParseProvenance(r io.Reader) (*Provenance, error) {
	var raw struct {
		PredicateType string `json:"predicateType"`
		Predicate     struct {
			// SLSA v1.0
			BuildDefinition struct {
				BuildType          string `json:"buildType"`
				ExternalParameters struct {
					Workflow struct {
						Repository string `json:"repository"`
					} `json:"workflow"`
				} `json:"externalParameters"`
			} `json:"buildDefinition"`
			RunDetails struct {
				Builder struct {
					ID string `json:"id"`
				} `json:"builder"`
			} `json:"runDetails"`
			// SLSA v0.2
			Builder struct {
				ID string `json:"id"`
			} `json:"builder"`
			Invocation struct {
				ConfigSource struct {
					URI string `json:"uri"`
				} `json:"configSource"`
			} `json:"invocation"`
			BuildType string `json:"buildType"`
		} `json:"predicate"`
	}

	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		return nil, fmt.Errorf("provenance: decode JSON: %w", err)
	}

	prov := &Provenance{Exists: true}

	// Detect version and extract fields
	if raw.PredicateType == "https://slsa.dev/provenance/v1" {
		prov.BuildType = raw.PredicateType
		prov.BuilderID = raw.Predicate.RunDetails.Builder.ID
		prov.SourceRepo = raw.Predicate.BuildDefinition.ExternalParameters.Workflow.Repository
	} else {
		// v0.2 layout
		prov.BuildType = raw.Predicate.BuildType
		if prov.BuildType == "" {
			prov.BuildType = raw.PredicateType
		}
		prov.BuilderID = raw.Predicate.Builder.ID
		prov.SourceRepo = raw.Predicate.Invocation.ConfigSource.URI
	}

	return prov, nil
}
```

- [ ] **Step 5: Write failing tests for signature parsing**

Create `pkg/policykit/signature_test.go`:

```go
package policykit_test

import (
	"os"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/policykit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSignature_CosignBundle(t *testing.T) {
	f, err := os.Open("../../testdata/policykit/cosign-bundle.json")
	require.NoError(t, err)
	defer f.Close()

	sig, err := policykit.ParseSignature(f, "cosign-bundle.json")
	require.NoError(t, err)

	assert.Equal(t, "cosign-bundle.json", sig.Path)
	assert.Equal(t, "cosign", sig.Format)
}

func TestParseSignature_UnknownFormat(t *testing.T) {
	f, err := os.CreateTemp("", "sig-unknown-*.bin")
	require.NoError(t, err)
	defer os.Remove(f.Name())
	_, _ = f.WriteString(`random binary data`)
	f.Seek(0, 0)

	sig, err := policykit.ParseSignature(f, "unknown.bin")
	require.NoError(t, err)
	assert.Equal(t, "unknown", sig.Format)
}
```

- [ ] **Step 6: Implement signature parsing**

Create `pkg/policykit/signature.go`:

```go
package policykit

import (
	"encoding/json"
	"io"
)

// SignatureInfo holds parsed signature file metadata.
type SignatureInfo struct {
	Path   string `json:"path"`
	Format string `json:"format"` // "cosign", "pgp", "x509", "unknown"
}

// ParseSignature detects the format of a signature file.
func ParseSignature(r io.Reader, filename string) (*SignatureInfo, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return &SignatureInfo{Path: filename, Format: "unknown"}, nil //nolint:nilerr // best effort
	}

	sig := &SignatureInfo{Path: filename}

	// Try cosign bundle detection
	var cosign struct {
		MediaType string `json:"mediaType"`
	}
	if json.Unmarshal(data, &cosign) == nil && cosign.MediaType != "" {
		if contains(cosign.MediaType, "cosign") || contains(cosign.MediaType, "sigstore") {
			sig.Format = "cosign"
			return sig, nil
		}
	}

	// PGP signature detection (binary or armored)
	if len(data) > 0 && (data[0] == 0x89 || data[0] == 0xc0 || // binary PGP
		(len(data) > 27 && string(data[:27]) == "-----BEGIN PGP SIGNATURE--")) {
		sig.Format = "pgp"
		return sig, nil
	}

	// x509 / PEM certificate
	if len(data) > 11 && string(data[:11]) == "-----BEGIN " {
		sig.Format = "x509"
		return sig, nil
	}

	sig.Format = "unknown"
	return sig, nil
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && stringContains(s, substr))
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
```

- [ ] **Step 7: Run all tests to verify they pass**

Run: `go test -race -count=1 -run "TestParseProvenance|TestParseSignature" ./pkg/policykit/...`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add pkg/policykit/provenance.go pkg/policykit/provenance_test.go \
       pkg/policykit/signature.go pkg/policykit/signature_test.go \
       testdata/policykit/slsa-provenance-v1.json testdata/policykit/cosign-bundle.json
git commit -m "feat(policykit): add provenance and signature parsing"
```

---

### Task 5: Input document assembly

**Files:**
- Create: `pkg/policykit/input.go`
- Create: `pkg/policykit/input_test.go`

- [ ] **Step 1: Write the failing test for input document assembly**

Create `pkg/policykit/input_test.go`:

```go
package policykit_test

import (
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
	"github.com/ravan/suse-cra-toolkit/pkg/policykit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildInput_FullArtifacts(t *testing.T) {
	artifacts := &policykit.ParsedArtifacts{
		Components: []formats.Component{
			{Name: "golang.org/x/text", Version: "v0.3.7", PURL: "pkg:golang/golang.org/x/text@v0.3.7", Type: "golang", Supplier: "Go Authors"},
			{Name: "example.com/nopurl", Version: "1.0.0"},
		},
		SBOMFormat:  "cyclonedx",
		SBOMVersion: "1.6",
		SBOMName:    "my-product",
		SBOMVersionField: "2.1.0",
		SBOMSupplier: "ACME Corp",
		Findings: []formats.Finding{
			{CVE: "CVE-2022-32149", AffectedPURL: "pkg:golang/golang.org/x/text@v0.3.7", CVSS: 7.5, Severity: "HIGH", FixVersion: "0.3.8"},
		},
		VEXResults: []formats.VEXResult{
			{CVE: "CVE-2022-32149", ComponentPURL: "pkg:golang/golang.org/x/text@v0.3.7", Status: "not_affected", Justification: "vulnerable_code_not_present"},
		},
		KEV: &policykit.KEVCatalog{CatalogDate: "2026-04-03", CVEs: map[string]bool{"CVE-2024-3094": true}},
		Provenance: &policykit.Provenance{Exists: true, BuilderID: "https://github.com/actions/runner", SourceRepo: "https://github.com/acme/my-product", BuildType: "https://slsa.dev/provenance/v1"},
		Signatures: []policykit.SignatureInfo{{Path: "my-product.sig", Format: "cosign"}},
		Product: &policykit.ProductConfig{
			Exists: true, Name: "my-product", Version: "2.1.0",
			ReleaseDate: "2025-06-01", SupportEndDate: "2031-06-01", SupportYears: 6,
			UpdateMechanism: policykit.UpdateMechanism{Type: "automatic", URL: "https://updates.example.com", AutoUpdateDefault: true, SecurityUpdatesSeparate: true},
		},
	}

	input := policykit.BuildInput(artifacts)
	require.NotNil(t, input)

	sbom, ok := input["sbom"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "cyclonedx", sbom["format"])

	components, ok := sbom["components"].([]map[string]any)
	require.True(t, ok)
	assert.Len(t, components, 2)
	assert.Equal(t, "pkg:golang/golang.org/x/text@v0.3.7", components[0]["purl"])

	scan, ok := input["scan"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, 1, scan["critical_high_count"])

	kev, ok := input["kev"].(map[string]any)
	require.True(t, ok)
	kevCVEs, ok := kev["cves"].([]string)
	require.True(t, ok)
	assert.Contains(t, kevCVEs, "CVE-2024-3094")

	prov, ok := input["provenance"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, true, prov["exists"])
}

func TestBuildInput_MissingOptionalArtifacts(t *testing.T) {
	artifacts := &policykit.ParsedArtifacts{
		Components:  []formats.Component{{Name: "foo", Version: "1.0", PURL: "pkg:npm/foo@1.0"}},
		SBOMFormat:  "cyclonedx",
		SBOMVersion: "1.6",
		SBOMName:    "test",
		SBOMVersionField: "1.0",
		Findings:    []formats.Finding{},
		VEXResults:  []formats.VEXResult{},
		KEV:         &policykit.KEVCatalog{CVEs: map[string]bool{}},
	}

	input := policykit.BuildInput(artifacts)

	prov, ok := input["provenance"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, false, prov["exists"])

	sigs, ok := input["signatures"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, false, sigs["exists"])

	product, ok := input["product"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, false, product["exists"])
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -race -count=1 -run TestBuildInput ./pkg/policykit/...`
Expected: FAIL

- [ ] **Step 3: Implement input document assembly and product config types**

Create `pkg/policykit/input.go`:

```go
package policykit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
	"gopkg.in/yaml.v3"
)

// ParsedArtifacts holds all artifacts parsed from CLI inputs.
type ParsedArtifacts struct {
	Components       []formats.Component
	SBOMFormat       string
	SBOMVersion      string
	SBOMName         string
	SBOMVersionField string
	SBOMSupplier     string
	Findings         []formats.Finding
	VEXResults       []formats.VEXResult
	KEV              *KEVCatalog
	Provenance       *Provenance
	Signatures       []SignatureInfo
	Product          *ProductConfig
}

// ProductConfig holds product metadata from --product-config.
type ProductConfig struct {
	Exists                 bool            `json:"exists"`
	Name                   string          `json:"name,omitempty"`
	Version                string          `json:"version,omitempty"`
	ReleaseDate            string          `json:"release_date,omitempty"`
	SupportEndDate         string          `json:"support_end_date,omitempty"`
	SupportYears           int             `json:"support_years,omitempty"`
	UpdateMechanism        UpdateMechanism `json:"update_mechanism,omitempty"`
}

// UpdateMechanism describes the product's update mechanism.
type UpdateMechanism struct {
	Type                   string `json:"type,omitempty"`
	URL                    string `json:"url,omitempty"`
	AutoUpdateDefault      bool   `json:"auto_update_default,omitempty"`
	SecurityUpdatesSeparate bool  `json:"security_updates_separate,omitempty"`
}

// LoadProductConfig parses a YAML or JSON product config file.
func LoadProductConfig(path string) (*ProductConfig, error) {
	data, err := os.ReadFile(path) //nolint:gosec // CLI flag path
	if err != nil {
		return nil, fmt.Errorf("product config: read: %w", err)
	}

	// Try YAML first (also handles JSON since JSON is valid YAML)
	var raw struct {
		Product struct {
			Name           string `yaml:"name" json:"name"`
			Version        string `yaml:"version" json:"version"`
			ReleaseDate    string `yaml:"release_date" json:"release_date"`
			SupportEndDate string `yaml:"support_end_date" json:"support_end_date"`
			UpdateMechanism struct {
				Type                    string `yaml:"type" json:"type"`
				URL                     string `yaml:"url" json:"url"`
				AutoUpdateDefault       bool   `yaml:"auto_update_default" json:"auto_update_default"`
				SecurityUpdatesSeparate bool   `yaml:"security_updates_separate" json:"security_updates_separate"`
			} `yaml:"update_mechanism" json:"update_mechanism"`
		} `yaml:"product" json:"product"`
	}

	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("product config: parse: %w", err)
	}

	pc := &ProductConfig{
		Exists:         true,
		Name:           raw.Product.Name,
		Version:        raw.Product.Version,
		ReleaseDate:    raw.Product.ReleaseDate,
		SupportEndDate: raw.Product.SupportEndDate,
		UpdateMechanism: UpdateMechanism{
			Type:                    raw.Product.UpdateMechanism.Type,
			URL:                     raw.Product.UpdateMechanism.URL,
			AutoUpdateDefault:       raw.Product.UpdateMechanism.AutoUpdateDefault,
			SecurityUpdatesSeparate: raw.Product.UpdateMechanism.SecurityUpdatesSeparate,
		},
	}

	// Compute support years
	if pc.ReleaseDate != "" && pc.SupportEndDate != "" {
		start, err1 := time.Parse("2006-01-02", pc.ReleaseDate)
		end, err2 := time.Parse("2006-01-02", pc.SupportEndDate)
		if err1 == nil && err2 == nil {
			pc.SupportYears = int(end.Sub(start).Hours() / 24 / 365)
		}
	}

	return pc, nil
}

// BuildInput assembles the unified OPA input document from parsed artifacts.
func BuildInput(a *ParsedArtifacts) map[string]any {
	input := make(map[string]any)

	// SBOM section
	components := make([]map[string]any, 0, len(a.Components))
	for i := range a.Components {
		c := &a.Components[i]
		components = append(components, map[string]any{
			"name":    c.Name,
			"version": c.Version,
			"purl":    c.PURL,
			"type":    c.Type,
		})
	}
	input["sbom"] = map[string]any{
		"format":  a.SBOMFormat,
		"version": a.SBOMVersion,
		"metadata": map[string]any{
			"name":     a.SBOMName,
			"version":  a.SBOMVersionField,
			"supplier": a.SBOMSupplier,
		},
		"components": components,
	}

	// Scan section
	var critHighCount int
	findings := make([]map[string]any, 0, len(a.Findings))
	for i := range a.Findings {
		f := &a.Findings[i]
		findings = append(findings, map[string]any{
			"cve":         f.CVE,
			"purl":        f.AffectedPURL,
			"cvss":        f.CVSS,
			"severity":    strings.ToUpper(f.Severity),
			"fix_version": f.FixVersion,
		})
		if f.CVSS >= 7.0 {
			critHighCount++
		}
	}
	input["scan"] = map[string]any{
		"findings":           findings,
		"critical_high_count": critHighCount,
	}

	// VEX section
	statements := make([]map[string]any, 0, len(a.VEXResults))
	for i := range a.VEXResults {
		vr := &a.VEXResults[i]
		statements = append(statements, map[string]any{
			"cve":           vr.CVE,
			"purl":          vr.ComponentPURL,
			"status":        string(vr.Status),
			"justification": string(vr.Justification),
		})
	}
	input["vex"] = map[string]any{"statements": statements}

	// KEV section
	kevCVEs := make([]string, 0)
	catalogDate := ""
	if a.KEV != nil {
		catalogDate = a.KEV.CatalogDate
		for cve := range a.KEV.CVEs {
			kevCVEs = append(kevCVEs, cve)
		}
	}
	input["kev"] = map[string]any{"catalog_date": catalogDate, "cves": kevCVEs}

	// Provenance section
	if a.Provenance != nil && a.Provenance.Exists {
		input["provenance"] = map[string]any{
			"exists":      true,
			"builder_id":  a.Provenance.BuilderID,
			"source_repo": a.Provenance.SourceRepo,
			"build_type":  a.Provenance.BuildType,
		}
	} else {
		input["provenance"] = map[string]any{"exists": false}
	}

	// Signatures section
	if len(a.Signatures) > 0 {
		files := make([]map[string]any, 0, len(a.Signatures))
		for i := range a.Signatures {
			files = append(files, map[string]any{
				"path":   a.Signatures[i].Path,
				"format": a.Signatures[i].Format,
			})
		}
		input["signatures"] = map[string]any{"exists": true, "files": files}
	} else {
		input["signatures"] = map[string]any{"exists": false}
	}

	// Product section
	if a.Product != nil && a.Product.Exists {
		input["product"] = map[string]any{
			"exists":           true,
			"name":             a.Product.Name,
			"version":          a.Product.Version,
			"release_date":     a.Product.ReleaseDate,
			"support_end_date": a.Product.SupportEndDate,
			"support_years":    a.Product.SupportYears,
			"update_mechanism": map[string]any{
				"type":                      a.Product.UpdateMechanism.Type,
				"url":                       a.Product.UpdateMechanism.URL,
				"auto_update_default":       a.Product.UpdateMechanism.AutoUpdateDefault,
				"security_updates_separate": a.Product.UpdateMechanism.SecurityUpdatesSeparate,
			},
		}
	} else {
		input["product"] = map[string]any{"exists": false}
	}

	return input
}
```

Note: Remove unused imports (`json`, `io` are not used in BuildInput — they are needed for `LoadProductConfig`). The compiler will tell you.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -race -count=1 -run TestBuildInput ./pkg/policykit/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/policykit/input.go pkg/policykit/input_test.go
git commit -m "feat(policykit): add input document assembly and product config parsing"
```

---

### Task 6: OPA engine — load and evaluate Rego policies

**Files:**
- Create: `pkg/policykit/engine.go`
- Create: `pkg/policykit/engine_test.go`

- [ ] **Step 1: Write a minimal test Rego policy for engine testing**

Create `testdata/policykit/test_policy.rego`:

```rego
package cra.test_policy

import rego.v1

default result := {
    "rule_id": "TEST-1",
    "name": "Test policy",
    "cra_reference": "Test",
    "status": "FAIL",
    "severity": "low",
    "evidence": {}
}

result := r if {
    input.test_value == true
    r := {
        "rule_id": "TEST-1",
        "name": "Test policy",
        "cra_reference": "Test",
        "status": "PASS",
        "severity": "low",
        "evidence": {"test_value": true}
    }
}
```

- [ ] **Step 2: Write the failing test for engine evaluation**

Create `pkg/policykit/engine_test.go`:

```go
package policykit_test

import (
	"context"
	"os"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/policykit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEngine_EvaluateSinglePolicy_Pass(t *testing.T) {
	policyData, err := os.ReadFile("../../testdata/policykit/test_policy.rego")
	require.NoError(t, err)

	engine, err := policykit.NewEngine(map[string]string{
		"test_policy.rego": string(policyData),
	})
	require.NoError(t, err)

	input := map[string]any{"test_value": true}
	results, err := engine.Evaluate(context.Background(), input)
	require.NoError(t, err)

	require.Len(t, results, 1)
	assert.Equal(t, "TEST-1", results[0].RuleID)
	assert.Equal(t, "PASS", results[0].Status)
}

func TestEngine_EvaluateSinglePolicy_Fail(t *testing.T) {
	policyData, err := os.ReadFile("../../testdata/policykit/test_policy.rego")
	require.NoError(t, err)

	engine, err := policykit.NewEngine(map[string]string{
		"test_policy.rego": string(policyData),
	})
	require.NoError(t, err)

	input := map[string]any{"test_value": false}
	results, err := engine.Evaluate(context.Background(), input)
	require.NoError(t, err)

	require.Len(t, results, 1)
	assert.Equal(t, "TEST-1", results[0].RuleID)
	assert.Equal(t, "FAIL", results[0].Status)
}

func TestEngine_MultiplePolicies(t *testing.T) {
	policy1 := `package cra.p1
import rego.v1
default result := {"rule_id": "P1", "name": "Policy 1", "cra_reference": "Test", "status": "PASS", "severity": "low", "evidence": {}}
`
	policy2 := `package cra.p2
import rego.v1
default result := {"rule_id": "P2", "name": "Policy 2", "cra_reference": "Test", "status": "FAIL", "severity": "high", "evidence": {}}
`
	engine, err := policykit.NewEngine(map[string]string{
		"p1.rego": policy1,
		"p2.rego": policy2,
	})
	require.NoError(t, err)

	results, err := engine.Evaluate(context.Background(), map[string]any{})
	require.NoError(t, err)

	assert.Len(t, results, 2)
	ruleIDs := map[string]string{}
	for _, r := range results {
		ruleIDs[r.RuleID] = r.Status
	}
	assert.Equal(t, "PASS", ruleIDs["P1"])
	assert.Equal(t, "FAIL", ruleIDs["P2"])
}

func TestEngine_DuplicateRuleID_Error(t *testing.T) {
	embedded := map[string]string{
		"p1.rego": `package cra.p1
import rego.v1
default result := {"rule_id": "DUPE-1", "name": "P1", "cra_reference": "T", "status": "PASS", "severity": "low", "evidence": {}}`,
	}
	custom := map[string]string{
		"custom.rego": `package cra.custom1
import rego.v1
default result := {"rule_id": "DUPE-1", "name": "Custom", "cra_reference": "T", "status": "PASS", "severity": "low", "evidence": {}}`,
	}

	engine, err := policykit.NewEngine(embedded)
	require.NoError(t, err)

	err = engine.AddCustomPolicies(custom)
	require.NoError(t, err)

	_, err = engine.Evaluate(context.Background(), map[string]any{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "DUPE-1")
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test -race -count=1 -run TestEngine ./pkg/policykit/...`
Expected: FAIL

- [ ] **Step 4: Implement the OPA engine**

Create `pkg/policykit/engine.go`:

```go
package policykit

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/open-policy-agent/opa/v1/rego"
)

// Engine wraps OPA policy evaluation.
type Engine struct {
	modules map[string]string // filename -> rego source
}

// NewEngine creates an engine with embedded policies.
func NewEngine(modules map[string]string) (*Engine, error) {
	return &Engine{modules: copyMap(modules)}, nil
}

// AddCustomPolicies loads additional policies from a directory.
func (e *Engine) AddCustomPolicies(modules map[string]string) error {
	for k, v := range modules {
		e.modules["custom/"+k] = v
	}
	return nil
}

// Evaluate runs all loaded policies against the input and returns results.
func (e *Engine) Evaluate(ctx context.Context, input map[string]any) ([]PolicyResult, error) {
	// Build rego options
	opts := []func(*rego.Rego){
		rego.Query("data.cra"),
	}
	for name, source := range e.modules {
		opts = append(opts, rego.Module(name, source))
	}

	prepared, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("engine: prepare: %w", err)
	}

	rs, err := prepared.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("engine: eval: %w", err)
	}

	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, nil
	}

	// rs[0].Expressions[0].Value is map[string]any keyed by package name
	topLevel, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("engine: unexpected result type %T", rs[0].Expressions[0].Value)
	}

	var results []PolicyResult
	seenRuleIDs := make(map[string]string) // rule_id -> package name

	// Iterate over packages in sorted order for determinism
	pkgNames := make([]string, 0, len(topLevel))
	for pkg := range topLevel {
		pkgNames = append(pkgNames, pkg)
	}
	sort.Strings(pkgNames)

	for _, pkg := range pkgNames {
		pkgData, ok := topLevel[pkg].(map[string]any)
		if !ok {
			continue
		}
		resultData, ok := pkgData["result"]
		if !ok {
			continue
		}

		// Convert to JSON and back to get PolicyResult
		jsonBytes, err := json.Marshal(resultData)
		if err != nil {
			continue
		}
		var pr PolicyResult
		if err := json.Unmarshal(jsonBytes, &pr); err != nil {
			continue
		}

		// Check for duplicate rule IDs
		if prevPkg, exists := seenRuleIDs[pr.RuleID]; exists {
			return nil, fmt.Errorf("engine: duplicate rule_id %q in packages %q and %q", pr.RuleID, prevPkg, pkg)
		}
		seenRuleIDs[pr.RuleID] = pkg

		results = append(results, pr)
	}

	return results, nil
}

func copyMap(m map[string]string) map[string]string {
	cp := make(map[string]string, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test -race -count=1 -run TestEngine ./pkg/policykit/...`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add pkg/policykit/engine.go pkg/policykit/engine_test.go testdata/policykit/test_policy.rego
git commit -m "feat(policykit): add OPA engine for policy evaluation"
```

---

### Task 7: Write all 7 Rego policies

**Files:**
- Create: `policies/cra_sbom_valid.rego`
- Create: `policies/cra_no_kev.rego`
- Create: `policies/cra_vex_coverage.rego`
- Create: `policies/cra_provenance.rego`
- Create: `policies/cra_signatures.rego`
- Create: `policies/cra_support_period.rego`
- Create: `policies/cra_update_mechanism.rego`
- Remove: `policies/.gitkeep`

- [ ] **Step 1: Write CRA-AI-1.1 SBOM validation policy**

Create `policies/cra_sbom_valid.rego`:

```rego
package cra.sbom_valid

import rego.v1

default result := {
	"rule_id": "CRA-AI-1.1",
	"name": "SBOM exists and is valid",
	"cra_reference": "Annex I Part II.1",
	"status": "FAIL",
	"severity": "critical",
	"evidence": {},
}

result := r if {
	input.sbom.format in {"cyclonedx", "spdx"}
	input.sbom.metadata.name != ""
	input.sbom.metadata.version != ""
	count(input.sbom.components) > 0
	purl_count := count([c | some c in input.sbom.components; c.purl != ""])

	r := {
		"rule_id": "CRA-AI-1.1",
		"name": "SBOM exists and is valid",
		"cra_reference": "Annex I Part II.1",
		"status": "PASS",
		"severity": "critical",
		"evidence": {
			"sbom_format": input.sbom.format,
			"sbom_version": input.sbom.version,
			"component_count": count(input.sbom.components),
			"components_with_purl": purl_count,
			"has_metadata": true,
			"has_supplier": input.sbom.metadata.supplier != "",
		},
	}
}
```

- [ ] **Step 2: Write CRA-AI-2.1 KEV cross-check policy**

Create `policies/cra_no_kev.rego`:

```rego
package cra.no_kev

import rego.v1

default result := {
	"rule_id": "CRA-AI-2.1",
	"name": "No known exploited vulnerabilities",
	"cra_reference": "Annex I Part I.2(a)",
	"status": "PASS",
	"severity": "critical",
	"evidence": {},
}

scan_cves := {f.cve | some f in input.scan.findings}

kev_set := {k | some k in input.kev.cves}

kev_matches := scan_cves & kev_set

result := r if {
	count(kev_matches) > 0
	r := {
		"rule_id": "CRA-AI-2.1",
		"name": "No known exploited vulnerabilities",
		"cra_reference": "Annex I Part I.2(a)",
		"status": "FAIL",
		"severity": "critical",
		"evidence": {
			"kev_matches": sort(kev_matches),
			"kev_catalog_date": input.kev.catalog_date,
			"total_cves_checked": count(scan_cves),
		},
	}
}
```

- [ ] **Step 3: Write CRA-AI-2.2 VEX coverage policy**

Create `policies/cra_vex_coverage.rego`:

```rego
package cra.vex_coverage

import rego.v1

critical_high_findings := [f | some f in input.scan.findings; f.cvss >= 7.0]

vex_lookup := {sprintf("%s|%s", [s.cve, s.purl]) | some s in input.vex.statements}

unassessed := [f.cve |
	some f in critical_high_findings
	not sprintf("%s|%s", [f.cve, f.purl]) in vex_lookup
]

default result := {
	"rule_id": "CRA-AI-2.2",
	"name": "All critical/high CVEs have VEX assessment",
	"cra_reference": "Annex I Part I.2(a)",
	"status": "FAIL",
	"severity": "high",
	"evidence": {},
}

result := r if {
	count(unassessed) == 0
	r := {
		"rule_id": "CRA-AI-2.2",
		"name": "All critical/high CVEs have VEX assessment",
		"cra_reference": "Annex I Part I.2(a)",
		"status": "PASS",
		"severity": "high",
		"evidence": {
			"total_critical_high": count(critical_high_findings),
			"assessed": count(critical_high_findings),
			"unassessed": [],
		},
	}
}

result := r if {
	count(unassessed) > 0
	r := {
		"rule_id": "CRA-AI-2.2",
		"name": "All critical/high CVEs have VEX assessment",
		"cra_reference": "Annex I Part I.2(a)",
		"status": "FAIL",
		"severity": "high",
		"evidence": {
			"total_critical_high": count(critical_high_findings),
			"assessed": count(critical_high_findings) - count(unassessed),
			"unassessed": unassessed,
		},
	}
}
```

- [ ] **Step 4: Write CRA-AI-3.1 provenance policy**

Create `policies/cra_provenance.rego`:

```rego
package cra.provenance

import rego.v1

default result := {
	"rule_id": "CRA-AI-3.1",
	"name": "Build provenance exists (SLSA L1+)",
	"cra_reference": "Art. 13",
	"status": "FAIL",
	"severity": "high",
	"evidence": {},
}

result := r if {
	not input.provenance.exists
	r := {
		"rule_id": "CRA-AI-3.1",
		"name": "Build provenance exists (SLSA L1+)",
		"cra_reference": "Art. 13",
		"status": "SKIP",
		"severity": "high",
		"evidence": {"reason": "No provenance attestation provided (--provenance flag)"},
	}
}

result := r if {
	input.provenance.exists
	input.provenance.builder_id != ""
	input.provenance.source_repo != ""
	input.provenance.build_type != ""
	r := {
		"rule_id": "CRA-AI-3.1",
		"name": "Build provenance exists (SLSA L1+)",
		"cra_reference": "Art. 13",
		"status": "PASS",
		"severity": "high",
		"evidence": {
			"builder_id": input.provenance.builder_id,
			"source_repo": input.provenance.source_repo,
			"build_type": input.provenance.build_type,
		},
	}
}
```

- [ ] **Step 5: Write CRA-AI-3.2 signatures policy**

Create `policies/cra_signatures.rego`:

```rego
package cra.signatures

import rego.v1

default result := {
	"rule_id": "CRA-AI-3.2",
	"name": "Artifacts cryptographically signed",
	"cra_reference": "Art. 13",
	"status": "FAIL",
	"severity": "high",
	"evidence": {},
}

result := r if {
	not input.signatures.exists
	r := {
		"rule_id": "CRA-AI-3.2",
		"name": "Artifacts cryptographically signed",
		"cra_reference": "Art. 13",
		"status": "SKIP",
		"severity": "high",
		"evidence": {"reason": "No signature files provided (--signature flag)"},
	}
}

result := r if {
	input.signatures.exists
	count(input.signatures.files) > 0
	formats := {f.format | some f in input.signatures.files}
	r := {
		"rule_id": "CRA-AI-3.2",
		"name": "Artifacts cryptographically signed",
		"cra_reference": "Art. 13",
		"status": "PASS",
		"severity": "high",
		"evidence": {
			"signature_count": count(input.signatures.files),
			"formats_detected": sort(formats),
		},
	}
}
```

- [ ] **Step 6: Write CRA-AI-4.1 support period policy**

Create `policies/cra_support_period.rego`:

```rego
package cra.support_period

import rego.v1

default result := {
	"rule_id": "CRA-AI-4.1",
	"name": "Support period declared and > 5 years",
	"cra_reference": "Annex I Part II",
	"status": "FAIL",
	"severity": "medium",
	"evidence": {},
}

result := r if {
	not input.product.exists
	r := {
		"rule_id": "CRA-AI-4.1",
		"name": "Support period declared and > 5 years",
		"cra_reference": "Annex I Part II",
		"status": "SKIP",
		"severity": "medium",
		"evidence": {"reason": "No product config provided (--product-config flag)"},
	}
}

result := r if {
	input.product.exists
	input.product.release_date != ""
	input.product.support_end_date != ""
	input.product.support_years >= 5
	r := {
		"rule_id": "CRA-AI-4.1",
		"name": "Support period declared and > 5 years",
		"cra_reference": "Annex I Part II",
		"status": "PASS",
		"severity": "medium",
		"evidence": {
			"release_date": input.product.release_date,
			"support_end_date": input.product.support_end_date,
			"support_years": input.product.support_years,
		},
	}
}
```

- [ ] **Step 7: Write CRA-AI-4.2 update mechanism policy**

Create `policies/cra_update_mechanism.rego`:

```rego
package cra.update_mechanism

import rego.v1

default result := {
	"rule_id": "CRA-AI-4.2",
	"name": "Secure update mechanism documented",
	"cra_reference": "Annex I Part II.7",
	"status": "FAIL",
	"severity": "medium",
	"evidence": {},
}

result := r if {
	not input.product.exists
	r := {
		"rule_id": "CRA-AI-4.2",
		"name": "Secure update mechanism documented",
		"cra_reference": "Annex I Part II.7",
		"status": "SKIP",
		"severity": "medium",
		"evidence": {"reason": "No product config provided (--product-config flag)"},
	}
}

valid_types := {"automatic", "manual", "hybrid"}

result := r if {
	input.product.exists
	input.product.update_mechanism.type in valid_types
	input.product.update_mechanism.url != ""
	r := {
		"rule_id": "CRA-AI-4.2",
		"name": "Secure update mechanism documented",
		"cra_reference": "Annex I Part II.7",
		"status": "PASS",
		"severity": "medium",
		"evidence": {
			"mechanism_type": input.product.update_mechanism.type,
			"url_present": true,
			"auto_update_default": input.product.update_mechanism.auto_update_default,
			"security_updates_separate": input.product.update_mechanism.security_updates_separate,
		},
	}
}
```

- [ ] **Step 8: Remove the old .gitkeep**

Run: `rm policies/.gitkeep`

- [ ] **Step 9: Verify Rego syntax compiles**

Run: `go run github.com/open-policy-agent/opa/v1/cmd/opa@latest check policies/`

If `opa` is not available, this step can be skipped — the engine tests in Task 6 already compile the policies.

- [ ] **Step 10: Commit**

```bash
git add policies/ && git rm --cached policies/.gitkeep 2>/dev/null; true
git add policies/*.rego
git commit -m "feat(policykit): add all 7 CRA Annex I Rego policies"
```

---

### Task 8: Human-flagged items and pipeline orchestration

**Files:**
- Create: `pkg/policykit/human.go`
- Modify: `pkg/policykit/policykit.go` (replace stub)

- [ ] **Step 1: Create human-flagged items**

Create `pkg/policykit/human.go`:

```go
package policykit

// HumanReviewItems returns the static list of CRA requirements that need human review.
func HumanReviewItems() []PolicyResult {
	return []PolicyResult{
		{RuleID: "CRA-HU-1.1", Name: "Appropriate cybersecurity level", CRAReference: "Annex I Part I.1", Status: "HUMAN", Severity: "high", Guidance: "Verify risk assessment performed and cybersecurity measures are proportionate to identified risks."},
		{RuleID: "CRA-HU-1.2", Name: "Secure by default configuration", CRAReference: "Annex I Part I.2(b)", Status: "HUMAN", Severity: "high", Guidance: "Verify product ships with secure defaults and users can reset to original state."},
		{RuleID: "CRA-HU-1.3", Name: "Access control mechanisms", CRAReference: "Annex I Part I.2(d)", Status: "HUMAN", Severity: "high", Guidance: "Verify authentication, identity, and access management systems protect against unauthorised access."},
		{RuleID: "CRA-HU-1.4", Name: "Data encryption at rest and in transit", CRAReference: "Annex I Part I.2(e)", Status: "HUMAN", Severity: "high", Guidance: "Verify confidentiality of stored, transmitted, and processed data using state of the art encryption."},
		{RuleID: "CRA-HU-1.5", Name: "Data integrity protection", CRAReference: "Annex I Part I.2(f)", Status: "HUMAN", Severity: "high", Guidance: "Verify integrity of stored, transmitted data, commands, programs, and configuration against unauthorised modification."},
		{RuleID: "CRA-HU-1.6", Name: "Data minimisation", CRAReference: "Annex I Part I.2(g)", Status: "HUMAN", Severity: "medium", Guidance: "Verify only adequate, relevant, and limited data is processed for the product's intended purpose."},
		{RuleID: "CRA-HU-1.7", Name: "Attack surface minimisation", CRAReference: "Annex I Part I.2(j)", Status: "HUMAN", Severity: "high", Guidance: "Verify product is designed to limit attack surfaces including external interfaces."},
		{RuleID: "CRA-HU-1.8", Name: "Risk assessment performed", CRAReference: "Art. 13(2)", Status: "HUMAN", Severity: "high", Guidance: "Verify cybersecurity risk assessment has been carried out and is documented."},
	}
}
```

- [ ] **Step 2: Implement the full pipeline in policykit.go**

Replace `pkg/policykit/policykit.go` entirely:

```go
// Package policykit implements CRA Annex I policy evaluation using embedded OPA/Rego policies.
// It evaluates SBOM, VEX, and provenance artifacts against machine-checkable CRA rules.
package policykit

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
	"github.com/ravan/suse-cra-toolkit/pkg/formats/csafvex"
	"github.com/ravan/suse-cra-toolkit/pkg/formats/cyclonedx"
	"github.com/ravan/suse-cra-toolkit/pkg/formats/grype"
	"github.com/ravan/suse-cra-toolkit/pkg/formats/openvex"
	"github.com/ravan/suse-cra-toolkit/pkg/formats/sarif"
	"github.com/ravan/suse-cra-toolkit/pkg/formats/spdx"
	"github.com/ravan/suse-cra-toolkit/pkg/formats/trivy"
)

//go:embed ../../policies/*.rego
var embeddedPolicies embed.FS

// Options configures a policykit evaluation run.
type Options struct {
	SBOMPath       string
	ScanPaths      []string
	VEXPath        string
	ProvenancePath string
	SignaturePaths []string
	ProductConfig  string
	KEVPath        string
	PolicyDir      string
	OutputFormat   string // "json" or "markdown"
}

// Run executes the CRA policy evaluation pipeline.
func Run(opts *Options, out io.Writer) error { //nolint:gocognit,gocyclo // pipeline has many sequential stages
	ctx := context.Background()

	// Stage 1: Parse artifacts
	artifacts, err := parseArtifacts(opts)
	if err != nil {
		return err
	}

	// Stage 2: Fetch KEV
	kev, err := LoadKEV(opts.KEVPath)
	if err != nil {
		return fmt.Errorf("load KEV: %w", err)
	}
	artifacts.KEV = kev

	// Stage 3: Build input
	input := BuildInput(artifacts)

	// Stage 4: Evaluate policies
	embeddedModules, err := loadEmbeddedPolicies()
	if err != nil {
		return fmt.Errorf("load embedded policies: %w", err)
	}

	engine, err := NewEngine(embeddedModules)
	if err != nil {
		return fmt.Errorf("create engine: %w", err)
	}

	if opts.PolicyDir != "" {
		customModules, err := loadPoliciesFromDir(opts.PolicyDir)
		if err != nil {
			return fmt.Errorf("load custom policies: %w", err)
		}
		if err := engine.AddCustomPolicies(customModules); err != nil {
			return err
		}
	}

	machineResults, err := engine.Evaluate(ctx, input)
	if err != nil {
		return fmt.Errorf("evaluate policies: %w", err)
	}

	// Stage 5: Assemble report
	allResults := append(machineResults, HumanReviewItems()...)

	report := &Report{
		ReportID:       fmt.Sprintf("policykit-%s", time.Now().UTC().Format(time.RFC3339)),
		ToolkitVersion: "0.1.0",
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Summary:        ComputeSummary(allResults),
		Results:        allResults,
	}

	format := opts.OutputFormat
	if format == "" {
		format = "json"
	}

	switch format {
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	case "markdown":
		_, err := io.WriteString(out, RenderMarkdown(report))
		return err
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}

func parseArtifacts(opts *Options) (*ParsedArtifacts, error) {
	a := &ParsedArtifacts{}

	// Parse SBOM
	components, sbomFormat, sbomMeta, err := parseSBOMWithMeta(opts.SBOMPath)
	if err != nil {
		return nil, fmt.Errorf("parse SBOM: %w", err)
	}
	a.Components = components
	a.SBOMFormat = sbomFormat
	a.SBOMName = sbomMeta.name
	a.SBOMVersionField = sbomMeta.version
	a.SBOMVersion = sbomMeta.specVersion
	a.SBOMSupplier = sbomMeta.supplier

	// Parse scan results
	for _, path := range opts.ScanPaths {
		findings, err := parseScan(path)
		if err != nil {
			return nil, fmt.Errorf("parse scan %s: %w", path, err)
		}
		a.Findings = append(a.Findings, findings...)
	}

	// Parse VEX
	if opts.VEXPath != "" {
		vr, err := parseVEXResults(opts.VEXPath)
		if err != nil {
			return nil, fmt.Errorf("parse VEX %s: %w", opts.VEXPath, err)
		}
		a.VEXResults = vr
	}

	// Parse provenance (optional)
	if opts.ProvenancePath != "" {
		f, err := os.Open(opts.ProvenancePath) //nolint:gosec
		if err != nil {
			return nil, fmt.Errorf("open provenance: %w", err)
		}
		defer f.Close() //nolint:errcheck
		prov, err := ParseProvenance(f)
		if err != nil {
			return nil, fmt.Errorf("parse provenance: %w", err)
		}
		a.Provenance = prov
	}

	// Parse signatures (optional)
	for _, path := range opts.SignaturePaths {
		f, err := os.Open(path) //nolint:gosec
		if err != nil {
			return nil, fmt.Errorf("open signature %s: %w", path, err)
		}
		sig, err := ParseSignature(f, filepath.Base(path))
		f.Close() //nolint:errcheck
		if err != nil {
			return nil, fmt.Errorf("parse signature %s: %w", path, err)
		}
		a.Signatures = append(a.Signatures, *sig)
	}

	// Parse product config (optional)
	if opts.ProductConfig != "" {
		pc, err := LoadProductConfig(opts.ProductConfig)
		if err != nil {
			return nil, fmt.Errorf("parse product config: %w", err)
		}
		a.Product = pc
	}

	return a, nil
}

type sbomMeta struct {
	name        string
	version     string
	specVersion string
	supplier    string
}

func parseSBOMWithMeta(path string) ([]formats.Component, string, sbomMeta, error) {
	format, f, err := openDetected(path)
	if err != nil {
		return nil, "", sbomMeta{}, err
	}
	defer f.Close() //nolint:errcheck

	var components []formats.Component
	meta := sbomMeta{}

	switch format {
	case formats.FormatCycloneDX:
		components, err = cyclonedx.Parser{}.Parse(f)
		meta.specVersion = "1.6" // CycloneDX default
		formatStr := "cyclonedx"
		if err != nil {
			return nil, formatStr, meta, err
		}
		// Re-read for metadata extraction
		extractCycloneDXMeta(path, &meta)
		return components, formatStr, meta, nil
	case formats.FormatSPDX:
		components, err = spdx.Parser{}.Parse(f)
		return components, "spdx", meta, err
	default:
		return nil, "", meta, fmt.Errorf("unsupported SBOM format: %s", format)
	}
}

func extractCycloneDXMeta(path string, meta *sbomMeta) {
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return
	}
	var raw struct {
		SpecVersion string `json:"specVersion"`
		Metadata    struct {
			Component struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"component"`
			Supplier struct {
				Name string `json:"name"`
			} `json:"supplier"`
		} `json:"metadata"`
	}
	if json.Unmarshal(data, &raw) == nil {
		if raw.SpecVersion != "" {
			meta.specVersion = raw.SpecVersion
		}
		meta.name = raw.Metadata.Component.Name
		meta.version = raw.Metadata.Component.Version
		meta.supplier = raw.Metadata.Supplier.Name
	}
}

func openDetected(path string) (formats.Format, *os.File, error) {
	df, err := os.Open(path) //nolint:gosec
	if err != nil {
		return formats.FormatUnknown, nil, fmt.Errorf("open for detection: %w", err)
	}
	format, err := formats.DetectFormat(df)
	_ = df.Close()
	if err != nil {
		return formats.FormatUnknown, nil, fmt.Errorf("detect format: %w", err)
	}
	pf, err := os.Open(path) //nolint:gosec
	if err != nil {
		return formats.FormatUnknown, nil, fmt.Errorf("open for parsing: %w", err)
	}
	return format, pf, nil
}

func parseScan(path string) ([]formats.Finding, error) {
	format, f, err := openDetected(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck
	switch format {
	case formats.FormatGrype:
		return grype.Parser{}.Parse(f)
	case formats.FormatTrivy:
		return trivy.Parser{}.Parse(f)
	case formats.FormatSARIF:
		return sarif.Parser{}.Parse(f)
	default:
		return nil, fmt.Errorf("unsupported scan format: %s", format)
	}
}

func parseVEXResults(path string) ([]formats.VEXResult, error) {
	format, f, err := openDetected(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck

	var stmts []formats.VEXStatement
	switch format {
	case formats.FormatOpenVEX:
		stmts, err = openvex.Parser{}.Parse(f)
	case formats.FormatCSAF:
		stmts, err = csafvex.Parser{}.Parse(f)
	default:
		return nil, fmt.Errorf("unsupported VEX format: %s", format)
	}
	if err != nil {
		return nil, err
	}

	results := make([]formats.VEXResult, 0, len(stmts))
	for _, s := range stmts {
		results = append(results, formats.VEXResult{
			CVE:           s.CVE,
			ComponentPURL: s.ProductPURL,
			Status:        s.Status,
			Justification: s.Justification,
		})
	}
	return results, nil
}

func loadEmbeddedPolicies() (map[string]string, error) {
	modules := make(map[string]string)
	err := fs.WalkDir(embeddedPolicies, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".rego") {
			return err
		}
		data, err := embeddedPolicies.ReadFile(path)
		if err != nil {
			return err
		}
		modules[path] = string(data)
		return nil
	})
	return modules, err
}

func loadPoliciesFromDir(dir string) (map[string]string, error) {
	modules := make(map[string]string)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read policy dir: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".rego") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec
		if err != nil {
			return nil, err
		}
		modules[e.Name()] = string(data)
	}
	return modules, nil
}
```

Note: The `embed` path `../../policies/*.rego` is relative to the Go source file. Adjust if needed — it may need to be just `policies/*.rego` if there's a `go:embed` issue. The embed directive must match the relative path from the Go file to the policies directory. Since `policykit.go` is in `pkg/policykit/`, the relative path to `policies/` at the repo root is `../../policies/*.rego`.

**Important:** Go's `embed` does not support `../` paths. You need to embed from within the package's directory or use a different approach. The solution is to move the embed directive to a file at the repo root or use `go generate` to copy policies. A simpler approach: create a `pkg/policykit/policies/` symlink or copy policies at build time.

**Recommended approach:** Instead of `//go:embed ../../policies/*.rego`, pass the policies directory to `Run()` at startup. Or embed from `cmd/cra/` and inject them. For simplicity, the engine's `NewEngine` already accepts a `map[string]string` — so the CLI layer can load the policies and pass them in. Update `Options` to include embedded policies:

Change the embed approach: add an `EmbeddedPolicies embed.FS` field or a `LoadPolicies` function in `cmd/cra/`. The simplest production approach: put a `policies.go` file at the repo root that embeds the policies, and the policykit package imports it.

**Simplest fix:** Create `policies/embed.go`:

```go
package policies

import "embed"

//go:embed *.rego
var Embedded embed.FS
```

Then in `policykit.go`, import `github.com/ravan/suse-cra-toolkit/policies` and use `policies.Embedded` instead of a local embed. Remove the `//go:embed` line from policykit.go.

Update the import to:
```go
import "github.com/ravan/suse-cra-toolkit/policies"
```

And change `loadEmbeddedPolicies` to walk `policies.Embedded`.

- [ ] **Step 3: Run full test suite to verify compilation**

Run: `go build ./...`
Expected: compiles successfully

- [ ] **Step 4: Commit**

```bash
git add policies/ pkg/policykit/policykit.go pkg/policykit/human.go
git commit -m "feat(policykit): add 7 Rego policies, human items, and pipeline orchestration"
```

---

### Task 9: CLI wiring

**Files:**
- Modify: `internal/cli/policykit.go`
- Modify: `Taskfile.yml`

- [ ] **Step 1: Wire up CLI flags**

Replace `internal/cli/policykit.go`:

```go
package cli

import (
	"context"
	"fmt"

	urfave "github.com/urfave/cli/v3"

	"github.com/ravan/suse-cra-toolkit/pkg/policykit"
)

func newPolicykitCmd() *urfave.Command {
	return &urfave.Command{
		Name:  "policykit",
		Usage: "Evaluate CRA Annex I compliance policies against product artifacts",
		Flags: []urfave.Flag{
			&urfave.StringFlag{
				Name:     "sbom",
				Usage:    "path to SBOM file (CycloneDX or SPDX)",
				Required: true,
			},
			&urfave.StringSliceFlag{
				Name:     "scan",
				Usage:    "path to scan results (Grype, Trivy, or SARIF); repeatable",
				Required: true,
			},
			&urfave.StringFlag{
				Name:     "vex",
				Usage:    "path to VEX document (OpenVEX or CSAF)",
				Required: true,
			},
			&urfave.StringFlag{
				Name:  "provenance",
				Usage: "path to SLSA provenance attestation JSON",
			},
			&urfave.StringSliceFlag{
				Name:  "signature",
				Usage: "path to signature file (repeatable)",
			},
			&urfave.StringFlag{
				Name:  "product-config",
				Usage: "path to product metadata YAML/JSON",
			},
			&urfave.StringFlag{
				Name:  "kev",
				Usage: "path to local CISA KEV catalog JSON (auto-fetched if omitted)",
			},
			&urfave.StringFlag{
				Name:  "policy-dir",
				Usage: "directory of custom Rego policies",
			},
			&urfave.StringFlag{
				Name:  "format",
				Value: "json",
				Usage: "output format: json or markdown",
			},
		},
		Action: func(_ context.Context, cmd *urfave.Command) error {
			outputFormat := cmd.String("format")
			if outputFormat != "json" && outputFormat != "markdown" {
				return fmt.Errorf("unsupported format %q: must be json or markdown", outputFormat)
			}

			opts := &policykit.Options{
				SBOMPath:       cmd.String("sbom"),
				ScanPaths:      cmd.StringSlice("scan"),
				VEXPath:        cmd.String("vex"),
				ProvenancePath: cmd.String("provenance"),
				SignaturePaths: cmd.StringSlice("signature"),
				ProductConfig:  cmd.String("product-config"),
				KEVPath:        cmd.String("kev"),
				PolicyDir:      cmd.String("policy-dir"),
				OutputFormat:   outputFormat,
			}

			w, closer := OutputWriter(cmd)
			defer closer() //nolint:errcheck

			return policykit.Run(opts, w)
		},
	}
}
```

- [ ] **Step 2: Add Taskfile targets**

Add to `Taskfile.yml` after the existing `test:llmjudge` task:

```yaml
  test:policykit:
    desc: Run policykit integration tests
    cmds:
      - go test -race -count=1 -run TestIntegration ./pkg/policykit/...

  test:policykit:llmjudge:
    desc: Run policykit LLM quality judge tests (requires gemini CLI)
    cmds:
      - go test -race -count=1 -tags llmjudge -run TestLLMJudge -v ./pkg/policykit/...
```

- [ ] **Step 3: Verify build**

Run: `task build`
Expected: compiles successfully

- [ ] **Step 4: Commit**

```bash
git add internal/cli/policykit.go Taskfile.yml
git commit -m "feat(policykit): wire CLI flags and add Taskfile targets"
```

---

### Task 10: Integration test fixtures

**Files:**
- Create: `testdata/integration/policykit-all-pass/` (all artifacts)
- Create: `testdata/integration/policykit-kev-fail/` (CVE in KEV)
- Create: `testdata/integration/policykit-vex-gap/` (missing VEX for high CVE)
- Create: `testdata/integration/policykit-missing-optional/` (no provenance/sig/config)
- Create: `testdata/integration/policykit-invalid-sbom/` (malformed SBOM)
- Create: `testdata/integration/policykit-mixed/` (realistic mixed scenario)

This task creates the test fixture directories. Each needs: SBOM, scan results, VEX document, and an `expected.json`. Some also include provenance, signatures, and product config.

- [ ] **Step 1: Create policykit-all-pass fixture**

Reuse the real SBOM and Grype scan from `csaf-single-cve`. Create supporting artifacts for all 7 policies to pass:

- Copy `testdata/integration/csaf-single-cve/sbom.cdx.json` → `testdata/integration/policykit-all-pass/sbom.cdx.json`
- Copy `testdata/integration/csaf-single-cve/grype.json` → `testdata/integration/policykit-all-pass/grype.json`
- Copy `testdata/integration/csaf-single-cve/vex-results.json` → `testdata/integration/policykit-all-pass/vex-results.json`
- Copy `testdata/policykit/slsa-provenance-v1.json` → `testdata/integration/policykit-all-pass/provenance.json`
- Copy `testdata/policykit/cosign-bundle.json` → `testdata/integration/policykit-all-pass/signature.json`
- Create `testdata/integration/policykit-all-pass/product-config.yaml`
- Create a KEV snapshot that does NOT contain CVE-2022-32149: `testdata/integration/policykit-all-pass/kev.json`
- Create `testdata/integration/policykit-all-pass/expected.json`

The product config:
```yaml
product:
  name: "go-reachable-test"
  version: "1.0.0"
  release_date: "2025-01-01"
  support_end_date: "2031-01-01"
  update_mechanism:
    type: "automatic"
    url: "https://updates.example.com/go-reachable-test"
    auto_update_default: true
    security_updates_separate: true
```

The KEV snapshot (empty vulnerabilities — no matches):
```json
{
  "title": "CISA KEV Test Subset",
  "catalogVersion": "test",
  "dateReleased": "2026-04-03",
  "vulnerabilities": []
}
```

The expected.json:
```json
{
  "description": "All 7 policies PASS — valid SBOM, no KEV hits, full VEX coverage, provenance, signatures, valid product config",
  "assertions": {
    "total_results": 15,
    "passed": 7,
    "failed": 0,
    "skipped": 0,
    "human": 8,
    "expected_statuses": {
      "CRA-AI-1.1": "PASS",
      "CRA-AI-2.1": "PASS",
      "CRA-AI-2.2": "PASS",
      "CRA-AI-3.1": "PASS",
      "CRA-AI-3.2": "PASS",
      "CRA-AI-4.1": "PASS",
      "CRA-AI-4.2": "PASS"
    }
  }
}
```

- [ ] **Step 2: Create policykit-kev-fail fixture**

Same as all-pass but the KEV snapshot includes CVE-2022-32149 (which is in the scan results):

KEV: `{"title":"...","catalogVersion":"test","dateReleased":"2026-04-03","vulnerabilities":[{"cveID":"CVE-2022-32149"}]}`

expected.json assertions: `"CRA-AI-2.1": "FAIL"`, all others PASS.

- [ ] **Step 3: Create policykit-vex-gap fixture**

Same as all-pass but VEX file has no statement for CVE-2022-32149 (which has CVSS 7.5 = high).

VEX: `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"test","author":"test","timestamp":"2026-04-04T00:00:00Z","version":1,"statements":[]}`

expected.json assertions: `"CRA-AI-2.2": "FAIL"`, all others PASS.

- [ ] **Step 4: Create policykit-missing-optional fixture**

Same SBOM/scan/VEX as all-pass, KEV with no matches, but NO provenance, signatures, or product config.

expected.json assertions: `"CRA-AI-3.1": "SKIP"`, `"CRA-AI-3.2": "SKIP"`, `"CRA-AI-4.1": "SKIP"`, `"CRA-AI-4.2": "SKIP"`, `"CRA-AI-1.1": "PASS"`, `"CRA-AI-2.1": "PASS"`, `"CRA-AI-2.2": "PASS"`.

- [ ] **Step 5: Create policykit-invalid-sbom fixture**

A minimal invalid SBOM (CycloneDX but empty components, missing metadata):

```json
{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{},"components":[]}
```

expected.json: `"CRA-AI-1.1": "FAIL"`.

- [ ] **Step 6: Create policykit-mixed fixture**

A realistic scenario combining multiple failures: KEV hit + VEX gap + valid provenance + no signatures + short support period.

expected.json with mixed PASS/FAIL/SKIP results.

- [ ] **Step 7: Commit all fixtures**

```bash
git add testdata/integration/policykit-*/
git commit -m "test(policykit): add 6 integration test fixture directories"
```

---

### Task 11: Integration tests

**Files:**
- Create: `pkg/policykit/integration_test.go`

- [ ] **Step 1: Write integration test**

Create `pkg/policykit/integration_test.go`:

```go
package policykit_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/policykit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fixtureBase = "../../testdata/integration"

type expectedPolicykit struct {
	Description string `json:"description"`
	Assertions  struct {
		TotalResults    int               `json:"total_results"`
		Passed          int               `json:"passed"`
		Failed          int               `json:"failed"`
		Skipped         int               `json:"skipped"`
		Human           int               `json:"human"`
		ExpectedStatuses map[string]string `json:"expected_statuses"`
	} `json:"assertions"`
}

func TestIntegration_PolicykitAllPass(t *testing.T) {
	runPolicykitIntegration(t, "policykit-all-pass")
}

func TestIntegration_PolicykitKEVFail(t *testing.T) {
	runPolicykitIntegration(t, "policykit-kev-fail")
}

func TestIntegration_PolicykitVEXGap(t *testing.T) {
	runPolicykitIntegration(t, "policykit-vex-gap")
}

func TestIntegration_PolicykitMissingOptional(t *testing.T) {
	runPolicykitIntegration(t, "policykit-missing-optional")
}

func TestIntegration_PolicykitInvalidSBOM(t *testing.T) {
	runPolicykitIntegration(t, "policykit-invalid-sbom")
}

func TestIntegration_PolicykitMixed(t *testing.T) {
	runPolicykitIntegration(t, "policykit-mixed")
}

func runPolicykitIntegration(t *testing.T, scenario string) {
	t.Helper()
	dir := filepath.Join(fixtureBase, scenario)

	expected := loadExpectedPolicykit(t, dir)

	opts := &policykit.Options{
		SBOMPath:     filepath.Join(dir, "sbom.cdx.json"),
		ScanPaths:    []string{filepath.Join(dir, "grype.json")},
		VEXPath:      filepath.Join(dir, "vex-results.json"),
		KEVPath:      filepath.Join(dir, "kev.json"),
		OutputFormat: "json",
	}

	// Optional files
	if _, err := os.Stat(filepath.Join(dir, "provenance.json")); err == nil {
		opts.ProvenancePath = filepath.Join(dir, "provenance.json")
	}
	if _, err := os.Stat(filepath.Join(dir, "signature.json")); err == nil {
		opts.SignaturePaths = []string{filepath.Join(dir, "signature.json")}
	}
	if _, err := os.Stat(filepath.Join(dir, "product-config.yaml")); err == nil {
		opts.ProductConfig = filepath.Join(dir, "product-config.yaml")
	}

	var buf bytes.Buffer
	err := policykit.Run(opts, &buf)
	require.NoError(t, err, "policykit.Run() error")

	var report policykit.Report
	require.NoError(t, json.Unmarshal(buf.Bytes(), &report), "output is not valid JSON")

	// Validate summary counts
	if expected.Assertions.TotalResults > 0 {
		assert.Equal(t, expected.Assertions.TotalResults, report.Summary.Total, "total results count")
	}
	if expected.Assertions.Passed >= 0 {
		assert.Equal(t, expected.Assertions.Passed, report.Summary.Passed, "passed count")
	}
	if expected.Assertions.Failed >= 0 {
		assert.Equal(t, expected.Assertions.Failed, report.Summary.Failed, "failed count")
	}
	if expected.Assertions.Skipped >= 0 {
		assert.Equal(t, expected.Assertions.Skipped, report.Summary.Skipped, "skipped count")
	}
	if expected.Assertions.Human >= 0 {
		assert.Equal(t, expected.Assertions.Human, report.Summary.Human, "human count")
	}

	// Validate per-rule statuses
	resultMap := make(map[string]string)
	for _, r := range report.Results {
		resultMap[r.RuleID] = r.Status
	}
	for ruleID, expectedStatus := range expected.Assertions.ExpectedStatuses {
		actual, ok := resultMap[ruleID]
		if !ok {
			t.Errorf("expected rule %s not found in results", ruleID)
			continue
		}
		assert.Equal(t, expectedStatus, actual, "rule %s status", ruleID)
	}

	t.Logf("%s: %d results (P:%d F:%d S:%d H:%d), all assertions passed",
		scenario, report.Summary.Total, report.Summary.Passed, report.Summary.Failed,
		report.Summary.Skipped, report.Summary.Human)
}

func loadExpectedPolicykit(t *testing.T, dir string) expectedPolicykit {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "expected.json")) //nolint:gosec
	require.NoError(t, err, "read expected.json")
	var expected expectedPolicykit
	require.NoError(t, json.Unmarshal(data, &expected), "parse expected.json")
	return expected
}
```

- [ ] **Step 2: Run integration tests**

Run: `go test -race -count=1 -run TestIntegration ./pkg/policykit/...`
Expected: All 6 scenarios PASS

- [ ] **Step 3: Fix any failures**

Iterate until all integration tests pass. Common issues:
- Embed path for policies
- KEV parsing with empty vulnerabilities
- VEX matching key format
- SBOM metadata extraction

- [ ] **Step 4: Commit**

```bash
git add pkg/policykit/integration_test.go
git commit -m "test(policykit): add 6 end-to-end integration tests"
```

---

### Task 12: LLM judge test

**Files:**
- Create: `pkg/policykit/llm_judge_test.go`

- [ ] **Step 1: Write the LLM judge test**

Create `pkg/policykit/llm_judge_test.go`:

```go
//go:build llmjudge

package policykit_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/policykit"
)

type policykitLLMScores struct {
	RegulatoryAccuracy int    `json:"regulatory_accuracy"`
	EvidenceQuality    int    `json:"evidence_quality"`
	Completeness       int    `json:"completeness"`
	ReportClarity      int    `json:"report_clarity"`
	Accuracy           int    `json:"accuracy"`
	OverallQuality     int    `json:"overall_quality"`
	Reasoning          string `json:"reasoning"`
}

func TestLLMJudge_PolicykitAllPass(t *testing.T) {
	geminiPath, err := exec.LookPath("gemini")
	if err != nil {
		t.Skip("gemini CLI not available, skipping LLM judge test")
	}

	dir := filepath.Join(fixtureBase, "policykit-all-pass")
	opts := &policykit.Options{
		SBOMPath:       filepath.Join(dir, "sbom.cdx.json"),
		ScanPaths:      []string{filepath.Join(dir, "grype.json")},
		VEXPath:        filepath.Join(dir, "vex-results.json"),
		KEVPath:        filepath.Join(dir, "kev.json"),
		ProvenancePath: filepath.Join(dir, "provenance.json"),
		SignaturePaths: []string{filepath.Join(dir, "signature.json")},
		ProductConfig:  filepath.Join(dir, "product-config.yaml"),
		OutputFormat:   "json",
	}

	var buf bytes.Buffer
	if err := policykit.Run(opts, &buf); err != nil {
		t.Fatalf("policykit.Run() error: %v", err)
	}

	reportFile, err := os.CreateTemp("", "policykit-report-*.json")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	defer os.Remove(reportFile.Name())
	reportFile.Write(buf.Bytes())
	reportFile.Close()

	craAnnexPath, err := filepath.Abs("../../docs/eu-cyber-resilience-act.pdf")
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}

	prompt := fmt.Sprintf(`You are a CRA compliance report quality judge.

Read the CRA REGULATION from: %s (focus on Annex I pages 68-69)
Read the GENERATED REPORT from: %s

Score the generated report on these dimensions (1-10 each):
1. regulatory_accuracy: Do rule IDs and CRA references correctly cite Annex I / Art. 13?
2. evidence_quality: Is evidence specific, verifiable, and actionable?
3. completeness: Are all machine-checkable requirements covered? Are human-review items listed?
4. report_clarity: Would a compliance officer understand this without CRA expertise?
5. accuracy: Given the input artifacts, are PASS/FAIL/SKIP statuses correct?
6. overall_quality: Would a market surveillance authority accept this as part of Annex VII?

Respond ONLY with valid JSON:
{"regulatory_accuracy": N, "evidence_quality": N, "completeness": N, "report_clarity": N, "accuracy": N, "overall_quality": N, "reasoning": "brief explanation"}`,
		craAnnexPath, reportFile.Name())

	cmd := exec.Command(geminiPath, "-p", prompt) //nolint:gosec
	var geminiOut bytes.Buffer
	cmd.Stdout = &geminiOut
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("gemini error: %v", err)
	}

	responseText := geminiOut.String()
	jsonStart := strings.Index(responseText, "{")
	jsonEnd := strings.LastIndex(responseText, "}")
	if jsonStart == -1 || jsonEnd == -1 {
		t.Fatalf("no JSON in response: %s", responseText)
	}

	var scores policykitLLMScores
	if err := json.Unmarshal([]byte(responseText[jsonStart:jsonEnd+1]), &scores); err != nil {
		t.Fatalf("parse scores: %v\nresponse: %s", err, responseText)
	}

	t.Logf("LLM Scores: regulatory=%d evidence=%d completeness=%d clarity=%d accuracy=%d overall=%d",
		scores.RegulatoryAccuracy, scores.EvidenceQuality, scores.Completeness,
		scores.ReportClarity, scores.Accuracy, scores.OverallQuality)
	t.Logf("Reasoning: %s", scores.Reasoning)

	threshold := 8
	dims := map[string]int{
		"regulatory_accuracy": scores.RegulatoryAccuracy,
		"evidence_quality":    scores.EvidenceQuality,
		"completeness":        scores.Completeness,
		"report_clarity":      scores.ReportClarity,
		"accuracy":            scores.Accuracy,
		"overall_quality":     scores.OverallQuality,
	}
	for dim, score := range dims {
		if score < threshold {
			t.Errorf("%s: score %d < threshold %d", dim, score, threshold)
		}
	}
}
```

- [ ] **Step 2: Run unit + integration tests to ensure nothing is broken**

Run: `task test`
Expected: All existing tests pass

- [ ] **Step 3: Run LLM judge (requires gemini CLI)**

Run: `task test:policykit:llmjudge`
Expected: All 6 dimensions >= 8

- [ ] **Step 4: Commit**

```bash
git add pkg/policykit/llm_judge_test.go
git commit -m "test(policykit): add LLM quality judge test"
```

---

### Task 13: Final quality gate

- [ ] **Step 1: Run full quality suite**

Run: `task quality`
Expected: All formatting, vet, lint, and tests pass

- [ ] **Step 2: Fix any lint issues**

Address any `golangci-lint` findings (nolint comments where justified, fix the rest).

- [ ] **Step 3: Run policykit-specific integration tests**

Run: `task test:policykit`
Expected: All 6 integration scenarios pass

- [ ] **Step 4: Verify CLI works end-to-end**

Run:
```bash
task build
./bin/cra policykit \
  --sbom testdata/integration/policykit-all-pass/sbom.cdx.json \
  --scan testdata/integration/policykit-all-pass/grype.json \
  --vex testdata/integration/policykit-all-pass/vex-results.json \
  --kev testdata/integration/policykit-all-pass/kev.json \
  --provenance testdata/integration/policykit-all-pass/provenance.json \
  --signature testdata/integration/policykit-all-pass/signature.json \
  --product-config testdata/integration/policykit-all-pass/product-config.yaml \
  --format json
```
Expected: JSON report with 7 PASS + 8 HUMAN

```bash
./bin/cra policykit \
  --sbom testdata/integration/policykit-all-pass/sbom.cdx.json \
  --scan testdata/integration/policykit-all-pass/grype.json \
  --vex testdata/integration/policykit-all-pass/vex-results.json \
  --kev testdata/integration/policykit-all-pass/kev.json \
  --format markdown
```
Expected: Markdown report with summary table and human review checklist

- [ ] **Step 5: Final commit**

```bash
git add -A
git commit -m "feat: implement cra-policykit — CRA Annex I policy evaluation"
```
