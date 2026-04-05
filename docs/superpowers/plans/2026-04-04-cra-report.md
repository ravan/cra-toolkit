# cra-report Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement CRA Article 14 notification generation — a stage-based pipeline producing 24h/72h/14d vulnerability notification documents with exploitation signal aggregation, CSIRT coordinator lookup, and Art. 14(8) user notification.

**Architecture:** Stateless, single-stage pipeline following the same `Run(opts, io.Writer) error` pattern as `pkg/csaf` and `pkg/policykit`. Signal aggregator collects KEV/EPSS/manual exploitation indicators. Three stage builders progressively enrich the notification document. Output as JSON or Markdown.

**Tech Stack:** Go 1.26, urfave/cli v3, testify, gopkg.in/yaml.v3. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-04-04-cra-report-design.md`

**Quality gates:** `task quality` must pass after every commit. Taskfile tasks added for `test:report` and `test:report:llmjudge`.

---

## File Map

| File | Responsibility |
|------|---------------|
| `pkg/report/types.go` | All type definitions: Stage, Notification, VulnEntry, ExploitationSignal, Completeness, Manufacturer, CSIRTInfo, UserNotification, Impact, AffectedProduct, Options |
| `pkg/report/epss.go` | EPSS JSON file parser |
| `pkg/report/epss_test.go` | EPSS parser unit tests |
| `pkg/report/csirt.go` | Embedded CSIRT coordinator lookup table + `LookupCSIRT()` |
| `pkg/report/csirt_test.go` | CSIRT lookup unit tests |
| `pkg/report/signals.go` | Exploitation signal aggregator: KEV + EPSS + manual flags |
| `pkg/report/signals_test.go` | Signal aggregator unit tests |
| `pkg/report/config.go` | Extended product config parser (manufacturer section, exploitation overrides) |
| `pkg/report/config_test.go` | Config parser unit tests |
| `pkg/report/human_input.go` | Human input YAML parser for 14-day final report |
| `pkg/report/human_input_test.go` | Human input parser unit tests |
| `pkg/report/early_warning.go` | `BuildEarlyWarning()` stage builder |
| `pkg/report/early_warning_test.go` | Early warning unit tests |
| `pkg/report/notification.go` | `BuildNotification()` stage builder |
| `pkg/report/notification_test.go` | Notification unit tests |
| `pkg/report/final_report.go` | `BuildFinalReport()` stage builder + human input merge |
| `pkg/report/final_report_test.go` | Final report unit tests |
| `pkg/report/user_notify.go` | `BuildUserNotification()` for Art. 14(8) |
| `pkg/report/user_notify_test.go` | User notification unit tests |
| `pkg/report/completeness.go` | `ComputeCompleteness()` |
| `pkg/report/completeness_test.go` | Completeness unit tests |
| `pkg/report/render.go` | `RenderMarkdown()` |
| `pkg/report/render_test.go` | Markdown rendering unit tests |
| `pkg/report/report.go` | `Run()` pipeline orchestrator (replaces stub) |
| `pkg/report/integration_test.go` | 6 scenario integration tests |
| `pkg/report/llm_judge_test.go` | LLM quality judge test |
| `internal/cli/report.go` | CLI command wiring (replaces stub) |
| `Taskfile.yml` | Add `test:report` and `test:report:llmjudge` tasks |
| `testdata/integration/report-*/` | 6 test fixture directories |

---

### Task 1: Taskfile tasks and types foundation

**Files:**
- Modify: `Taskfile.yml`
- Create: `pkg/report/types.go`

- [ ] **Step 1: Add Taskfile tasks for report testing**

Add to `Taskfile.yml` after the `test:policykit:llmjudge` task:

```yaml
  test:report:
    desc: Run report integration tests
    cmds:
      - go test -race -count=1 -run TestIntegration ./pkg/report/...

  test:report:llmjudge:
    desc: Run report LLM quality judge tests (requires gemini CLI)
    cmds:
      - go test -race -count=1 -tags llmjudge -run TestLLMJudge -v ./pkg/report/...
```

- [ ] **Step 2: Create types.go with all type definitions**

Create `pkg/report/types.go`:

```go
// Package report generates CRA Article 14 vulnerability notification documents.
// It supports the three-stage pipeline: 24h early warning, 72h notification, 14-day final report.
package report

import "errors"

// ErrNoExploitedVulns is returned when no CVEs have exploitation signals.
var ErrNoExploitedVulns = errors.New("report: no vulnerabilities with exploitation signals found")

// Stage represents an Art. 14(2) notification stage.
type Stage string

const (
	StageEarlyWarning Stage = "early-warning" // Art. 14(2)(a) -- 24h
	StageNotification Stage = "notification"  // Art. 14(2)(b) -- 72h
	StageFinalReport  Stage = "final-report"  // Art. 14(2)(c) -- 14d
)

// CRAReference returns the CRA article reference for this stage.
func (s Stage) CRAReference() string {
	switch s {
	case StageEarlyWarning:
		return "Art. 14(2)(a)"
	case StageNotification:
		return "Art. 14(2)(b)"
	case StageFinalReport:
		return "Art. 14(2)(c)"
	default:
		return "Art. 14(2)"
	}
}

// ParseStage converts a string to a Stage, returning an error for invalid values.
func ParseStage(s string) (Stage, error) {
	switch Stage(s) {
	case StageEarlyWarning, StageNotification, StageFinalReport:
		return Stage(s), nil
	default:
		return "", errors.New("report: invalid stage " + s + ": must be early-warning, notification, or final-report")
	}
}

// SubmissionChannelENISA is the constant submission channel per Art. 14(7).
const SubmissionChannelENISA = "ENISA Single Reporting Platform (Art. 16)"

// CompletenessNote is the constant disclaimer on the completeness metric.
const CompletenessNote = "Toolkit quality metric. CRA Art. 14 does not define completeness thresholds."

// Options configures a report generation run.
type Options struct {
	SBOMPath              string
	ScanPaths             []string
	Stage                 Stage
	ProductConfig         string
	KEVPath               string
	EPSSPath              string
	EPSSThreshold         float64
	VEXPath               string
	HumanInputPath        string
	CSAFAdvisoryRef       string
	CorrectiveMeasureDate string
	OutputFormat          string // "json" or "markdown"
}

// Notification is the top-level Art. 14 notification document.
type Notification struct {
	NotificationID    string            `json:"notification_id"`
	ToolkitVersion    string            `json:"toolkit_version"`
	Timestamp         string            `json:"timestamp"`
	Stage             Stage             `json:"stage"`
	CRAReference      string            `json:"cra_reference"`
	SubmissionChannel string            `json:"submission_channel"`
	Manufacturer      Manufacturer      `json:"manufacturer"`
	CSIRTCoordinator  CSIRTInfo         `json:"csirt_coordinator"`
	Vulnerabilities   []VulnEntry       `json:"vulnerabilities"`
	UserNotification  *UserNotification `json:"user_notification,omitempty"`
	Completeness      Completeness      `json:"completeness"`
}

// VulnEntry holds per-CVE data, progressively enriched by stage.
type VulnEntry struct {
	CVE                   string               `json:"cve"`
	ExploitationSignals   []ExploitationSignal  `json:"exploitation_signals"`
	Severity              string               `json:"severity"`
	CVSS                  float64              `json:"cvss"`
	AffectedProducts      []AffectedProduct    `json:"affected_products"`
	MemberStates          []string             `json:"member_states,omitempty"`
	Description           string               `json:"description,omitempty"`
	GeneralNature         string               `json:"general_nature,omitempty"`
	CorrectiveActions     []string             `json:"corrective_actions,omitempty"`
	MitigatingMeasures    []string             `json:"mitigating_measures,omitempty"`
	EstimatedImpact       *Impact              `json:"estimated_impact,omitempty"`
	InformationSensitivity string              `json:"information_sensitivity,omitempty"`
	CorrectiveMeasureDate string               `json:"corrective_measure_date,omitempty"`
	RootCause             string               `json:"root_cause,omitempty"`
	ThreatActorInfo       string               `json:"threat_actor_info,omitempty"`
	SecurityUpdate        string               `json:"security_update,omitempty"`
	PreventiveMeasures    []string             `json:"preventive_measures,omitempty"`
}

// ExploitationSignal records one data source's indication of active exploitation.
type ExploitationSignal struct {
	Source ExploitationSource `json:"source"`
	Detail string             `json:"detail"`
}

// ExploitationSource identifies where an exploitation signal came from.
type ExploitationSource string

const (
	ExploitationKEV    ExploitationSource = "kev"
	ExploitationEPSS   ExploitationSource = "epss"
	ExploitationManual ExploitationSource = "manual"
)

// ExploitedVuln is an intermediate type used during signal aggregation.
type ExploitedVuln struct {
	CVE              string
	Signals          []ExploitationSignal
	AffectedProducts []AffectedProduct
	Severity         string
	CVSS             float64
	CVSSVector       string
	Description      string
	FixVersion       string
}

// AffectedProduct identifies a product affected by a vulnerability.
type AffectedProduct struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

// Impact captures the estimated impact of a vulnerability.
type Impact struct {
	AffectedComponentCount int            `json:"affected_component_count"`
	SeverityDistribution   map[string]int `json:"severity_distribution"`
}

// Completeness is a toolkit quality metric (NOT a regulatory measure).
type Completeness struct {
	Score            float64  `json:"score"`
	TotalFields      int      `json:"total_fields"`
	FilledFields     int      `json:"filled_fields"`
	MachineGenerated int      `json:"machine_generated"`
	HumanProvided    int      `json:"human_provided"`
	Pending          []string `json:"pending,omitempty"`
	Note             string   `json:"note"`
}

// Manufacturer identifies the product manufacturer per Art. 14.
type Manufacturer struct {
	Name                  string   `json:"name" yaml:"name"`
	MemberState           string   `json:"member_state" yaml:"member_state"`
	Address               string   `json:"address,omitempty" yaml:"address,omitempty"`
	ContactEmail          string   `json:"contact_email" yaml:"contact_email"`
	Website               string   `json:"website,omitempty" yaml:"website,omitempty"`
	MemberStatesAvailable []string `json:"member_states_available,omitempty" yaml:"member_states_available,omitempty"`
}

// CSIRTInfo identifies the designated CSIRT coordinator (informational metadata only).
// Actual submission is via the ENISA Single Reporting Platform per Art. 14(7).
type CSIRTInfo struct {
	Name              string `json:"name"`
	Country           string `json:"country"`
	SubmissionChannel string `json:"submission_channel"`
}

// UserNotification holds Art. 14(8) user-facing notification data.
type UserNotification struct {
	AffectedProducts   []AffectedProduct `json:"affected_products"`
	RecommendedActions []string          `json:"recommended_actions"`
	Severity           string            `json:"severity"`
	CSAFAdvisoryRef    string            `json:"csaf_advisory_ref,omitempty"`
}

// ExploitationOverride is a manual exploitation flag from product config.
type ExploitationOverride struct {
	CVE    string `json:"cve" yaml:"cve"`
	Source string `json:"source" yaml:"source"`
	Reason string `json:"reason" yaml:"reason"`
}

// HumanVulnInput holds human-authored fields for a single CVE in the final report.
type HumanVulnInput struct {
	CorrectiveMeasureDate string   `json:"corrective_measure_date" yaml:"corrective_measure_date"`
	RootCause             string   `json:"root_cause" yaml:"root_cause"`
	ThreatActorInfo       string   `json:"threat_actor_info" yaml:"threat_actor_info"`
	SecurityUpdate        string   `json:"security_update" yaml:"security_update"`
	PreventiveMeasures    []string `json:"preventive_measures" yaml:"preventive_measures"`
}

// HumanInput holds all human-authored input for the final report.
type HumanInput struct {
	Vulnerabilities map[string]HumanVulnInput `json:"vulnerabilities" yaml:"vulnerabilities"`
}

// EPSSData holds parsed EPSS scores.
type EPSSData struct {
	ModelVersion string             `json:"model_version"`
	ScoreDate    string             `json:"score_date"`
	Scores       map[string]float64 `json:"scores"`
}

// ReportProductConfig extends the policykit product config with manufacturer and overrides.
type ReportProductConfig struct {
	Product                ProductSection         `json:"product" yaml:"product"`
	Manufacturer           Manufacturer           `json:"manufacturer" yaml:"manufacturer"`
	ExploitationOverrides  []ExploitationOverride  `json:"exploitation_overrides" yaml:"exploitation_overrides"`
}

// ProductSection is the product metadata section of the config.
type ProductSection struct {
	Name            string `json:"name" yaml:"name"`
	Version         string `json:"version" yaml:"version"`
	SupportPeriod   string `json:"support_period" yaml:"support_period"`
	UpdateMechanism string `json:"update_mechanism" yaml:"update_mechanism"`
}
```

- [ ] **Step 3: Verify it compiles**

Run: `go build ./pkg/report/...`
Expected: Success (no output)

- [ ] **Step 4: Run quality gates**

Run: `task quality`
Expected: All pass

- [ ] **Step 5: Commit**

```bash
git add Taskfile.yml pkg/report/types.go
git commit -m "feat(report): add types foundation and Taskfile tasks for cra-report"
```

---

### Task 2: EPSS parser

**Files:**
- Create: `pkg/report/epss_test.go`
- Create: `pkg/report/epss.go`

- [ ] **Step 1: Write the failing EPSS parser test**

Create `pkg/report/epss_test.go`:

```go
package report

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseEPSS(t *testing.T) {
	input := `{
		"model_version": "v2023.03.01",
		"score_date": "2026-04-04",
		"scores": {
			"CVE-2021-44228": 0.975,
			"CVE-2022-32149": 0.42
		}
	}`

	data, err := ParseEPSS(strings.NewReader(input))
	require.NoError(t, err)
	assert.Equal(t, "v2023.03.01", data.ModelVersion)
	assert.Equal(t, "2026-04-04", data.ScoreDate)
	assert.InDelta(t, 0.975, data.Scores["CVE-2021-44228"], 0.001)
	assert.InDelta(t, 0.42, data.Scores["CVE-2022-32149"], 0.001)
}

func TestParseEPSS_Empty(t *testing.T) {
	input := `{"model_version": "v1", "score_date": "2026-01-01", "scores": {}}`
	data, err := ParseEPSS(strings.NewReader(input))
	require.NoError(t, err)
	assert.Empty(t, data.Scores)
}

func TestParseEPSS_InvalidJSON(t *testing.T) {
	_, err := ParseEPSS(strings.NewReader("not json"))
	require.Error(t, err)
}

func TestLoadEPSS_FromFile(t *testing.T) {
	// Use the real EPSS fixture from integration tests (created in Task 10)
	// For now test with nil path returns nil
	data, err := LoadEPSS("")
	require.NoError(t, err)
	assert.Nil(t, data)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/report/ -run TestParseEPSS -v`
Expected: FAIL — `ParseEPSS` not defined

- [ ] **Step 3: Implement EPSS parser**

Create `pkg/report/epss.go`:

```go
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// ParseEPSS reads EPSS JSON from r and returns parsed scores.
func ParseEPSS(r io.Reader) (*EPSSData, error) {
	var data EPSSData
	if err := json.NewDecoder(r).Decode(&data); err != nil {
		return nil, fmt.Errorf("parsing EPSS JSON: %w", err)
	}
	if data.Scores == nil {
		data.Scores = make(map[string]float64)
	}
	return &data, nil
}

// LoadEPSS loads EPSS data from a local file. Returns nil if path is empty.
func LoadEPSS(path string) (*EPSSData, error) {
	if path == "" {
		return nil, nil //nolint:nilnil // nil means EPSS not provided
	}
	f, err := os.Open(path) //nolint:gosec // CLI flag
	if err != nil {
		return nil, fmt.Errorf("opening EPSS file %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck // read-only file
	return ParseEPSS(f)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/report/ -run TestParseEPSS -v && go test ./pkg/report/ -run TestLoadEPSS -v`
Expected: All PASS

- [ ] **Step 5: Run quality gates and commit**

Run: `task quality`

```bash
git add pkg/report/epss.go pkg/report/epss_test.go
git commit -m "feat(report): add EPSS score parser"
```

---

### Task 3: CSIRT coordinator lookup table

**Files:**
- Create: `pkg/report/csirt_test.go`
- Create: `pkg/report/csirt.go`

- [ ] **Step 1: Write the failing CSIRT lookup test**

Create `pkg/report/csirt_test.go`:

```go
package report

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLookupCSIRT_Germany(t *testing.T) {
	info, err := LookupCSIRT("DE")
	require.NoError(t, err)
	assert.Equal(t, "BSI (CERT-Bund)", info.Name)
	assert.Equal(t, "DE", info.Country)
	assert.Equal(t, SubmissionChannelENISA, info.SubmissionChannel)
}

func TestLookupCSIRT_France(t *testing.T) {
	info, err := LookupCSIRT("FR")
	require.NoError(t, err)
	assert.Equal(t, "CERT-FR (ANSSI)", info.Name)
	assert.Equal(t, "FR", info.Country)
}

func TestLookupCSIRT_AllEUMembers(t *testing.T) {
	euCodes := []string{
		"AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
		"DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
		"PL", "PT", "RO", "SK", "SI", "ES", "SE",
	}
	for _, code := range euCodes {
		t.Run(code, func(t *testing.T) {
			info, err := LookupCSIRT(code)
			require.NoError(t, err, "missing CSIRT for EU member %s", code)
			assert.NotEmpty(t, info.Name)
			assert.Equal(t, code, info.Country)
			assert.Equal(t, SubmissionChannelENISA, info.SubmissionChannel)
		})
	}
}

func TestLookupCSIRT_EEAMembers(t *testing.T) {
	eeaCodes := []string{"NO", "IS", "LI"}
	for _, code := range eeaCodes {
		t.Run(code, func(t *testing.T) {
			info, err := LookupCSIRT(code)
			require.NoError(t, err, "missing CSIRT for EEA member %s", code)
			assert.NotEmpty(t, info.Name)
		})
	}
}

func TestLookupCSIRT_Unknown(t *testing.T) {
	_, err := LookupCSIRT("XX")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "XX")
}

func TestLookupCSIRT_CaseInsensitive(t *testing.T) {
	info, err := LookupCSIRT("de")
	require.NoError(t, err)
	assert.Equal(t, "BSI (CERT-Bund)", info.Name)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/report/ -run TestLookupCSIRT -v`
Expected: FAIL — `LookupCSIRT` not defined

- [ ] **Step 3: Implement CSIRT lookup**

Create `pkg/report/csirt.go`:

```go
package report

import (
	"fmt"
	"strings"
)

// csirtTable maps ISO 3166-1 alpha-2 country codes to CSIRT coordinator names.
// Source: ENISA CSIRT-network member list (https://csirtsnetwork.eu)
// Last verified: 2026-04-04
//
// This is informational metadata only. Per Art. 14(7), notifications are
// submitted via the ENISA Single Reporting Platform (Art. 16), NOT directly
// to the CSIRT.
var csirtTable = map[string]string{
	// EU Member States (27)
	"AT": "CERT.at",
	"BE": "CERT.be (Centre for Cybersecurity Belgium)",
	"BG": "CERT Bulgaria",
	"HR": "CERT.hr (CARNET CERT)",
	"CY": "CSIRT-CY (Digital Security Authority)",
	"CZ": "CSIRT.CZ (CZ.NIC)",
	"DK": "CFCS (Centre for Cyber Security)",
	"EE": "CERT-EE (RIA)",
	"FI": "NCSC-FI (Traficom)",
	"FR": "CERT-FR (ANSSI)",
	"DE": "BSI (CERT-Bund)",
	"GR": "GR-CSIRT (National CSIRT Greece)",
	"HU": "NCSC-HU (NBSZ)",
	"IE": "CSIRT-IE (NCSC Ireland)",
	"IT": "CSIRT Italia (ACN)",
	"LV": "CERT.LV",
	"LT": "CERT-LT (NRD CSIRT)",
	"LU": "CIRCL (CSIRT Luxembourg)",
	"MT": "CSIRTMalta (MITA)",
	"NL": "NCSC-NL",
	"PL": "CERT Polska (NASK)",
	"PT": "CERT.PT (CNCS)",
	"RO": "CERT-RO",
	"SK": "SK-CERT (NSA SR)",
	"SI": "SI-CERT (ARNES)",
	"ES": "CCN-CERT (CNI)",
	"SE": "CERT-SE (MSB)",
	// EEA Members (3)
	"NO": "NorCERT (NSM)",
	"IS": "CERT-IS (ISNIC)",
	"LI": "CERT Liechtenstein (AMS)",
}

// LookupCSIRT returns the CSIRT coordinator info for the given country code.
// Country codes are case-insensitive.
func LookupCSIRT(countryCode string) (CSIRTInfo, error) {
	code := strings.ToUpper(countryCode)
	name, ok := csirtTable[code]
	if !ok {
		return CSIRTInfo{}, fmt.Errorf("report: no CSIRT coordinator found for country code %q", code)
	}
	return CSIRTInfo{
		Name:              name,
		Country:           code,
		SubmissionChannel: SubmissionChannelENISA,
	}, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/report/ -run TestLookupCSIRT -v`
Expected: All PASS (including all 27 EU + 3 EEA members)

- [ ] **Step 5: Run quality gates and commit**

Run: `task quality`

```bash
git add pkg/report/csirt.go pkg/report/csirt_test.go
git commit -m "feat(report): add CSIRT coordinator lookup table (27 EU + 3 EEA)"
```

---

### Task 4: Product config parser (extended with manufacturer)

**Files:**
- Create: `pkg/report/config_test.go`
- Create: `pkg/report/config.go`

- [ ] **Step 1: Write the failing config parser test**

Create `pkg/report/config_test.go`:

```go
package report

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadReportConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "product-config.yaml")
	err := os.WriteFile(path, []byte(`
product:
  name: "SUSE Linux Enterprise Server"
  version: "15-SP5"
  support_period: "2028-12-31"
  update_mechanism: "automatic"

manufacturer:
  name: "SUSE LLC"
  member_state: "DE"
  contact_email: "security@suse.com"
  website: "https://suse.com"
  member_states_available:
    - DE
    - FR
    - NL

exploitation_overrides:
  - cve: "CVE-2026-XXXX"
    source: "manual"
    reason: "Internal threat intel confirmed active exploitation"
`), 0o600)
	require.NoError(t, err)

	cfg, err := LoadReportConfig(path)
	require.NoError(t, err)

	assert.Equal(t, "SUSE Linux Enterprise Server", cfg.Product.Name)
	assert.Equal(t, "15-SP5", cfg.Product.Version)
	assert.Equal(t, "SUSE LLC", cfg.Manufacturer.Name)
	assert.Equal(t, "DE", cfg.Manufacturer.MemberState)
	assert.Equal(t, "security@suse.com", cfg.Manufacturer.ContactEmail)
	assert.Equal(t, []string{"DE", "FR", "NL"}, cfg.Manufacturer.MemberStatesAvailable)
	require.Len(t, cfg.ExploitationOverrides, 1)
	assert.Equal(t, "CVE-2026-XXXX", cfg.ExploitationOverrides[0].CVE)
	assert.Equal(t, "manual", cfg.ExploitationOverrides[0].Source)
}

func TestLoadReportConfig_MissingManufacturer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "product-config.yaml")
	err := os.WriteFile(path, []byte(`
product:
  name: "test"
  version: "1.0"
`), 0o600)
	require.NoError(t, err)

	_, err = LoadReportConfig(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "manufacturer")
}

func TestLoadReportConfig_MissingMemberState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "product-config.yaml")
	err := os.WriteFile(path, []byte(`
product:
  name: "test"
  version: "1.0"
manufacturer:
  name: "SUSE LLC"
  contact_email: "sec@suse.com"
`), 0o600)
	require.NoError(t, err)

	_, err = LoadReportConfig(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "member_state")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/report/ -run TestLoadReportConfig -v`
Expected: FAIL — `LoadReportConfig` not defined

- [ ] **Step 3: Implement config parser**

Create `pkg/report/config.go`:

```go
package report

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadReportConfig loads and validates the extended product config with manufacturer section.
func LoadReportConfig(path string) (*ReportProductConfig, error) {
	data, err := os.ReadFile(path) //nolint:gosec // CLI flag
	if err != nil {
		return nil, fmt.Errorf("reading product config %s: %w", path, err)
	}

	var cfg ReportProductConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing product config %s: %w", path, err)
	}

	if cfg.Manufacturer.Name == "" {
		return nil, fmt.Errorf("product config %s: manufacturer.name is required", path)
	}
	if cfg.Manufacturer.MemberState == "" {
		return nil, fmt.Errorf("product config %s: manufacturer.member_state is required", path)
	}

	return &cfg, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/report/ -run TestLoadReportConfig -v`
Expected: All PASS

- [ ] **Step 5: Run quality gates and commit**

Run: `task quality`

```bash
git add pkg/report/config.go pkg/report/config_test.go
git commit -m "feat(report): add extended product config parser with manufacturer section"
```

---

### Task 5: Human input parser

**Files:**
- Create: `pkg/report/human_input_test.go`
- Create: `pkg/report/human_input.go`

- [ ] **Step 1: Write the failing human input test**

Create `pkg/report/human_input_test.go`:

```go
package report

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadHumanInput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "human-input.yaml")
	err := os.WriteFile(path, []byte(`
vulnerabilities:
  CVE-2021-44228:
    corrective_measure_date: "2021-12-12"
    root_cause: "Insufficient input validation in JNDI lookup functionality"
    threat_actor_info: "Multiple APT groups"
    security_update: "Log4j 2.17.0 disables JNDI by default"
    preventive_measures:
      - "Implemented input validation for all JNDI lookups"
      - "Added runtime protection against recursive lookups"
`), 0o600)
	require.NoError(t, err)

	hi, err := LoadHumanInput(path)
	require.NoError(t, err)
	require.Contains(t, hi.Vulnerabilities, "CVE-2021-44228")

	vuln := hi.Vulnerabilities["CVE-2021-44228"]
	assert.Equal(t, "2021-12-12", vuln.CorrectiveMeasureDate)
	assert.Equal(t, "Insufficient input validation in JNDI lookup functionality", vuln.RootCause)
	assert.Equal(t, "Multiple APT groups", vuln.ThreatActorInfo)
	assert.Equal(t, "Log4j 2.17.0 disables JNDI by default", vuln.SecurityUpdate)
	assert.Len(t, vuln.PreventiveMeasures, 2)
}

func TestLoadHumanInput_Empty(t *testing.T) {
	hi, err := LoadHumanInput("")
	require.NoError(t, err)
	assert.Nil(t, hi)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/report/ -run TestLoadHumanInput -v`
Expected: FAIL — `LoadHumanInput` not defined

- [ ] **Step 3: Implement human input parser**

Create `pkg/report/human_input.go`:

```go
package report

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadHumanInput loads human-authored vulnerability data for the 14-day final report.
// Returns nil if path is empty.
func LoadHumanInput(path string) (*HumanInput, error) {
	if path == "" {
		return nil, nil //nolint:nilnil // nil means no human input provided
	}

	data, err := os.ReadFile(path) //nolint:gosec // CLI flag
	if err != nil {
		return nil, fmt.Errorf("reading human input %s: %w", path, err)
	}

	var hi HumanInput
	if err := yaml.Unmarshal(data, &hi); err != nil {
		return nil, fmt.Errorf("parsing human input %s: %w", path, err)
	}

	return &hi, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/report/ -run TestLoadHumanInput -v`
Expected: All PASS

- [ ] **Step 5: Run quality gates and commit**

Run: `task quality`

```bash
git add pkg/report/human_input.go pkg/report/human_input_test.go
git commit -m "feat(report): add human input YAML parser for 14-day final report"
```

---

### Task 6: Exploitation signal aggregator

**Files:**
- Create: `pkg/report/signals_test.go`
- Create: `pkg/report/signals.go`

- [ ] **Step 1: Write the failing signals test**

Create `pkg/report/signals_test.go`:

```go
package report

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/policykit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAggregateSignals_KEVMatch(t *testing.T) {
	findings := []formats.Finding{
		{CVE: "CVE-2022-32149", AffectedPURL: "pkg:golang/golang.org/x/text@v0.3.7", Severity: "high", CVSS: 7.5, Description: "DoS via Accept-Language", FixVersion: "0.3.8"},
	}
	kev := &policykit.KEVCatalog{CVEs: map[string]bool{"CVE-2022-32149": true}}
	components := []formats.Component{{Name: "golang.org/x/text", Version: "v0.3.7", PURL: "pkg:golang/golang.org/x/text@v0.3.7"}}

	vulns := AggregateExploitationSignals(findings, kev, nil, nil, components, 0.7)
	require.Len(t, vulns, 1)
	assert.Equal(t, "CVE-2022-32149", vulns[0].CVE)
	require.Len(t, vulns[0].Signals, 1)
	assert.Equal(t, ExploitationKEV, vulns[0].Signals[0].Source)
}

func TestAggregateSignals_EPSSAboveThreshold(t *testing.T) {
	findings := []formats.Finding{
		{CVE: "CVE-2022-32149", Severity: "high", CVSS: 7.5, AffectedPURL: "pkg:golang/golang.org/x/text@v0.3.7"},
	}
	epss := &EPSSData{Scores: map[string]float64{"CVE-2022-32149": 0.85}}
	components := []formats.Component{{Name: "golang.org/x/text", Version: "v0.3.7", PURL: "pkg:golang/golang.org/x/text@v0.3.7"}}

	vulns := AggregateExploitationSignals(findings, nil, epss, nil, components, 0.7)
	require.Len(t, vulns, 1)
	require.Len(t, vulns[0].Signals, 1)
	assert.Equal(t, ExploitationEPSS, vulns[0].Signals[0].Source)
	assert.Contains(t, vulns[0].Signals[0].Detail, "0.85")
}

func TestAggregateSignals_EPSSBelowThreshold(t *testing.T) {
	findings := []formats.Finding{
		{CVE: "CVE-2022-32149", Severity: "high", CVSS: 7.5, AffectedPURL: "pkg:golang/golang.org/x/text@v0.3.7"},
	}
	epss := &EPSSData{Scores: map[string]float64{"CVE-2022-32149": 0.3}}
	components := []formats.Component{{PURL: "pkg:golang/golang.org/x/text@v0.3.7"}}

	vulns := AggregateExploitationSignals(findings, nil, epss, nil, components, 0.7)
	assert.Empty(t, vulns)
}

func TestAggregateSignals_ManualOverride(t *testing.T) {
	findings := []formats.Finding{
		{CVE: "CVE-2022-32149", Severity: "high", CVSS: 7.5, AffectedPURL: "pkg:golang/golang.org/x/text@v0.3.7"},
	}
	overrides := []ExploitationOverride{
		{CVE: "CVE-2022-32149", Source: "manual", Reason: "Internal threat intel"},
	}
	components := []formats.Component{{Name: "golang.org/x/text", Version: "v0.3.7", PURL: "pkg:golang/golang.org/x/text@v0.3.7"}}

	vulns := AggregateExploitationSignals(findings, nil, nil, overrides, components, 0.7)
	require.Len(t, vulns, 1)
	require.Len(t, vulns[0].Signals, 1)
	assert.Equal(t, ExploitationManual, vulns[0].Signals[0].Source)
	assert.Equal(t, "Internal threat intel", vulns[0].Signals[0].Detail)
}

func TestAggregateSignals_MultipleSignals(t *testing.T) {
	findings := []formats.Finding{
		{CVE: "CVE-2022-32149", Severity: "high", CVSS: 7.5, AffectedPURL: "pkg:golang/golang.org/x/text@v0.3.7"},
	}
	kev := &policykit.KEVCatalog{CVEs: map[string]bool{"CVE-2022-32149": true}}
	epss := &EPSSData{Scores: map[string]float64{"CVE-2022-32149": 0.95}}
	components := []formats.Component{{PURL: "pkg:golang/golang.org/x/text@v0.3.7"}}

	vulns := AggregateExploitationSignals(findings, kev, epss, nil, components, 0.7)
	require.Len(t, vulns, 1)
	// Both KEV and EPSS signals should be recorded
	assert.Len(t, vulns[0].Signals, 2)
}

func TestAggregateSignals_NoSignals(t *testing.T) {
	findings := []formats.Finding{
		{CVE: "CVE-2022-32149", Severity: "high", CVSS: 7.5, AffectedPURL: "pkg:golang/golang.org/x/text@v0.3.7"},
	}
	components := []formats.Component{{PURL: "pkg:golang/golang.org/x/text@v0.3.7"}}

	vulns := AggregateExploitationSignals(findings, nil, nil, nil, components, 0.7)
	assert.Empty(t, vulns)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/report/ -run TestAggregateSignals -v`
Expected: FAIL — `AggregateExploitationSignals` not defined

- [ ] **Step 3: Implement signal aggregator**

Create `pkg/report/signals.go`:

```go
package report

import (
	"fmt"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/policykit"
)

// AggregateExploitationSignals collects exploitation signals from KEV, EPSS, and manual
// overrides for each finding. Returns only findings with at least one signal.
// This supports the manufacturer's determination per Art. 14(1) — it does NOT make
// the regulatory determination itself.
func AggregateExploitationSignals(
	findings []formats.Finding,
	kev *policykit.KEVCatalog,
	epss *EPSSData,
	overrides []ExploitationOverride,
	components []formats.Component,
	epssThreshold float64,
) []ExploitedVuln {
	// Build manual override lookup.
	manualLookup := make(map[string]ExploitationOverride, len(overrides))
	for _, o := range overrides {
		manualLookup[o.CVE] = o
	}

	// Build component lookup for affected product info.
	componentByPURL := make(map[string]formats.Component, len(components))
	for _, c := range components {
		if c.PURL != "" {
			componentByPURL[c.PURL] = c
		}
	}

	// Deduplicate findings by CVE (scanners may report same CVE multiple times).
	seen := make(map[string]bool)
	var result []ExploitedVuln

	for i := range findings {
		f := &findings[i]
		if seen[f.CVE] {
			continue
		}

		var signals []ExploitationSignal

		// Check KEV.
		if kev != nil && kev.Contains(f.CVE) {
			signals = append(signals, ExploitationSignal{
				Source: ExploitationKEV,
				Detail: "Listed in CISA Known Exploited Vulnerabilities catalog",
			})
		}

		// Check manual overrides.
		if o, ok := manualLookup[f.CVE]; ok {
			signals = append(signals, ExploitationSignal{
				Source: ExploitationManual,
				Detail: o.Reason,
			})
		}

		// Check EPSS.
		if epss != nil {
			if score, ok := epss.Scores[f.CVE]; ok && score >= epssThreshold {
				signals = append(signals, ExploitationSignal{
					Source: ExploitationEPSS,
					Detail: fmt.Sprintf("EPSS score %.4f (threshold %.2f)", score, epssThreshold),
				})
			}
		}

		if len(signals) == 0 {
			continue
		}

		seen[f.CVE] = true

		// Build affected products from component lookup.
		var affected []AffectedProduct
		comp, ok := componentByPURL[f.AffectedPURL]
		if ok {
			affected = append(affected, AffectedProduct{
				Name:    comp.Name,
				Version: comp.Version,
				PURL:    comp.PURL,
			})
		} else if f.AffectedPURL != "" {
			affected = append(affected, AffectedProduct{
				Name:    f.AffectedName,
				Version: "",
				PURL:    f.AffectedPURL,
			})
		}

		result = append(result, ExploitedVuln{
			CVE:              f.CVE,
			Signals:          signals,
			AffectedProducts: affected,
			Severity:         f.Severity,
			CVSS:             f.CVSS,
			CVSSVector:       f.CVSSVector,
			Description:      f.Description,
			FixVersion:       f.FixVersion,
		})
	}

	return result
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/report/ -run TestAggregateSignals -v`
Expected: All PASS

- [ ] **Step 5: Run quality gates and commit**

Run: `task quality`

```bash
git add pkg/report/signals.go pkg/report/signals_test.go
git commit -m "feat(report): add exploitation signal aggregator (KEV/EPSS/manual)"
```

---

### Task 7: Stage builders (early warning, notification, final report)

**Files:**
- Create: `pkg/report/early_warning_test.go`
- Create: `pkg/report/early_warning.go`
- Create: `pkg/report/notification_test.go`
- Create: `pkg/report/notification.go`
- Create: `pkg/report/final_report_test.go`
- Create: `pkg/report/final_report.go`

- [ ] **Step 1: Write the failing early warning test**

Create `pkg/report/early_warning_test.go`:

```go
package report

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildEarlyWarning(t *testing.T) {
	vulns := []ExploitedVuln{
		{
			CVE:      "CVE-2022-32149",
			Signals:  []ExploitationSignal{{Source: ExploitationKEV, Detail: "In KEV catalog"}},
			Severity: "high",
			CVSS:     7.5,
			AffectedProducts: []AffectedProduct{
				{Name: "golang.org/x/text", Version: "v0.3.7", PURL: "pkg:golang/golang.org/x/text@v0.3.7"},
			},
		},
	}
	mfr := Manufacturer{
		Name:                  "SUSE LLC",
		MemberState:           "DE",
		MemberStatesAvailable: []string{"DE", "FR"},
	}

	entries := BuildEarlyWarning(vulns, mfr)
	require.Len(t, entries, 1)
	assert.Equal(t, "CVE-2022-32149", entries[0].CVE)
	assert.Len(t, entries[0].ExploitationSignals, 1)
	assert.Equal(t, ExploitationKEV, entries[0].ExploitationSignals[0].Source)
	assert.Equal(t, "high", entries[0].Severity)
	assert.InDelta(t, 7.5, entries[0].CVSS, 0.01)
	assert.Len(t, entries[0].AffectedProducts, 1)
	assert.Equal(t, []string{"DE", "FR"}, entries[0].MemberStates)
	// 72h/14d fields should be empty
	assert.Empty(t, entries[0].Description)
	assert.Empty(t, entries[0].RootCause)
}
```

- [ ] **Step 2: Implement early warning builder**

Create `pkg/report/early_warning.go`:

```go
package report

// BuildEarlyWarning creates VulnEntry values for the 24h early warning stage.
// Per Art. 14(2)(a): CVE, exploitation signals, severity, affected products, member states.
func BuildEarlyWarning(vulns []ExploitedVuln, mfr Manufacturer) []VulnEntry {
	entries := make([]VulnEntry, 0, len(vulns))
	for _, v := range vulns {
		entries = append(entries, VulnEntry{
			CVE:                 v.CVE,
			ExploitationSignals: v.Signals,
			Severity:            v.Severity,
			CVSS:                v.CVSS,
			AffectedProducts:    v.AffectedProducts,
			MemberStates:        mfr.MemberStatesAvailable,
		})
	}
	return entries
}
```

- [ ] **Step 3: Write the failing notification test**

Create `pkg/report/notification_test.go`:

```go
package report

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildNotification(t *testing.T) {
	vulns := []ExploitedVuln{
		{
			CVE:         "CVE-2022-32149",
			Signals:     []ExploitationSignal{{Source: ExploitationKEV, Detail: "In KEV"}},
			Severity:    "high",
			CVSS:        7.5,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
			Description: "DoS via crafted Accept-Language header",
			FixVersion:  "0.3.8",
			AffectedProducts: []AffectedProduct{
				{Name: "golang.org/x/text", Version: "v0.3.7", PURL: "pkg:golang/golang.org/x/text@v0.3.7"},
			},
		},
	}
	mfr := Manufacturer{Name: "SUSE LLC", MemberState: "DE", MemberStatesAvailable: []string{"DE"}}
	components := []formats.Component{
		{Name: "golang.org/x/text", Version: "v0.3.7", PURL: "pkg:golang/golang.org/x/text@v0.3.7"},
		{Name: "example.com/app", Version: "1.0.0", PURL: "pkg:golang/example.com/app@1.0.0"},
	}
	var vexResults []formats.VEXResult

	entries := BuildNotification(vulns, mfr, components, vexResults)
	require.Len(t, entries, 1)

	e := entries[0]
	assert.Equal(t, "DoS via crafted Accept-Language header", e.Description)
	assert.NotEmpty(t, e.GeneralNature)
	assert.Contains(t, e.CorrectiveActions, "Update golang.org/x/text to version 0.3.8")
	assert.NotNil(t, e.EstimatedImpact)
	assert.Equal(t, 2, e.EstimatedImpact.AffectedComponentCount)
	assert.Equal(t, "high", e.InformationSensitivity)
	// 14d fields still empty
	assert.Empty(t, e.RootCause)
}
```

- [ ] **Step 4: Implement notification builder**

Create `pkg/report/notification.go`:

```go
package report

import (
	"fmt"
	"strings"

	"github.com/ravan/cra-toolkit/pkg/formats"
)

// BuildNotification creates VulnEntry values for the 72h notification stage.
// Per Art. 14(2)(b): everything from early warning plus description, general nature,
// corrective actions, mitigating measures, estimated impact, sensitivity.
func BuildNotification(vulns []ExploitedVuln, mfr Manufacturer, components []formats.Component, vexResults []formats.VEXResult) []VulnEntry {
	// Build VEX lookup for mitigating measures.
	vexByCV := make(map[string]formats.VEXResult, len(vexResults))
	for _, vr := range vexResults {
		vexByCV[vr.CVE] = vr
	}

	impact := &Impact{
		AffectedComponentCount: len(components),
		SeverityDistribution:   buildSeverityDistribution(vulns),
	}

	entries := make([]VulnEntry, 0, len(vulns))
	for _, v := range vulns {
		e := VulnEntry{
			CVE:                    v.CVE,
			ExploitationSignals:    v.Signals,
			Severity:               v.Severity,
			CVSS:                   v.CVSS,
			AffectedProducts:       v.AffectedProducts,
			MemberStates:           mfr.MemberStatesAvailable,
			Description:            v.Description,
			GeneralNature:          buildGeneralNature(v.Description, v.CVSSVector),
			EstimatedImpact:        impact,
			InformationSensitivity: "high",
		}

		if v.FixVersion != "" {
			name := "affected component"
			if len(v.AffectedProducts) > 0 {
				name = v.AffectedProducts[0].Name
			}
			e.CorrectiveActions = []string{
				fmt.Sprintf("Update %s to version %s", name, v.FixVersion),
			}
		}

		if vr, ok := vexByCV[v.CVE]; ok && vr.Evidence != "" {
			e.MitigatingMeasures = []string{vr.Evidence}
		}

		entries = append(entries, e)
	}
	return entries
}

// buildGeneralNature derives the general nature of the exploit from the CVE description
// and CVSS vector. The CVE description is the primary source per our design spec.
func buildGeneralNature(description, cvssVector string) string {
	if description == "" {
		return ""
	}

	// Start with the CVE description as the general nature.
	nature := description

	// Supplement with structured CVSS metadata if available.
	if cvssVector != "" {
		var supplements []string
		if strings.Contains(cvssVector, "AV:N") {
			supplements = append(supplements, "network-accessible")
		} else if strings.Contains(cvssVector, "AV:L") {
			supplements = append(supplements, "local access required")
		}
		if strings.Contains(cvssVector, "AC:L") {
			supplements = append(supplements, "low complexity")
		}
		if strings.Contains(cvssVector, "PR:N") {
			supplements = append(supplements, "no authentication required")
		}
		if len(supplements) > 0 {
			nature += " (" + strings.Join(supplements, ", ") + ")"
		}
	}

	return nature
}

func buildSeverityDistribution(vulns []ExploitedVuln) map[string]int {
	dist := make(map[string]int)
	for _, v := range vulns {
		if v.Severity != "" {
			dist[v.Severity]++
		}
	}
	return dist
}
```

- [ ] **Step 5: Write the failing final report test**

Create `pkg/report/final_report_test.go`:

```go
package report

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildFinalReport_WithHumanInput(t *testing.T) {
	vulns := []ExploitedVuln{
		{
			CVE:         "CVE-2022-32149",
			Signals:     []ExploitationSignal{{Source: ExploitationKEV, Detail: "In KEV"}},
			Severity:    "high",
			CVSS:        7.5,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
			Description: "DoS via crafted Accept-Language header",
			FixVersion:  "0.3.8",
			AffectedProducts: []AffectedProduct{
				{Name: "golang.org/x/text", Version: "v0.3.7", PURL: "pkg:golang/golang.org/x/text@v0.3.7"},
			},
		},
	}
	mfr := Manufacturer{Name: "SUSE LLC", MemberState: "DE", MemberStatesAvailable: []string{"DE"}}
	components := []formats.Component{{Name: "golang.org/x/text", Version: "v0.3.7", PURL: "pkg:golang/golang.org/x/text@v0.3.7"}}
	human := &HumanInput{
		Vulnerabilities: map[string]HumanVulnInput{
			"CVE-2022-32149": {
				CorrectiveMeasureDate: "2022-10-11",
				RootCause:             "Algorithmic complexity in ParseAcceptLanguage",
				ThreatActorInfo:       "No specific threat actor identified",
				SecurityUpdate:        "golang.org/x/text v0.3.8",
				PreventiveMeasures:    []string{"Input length limiting"},
			},
		},
	}

	entries := BuildFinalReport(vulns, mfr, components, nil, human, "")
	require.Len(t, entries, 1)

	e := entries[0]
	assert.Equal(t, "2022-10-11", e.CorrectiveMeasureDate)
	assert.Equal(t, "Algorithmic complexity in ParseAcceptLanguage", e.RootCause)
	assert.Equal(t, "No specific threat actor identified", e.ThreatActorInfo)
	assert.Equal(t, "golang.org/x/text v0.3.8", e.SecurityUpdate)
	assert.Equal(t, []string{"Input length limiting"}, e.PreventiveMeasures)
}

func TestBuildFinalReport_WithoutHumanInput(t *testing.T) {
	vulns := []ExploitedVuln{
		{CVE: "CVE-2022-32149", Signals: []ExploitationSignal{{Source: ExploitationKEV, Detail: "In KEV"}}, Severity: "high", CVSS: 7.5, Description: "DoS"},
	}
	mfr := Manufacturer{Name: "SUSE LLC", MemberState: "DE"}

	entries := BuildFinalReport(vulns, mfr, nil, nil, nil, "")
	require.Len(t, entries, 1)

	e := entries[0]
	assert.Equal(t, "[HUMAN INPUT REQUIRED]", e.RootCause)
	assert.Equal(t, "[HUMAN INPUT REQUIRED]", e.ThreatActorInfo)
}

func TestBuildFinalReport_CorrectiveMeasureDateFromFlag(t *testing.T) {
	vulns := []ExploitedVuln{
		{CVE: "CVE-2022-32149", Signals: []ExploitationSignal{{Source: ExploitationKEV, Detail: "In KEV"}}, Severity: "high"},
	}
	mfr := Manufacturer{Name: "SUSE LLC", MemberState: "DE"}

	entries := BuildFinalReport(vulns, mfr, nil, nil, nil, "2022-10-15")
	require.Len(t, entries, 1)
	assert.Equal(t, "2022-10-15", entries[0].CorrectiveMeasureDate)
}
```

- [ ] **Step 6: Implement final report builder**

Create `pkg/report/final_report.go`:

```go
package report

import "github.com/ravan/cra-toolkit/pkg/formats"

const humanInputRequired = "[HUMAN INPUT REQUIRED]"

// BuildFinalReport creates VulnEntry values for the 14-day final report stage.
// Per Art. 14(2)(c): everything from notification plus root cause, threat actor info,
// security update details, corrective measures, preventive measures.
// Human input is merged where available; missing fields get placeholders.
func BuildFinalReport(
	vulns []ExploitedVuln,
	mfr Manufacturer,
	components []formats.Component,
	vexResults []formats.VEXResult,
	human *HumanInput,
	correctiveMeasureDate string,
) []VulnEntry {
	// Start with notification-level enrichment.
	entries := BuildNotification(vulns, mfr, components, vexResults)

	for i := range entries {
		e := &entries[i]

		// Merge human input if available.
		var hi HumanVulnInput
		if human != nil {
			hi = human.Vulnerabilities[e.CVE]
		}

		// Corrective measure date: CLI flag overrides human input.
		e.CorrectiveMeasureDate = correctiveMeasureDate
		if e.CorrectiveMeasureDate == "" {
			e.CorrectiveMeasureDate = hi.CorrectiveMeasureDate
		}

		// Human-authored fields with placeholders.
		e.RootCause = hi.RootCause
		if e.RootCause == "" {
			e.RootCause = humanInputRequired
		}

		e.ThreatActorInfo = hi.ThreatActorInfo
		if e.ThreatActorInfo == "" {
			e.ThreatActorInfo = humanInputRequired
		}

		if hi.SecurityUpdate != "" {
			e.SecurityUpdate = hi.SecurityUpdate
		} else if len(e.CorrectiveActions) > 0 {
			e.SecurityUpdate = e.CorrectiveActions[0]
		} else {
			e.SecurityUpdate = humanInputRequired
		}

		if len(hi.PreventiveMeasures) > 0 {
			e.PreventiveMeasures = hi.PreventiveMeasures
		}
	}

	return entries
}
```

- [ ] **Step 7: Run all stage builder tests**

Run: `go test ./pkg/report/ -run "TestBuild(EarlyWarning|Notification|FinalReport)" -v`
Expected: All PASS

- [ ] **Step 8: Run quality gates and commit**

Run: `task quality`

```bash
git add pkg/report/early_warning.go pkg/report/early_warning_test.go \
       pkg/report/notification.go pkg/report/notification_test.go \
       pkg/report/final_report.go pkg/report/final_report_test.go
git commit -m "feat(report): add stage builders for early warning, notification, and final report"
```

---

### Task 8: User notification, completeness, and markdown renderer

**Files:**
- Create: `pkg/report/user_notify_test.go`, `pkg/report/user_notify.go`
- Create: `pkg/report/completeness_test.go`, `pkg/report/completeness.go`
- Create: `pkg/report/render_test.go`, `pkg/report/render.go`

- [ ] **Step 1: Write failing user notification test**

Create `pkg/report/user_notify_test.go`:

```go
package report

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildUserNotification(t *testing.T) {
	vulns := []ExploitedVuln{
		{
			CVE:      "CVE-2022-32149",
			Severity: "high",
			CVSS:     7.5,
			AffectedProducts: []AffectedProduct{
				{Name: "golang.org/x/text", Version: "v0.3.7", PURL: "pkg:golang/golang.org/x/text@v0.3.7"},
			},
			FixVersion: "0.3.8",
		},
	}

	un := BuildUserNotification(vulns, "CSAF-ADV-2026-001")
	require.NotNil(t, un)
	assert.Len(t, un.AffectedProducts, 1)
	assert.Equal(t, "high", un.Severity)
	assert.Equal(t, "CSAF-ADV-2026-001", un.CSAFAdvisoryRef)
	assert.NotEmpty(t, un.RecommendedActions)
}

func TestBuildUserNotification_NoRef(t *testing.T) {
	vulns := []ExploitedVuln{{CVE: "CVE-2022-32149", Severity: "high"}}
	un := BuildUserNotification(vulns, "")
	assert.Empty(t, un.CSAFAdvisoryRef)
}
```

- [ ] **Step 2: Implement user notification builder**

Create `pkg/report/user_notify.go`:

```go
package report

import "fmt"

// BuildUserNotification creates the Art. 14(8) user notification section.
func BuildUserNotification(vulns []ExploitedVuln, csafRef string) *UserNotification {
	var allProducts []AffectedProduct
	var maxSeverity string
	var actions []string

	for _, v := range vulns {
		allProducts = append(allProducts, v.AffectedProducts...)
		if compareSeverity(v.Severity, maxSeverity) > 0 {
			maxSeverity = v.Severity
		}
		if v.FixVersion != "" {
			name := v.CVE
			if len(v.AffectedProducts) > 0 {
				name = v.AffectedProducts[0].Name
			}
			actions = append(actions, fmt.Sprintf("Update %s to version %s or later", name, v.FixVersion))
		}
	}

	if len(actions) == 0 {
		actions = []string{"Monitor vendor advisories for patches and mitigations"}
	}

	return &UserNotification{
		AffectedProducts:   allProducts,
		RecommendedActions: actions,
		Severity:           maxSeverity,
		CSAFAdvisoryRef:    csafRef,
	}
}

func compareSeverity(a, b string) int {
	order := map[string]int{"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	return order[a] - order[b]
}
```

- [ ] **Step 3: Write failing completeness test**

Create `pkg/report/completeness_test.go`:

```go
package report

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComputeCompleteness_EarlyWarning(t *testing.T) {
	n := &Notification{
		Stage: StageEarlyWarning,
		Vulnerabilities: []VulnEntry{
			{
				CVE:                 "CVE-2022-32149",
				ExploitationSignals: []ExploitationSignal{{Source: ExploitationKEV}},
				Severity:            "high",
				CVSS:                7.5,
				AffectedProducts:    []AffectedProduct{{Name: "test"}},
				MemberStates:        []string{"DE"},
			},
		},
	}

	c := ComputeCompleteness(n)
	assert.InDelta(t, 1.0, c.Score, 0.01)
	assert.Empty(t, c.Pending)
	assert.Equal(t, CompletenessNote, c.Note)
}

func TestComputeCompleteness_FinalReportWithPlaceholders(t *testing.T) {
	n := &Notification{
		Stage: StageFinalReport,
		Vulnerabilities: []VulnEntry{
			{
				CVE:         "CVE-2022-32149",
				Severity:    "high",
				RootCause:   humanInputRequired,
				ThreatActorInfo: humanInputRequired,
				SecurityUpdate:  humanInputRequired,
			},
		},
	}

	c := ComputeCompleteness(n)
	assert.Less(t, c.Score, 1.0)
	assert.NotEmpty(t, c.Pending)
	assert.Equal(t, CompletenessNote, c.Note)
}
```

- [ ] **Step 4: Implement completeness calculator**

Create `pkg/report/completeness.go`:

```go
package report

// ComputeCompleteness calculates the toolkit quality metric for a notification.
// This is NOT a regulatory compliance measure.
func ComputeCompleteness(n *Notification) Completeness {
	var total, filled, machine, human int
	var pending []string

	for _, v := range n.Vulnerabilities {
		fields := completenessFields(n.Stage, &v)
		for _, f := range fields {
			total++
			if f.filled {
				filled++
				if f.source == "human" {
					human++
				} else {
					machine++
				}
			} else {
				pending = append(pending, f.name)
			}
		}
	}

	score := 0.0
	if total > 0 {
		score = float64(filled) / float64(total)
	}

	return Completeness{
		Score:            score,
		TotalFields:      total,
		FilledFields:     filled,
		MachineGenerated: machine,
		HumanProvided:    human,
		Pending:          pending,
		Note:             CompletenessNote,
	}
}

type fieldCheck struct {
	name   string
	filled bool
	source string // "machine" or "human"
}

func completenessFields(stage Stage, v *VulnEntry) []fieldCheck { //nolint:gocyclo // field enumeration by stage
	var fields []fieldCheck

	// Early warning fields (all stages).
	fields = append(fields,
		fieldCheck{"cve", v.CVE != "", "machine"},
		fieldCheck{"exploitation_signals", len(v.ExploitationSignals) > 0, "machine"},
		fieldCheck{"severity", v.Severity != "", "machine"},
		fieldCheck{"affected_products", len(v.AffectedProducts) > 0, "machine"},
	)

	if stage == StageEarlyWarning {
		return fields
	}

	// Notification fields (72h+).
	fields = append(fields,
		fieldCheck{"description", v.Description != "", "machine"},
		fieldCheck{"general_nature", v.GeneralNature != "", "machine"},
		fieldCheck{"corrective_actions", len(v.CorrectiveActions) > 0, "machine"},
		fieldCheck{"estimated_impact", v.EstimatedImpact != nil, "machine"},
		fieldCheck{"information_sensitivity", v.InformationSensitivity != "", "machine"},
	)

	if stage == StageNotification {
		return fields
	}

	// Final report fields (14d).
	fields = append(fields,
		fieldCheck{"corrective_measure_date", v.CorrectiveMeasureDate != "", "human"},
		fieldCheck{"root_cause", v.RootCause != "" && v.RootCause != humanInputRequired, "human"},
		fieldCheck{"threat_actor_info", v.ThreatActorInfo != "" && v.ThreatActorInfo != humanInputRequired, "human"},
		fieldCheck{"security_update", v.SecurityUpdate != "" && v.SecurityUpdate != humanInputRequired, "human"},
	)

	return fields
}
```

- [ ] **Step 5: Write failing render test**

Create `pkg/report/render_test.go`:

```go
package report

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRenderMarkdown(t *testing.T) {
	n := &Notification{
		NotificationID:    "CRA-NOTIF-TEST",
		ToolkitVersion:    "0.1.0",
		Timestamp:         "2026-04-04T12:00:00Z",
		Stage:             StageEarlyWarning,
		CRAReference:      "Art. 14(2)(a)",
		SubmissionChannel: SubmissionChannelENISA,
		Manufacturer:      Manufacturer{Name: "SUSE LLC", MemberState: "DE"},
		CSIRTCoordinator:  CSIRTInfo{Name: "BSI (CERT-Bund)", Country: "DE", SubmissionChannel: SubmissionChannelENISA},
		Vulnerabilities: []VulnEntry{
			{
				CVE:                 "CVE-2022-32149",
				ExploitationSignals: []ExploitationSignal{{Source: ExploitationKEV, Detail: "In KEV catalog"}},
				Severity:            "high",
				CVSS:                7.5,
				AffectedProducts:    []AffectedProduct{{Name: "golang.org/x/text", Version: "v0.3.7"}},
			},
		},
		Completeness: Completeness{Score: 1.0, TotalFields: 4, FilledFields: 4, Note: CompletenessNote},
	}

	md := RenderMarkdown(n)
	assert.Contains(t, md, "CRA Article 14 Vulnerability Notification")
	assert.Contains(t, md, "CRA-NOTIF-TEST")
	assert.Contains(t, md, "Early Warning")
	assert.Contains(t, md, "Art. 14(2)(a)")
	assert.Contains(t, md, "ENISA Single Reporting Platform")
	assert.Contains(t, md, "BSI (CERT-Bund)")
	assert.Contains(t, md, "CVE-2022-32149")
	assert.Contains(t, md, "KEV")
	assert.Contains(t, md, "Toolkit quality metric")
	// Check the regulatory honesty notes are present
	assert.True(t, strings.Contains(md, "manufacturer") && strings.Contains(md, "determination"))
}
```

- [ ] **Step 6: Implement markdown renderer**

Create `pkg/report/render.go`:

```go
package report

import (
	"fmt"
	"strings"
)

// RenderMarkdown produces a human-readable markdown notification document.
func RenderMarkdown(n *Notification) string { //nolint:gocognit,gocyclo // markdown rendering iterates multiple sections
	var b strings.Builder

	b.WriteString("# CRA Article 14 Vulnerability Notification\n\n")

	// Metadata.
	b.WriteString("## Metadata\n\n")
	b.WriteString("| Field | Value |\n| --- | --- |\n")
	b.WriteString(fmt.Sprintf("| Notification ID | %s |\n", n.NotificationID))
	b.WriteString(fmt.Sprintf("| Stage | %s — %s |\n", stageLabel(n.Stage), n.CRAReference))
	b.WriteString(fmt.Sprintf("| Generated | %s |\n", n.Timestamp))
	b.WriteString(fmt.Sprintf("| Submission Channel | %s |\n", n.SubmissionChannel))
	b.WriteString(fmt.Sprintf("| Toolkit Version | %s |\n", n.ToolkitVersion))
	b.WriteString("\n")

	// Manufacturer.
	b.WriteString("## Manufacturer\n\n")
	b.WriteString("| Field | Value |\n| --- | --- |\n")
	b.WriteString(fmt.Sprintf("| Name | %s |\n", n.Manufacturer.Name))
	b.WriteString(fmt.Sprintf("| Member State | %s |\n", n.Manufacturer.MemberState))
	if n.Manufacturer.ContactEmail != "" {
		b.WriteString(fmt.Sprintf("| Contact | %s |\n", n.Manufacturer.ContactEmail))
	}
	b.WriteString("\n")

	// CSIRT Coordinator.
	b.WriteString("## CSIRT Coordinator (Informational)\n\n")
	b.WriteString("| Field | Value |\n| --- | --- |\n")
	b.WriteString(fmt.Sprintf("| CSIRT | %s |\n", n.CSIRTCoordinator.Name))
	b.WriteString(fmt.Sprintf("| Country | %s |\n", n.CSIRTCoordinator.Country))
	b.WriteString("\n> **Note:** Per Art. 14(7), this notification is submitted via the ENISA Single\n")
	b.WriteString("> Reporting Platform, which routes to the CSIRT coordinator simultaneously with ENISA.\n\n")

	// Vulnerabilities.
	b.WriteString("## Vulnerabilities with Exploitation Signals\n\n")
	for _, v := range n.Vulnerabilities {
		b.WriteString(fmt.Sprintf("### %s\n\n", v.CVE))

		// Signals.
		var signalParts []string
		for _, s := range v.ExploitationSignals {
			signalParts = append(signalParts, fmt.Sprintf("%s (%s)", strings.ToUpper(string(s.Source)), s.Detail))
		}
		b.WriteString(fmt.Sprintf("- **Exploitation Signals:** %s\n", strings.Join(signalParts, "; ")))
		b.WriteString(fmt.Sprintf("- **Severity:** %s (CVSS %.1f)\n", strings.Title(v.Severity), v.CVSS)) //nolint:staticcheck // strings.Title is fine for severity labels
		for _, p := range v.AffectedProducts {
			b.WriteString(fmt.Sprintf("- **Affected:** %s %s\n", p.Name, p.Version))
		}

		// Notification-level fields.
		if v.Description != "" {
			b.WriteString(fmt.Sprintf("- **Description:** %s\n", v.Description))
		}
		if len(v.CorrectiveActions) > 0 {
			b.WriteString(fmt.Sprintf("- **Corrective Actions:** %s\n", strings.Join(v.CorrectiveActions, "; ")))
		}

		// Final report fields.
		if v.CorrectiveMeasureDate != "" {
			b.WriteString(fmt.Sprintf("- **Corrective Measure Available:** %s\n", v.CorrectiveMeasureDate))
		}
		if v.RootCause != "" {
			b.WriteString(fmt.Sprintf("- **Root Cause:** %s\n", v.RootCause))
		}
		if v.ThreatActorInfo != "" {
			b.WriteString(fmt.Sprintf("- **Threat Actor Info:** %s\n", v.ThreatActorInfo))
		}
		if v.SecurityUpdate != "" {
			b.WriteString(fmt.Sprintf("- **Security Update:** %s\n", v.SecurityUpdate))
		}

		b.WriteString("\n")
	}

	b.WriteString("> **Note:** Exploitation signals are provided to support the manufacturer's\n")
	b.WriteString("> determination per Art. 14(1). The manufacturer is responsible for the\n")
	b.WriteString("> regulatory decision to notify.\n\n")

	// User notification.
	if n.UserNotification != nil {
		b.WriteString("## User Notification (Art. 14(8))\n\n")
		b.WriteString(fmt.Sprintf("- **Severity:** %s\n", n.UserNotification.Severity))
		if n.UserNotification.CSAFAdvisoryRef != "" {
			b.WriteString(fmt.Sprintf("- **CSAF Advisory:** %s\n", n.UserNotification.CSAFAdvisoryRef))
		}
		for _, a := range n.UserNotification.RecommendedActions {
			b.WriteString(fmt.Sprintf("- **Action:** %s\n", a))
		}
		b.WriteString("\n")
	}

	// Completeness.
	b.WriteString("## Completeness (Toolkit Quality Metric)\n\n")
	b.WriteString("| Metric | Value |\n| --- | --- |\n")
	b.WriteString(fmt.Sprintf("| Score | %.0f%% |\n", n.Completeness.Score*100))
	b.WriteString(fmt.Sprintf("| Machine Generated | %d |\n", n.Completeness.MachineGenerated))
	b.WriteString(fmt.Sprintf("| Human Provided | %d |\n", n.Completeness.HumanProvided))
	b.WriteString(fmt.Sprintf("| Pending | %d |\n", len(n.Completeness.Pending)))
	b.WriteString(fmt.Sprintf("\n> %s\n", CompletenessNote))

	return b.String()
}

func stageLabel(s Stage) string {
	switch s {
	case StageEarlyWarning:
		return "Early Warning (24h)"
	case StageNotification:
		return "Notification (72h)"
	case StageFinalReport:
		return "Final Report (14d)"
	default:
		return string(s)
	}
}
```

- [ ] **Step 7: Run all tests**

Run: `go test ./pkg/report/ -run "TestBuildUserNotification|TestComputeCompleteness|TestRenderMarkdown" -v`
Expected: All PASS

- [ ] **Step 8: Run quality gates and commit**

Run: `task quality`

```bash
git add pkg/report/user_notify.go pkg/report/user_notify_test.go \
       pkg/report/completeness.go pkg/report/completeness_test.go \
       pkg/report/render.go pkg/report/render_test.go
git commit -m "feat(report): add user notification, completeness calculator, and markdown renderer"
```

---

### Task 9: Run pipeline and CLI wiring

**Files:**
- Modify: `pkg/report/report.go` (replace stub)
- Modify: `internal/cli/report.go` (replace stub)

- [ ] **Step 1: Replace report.go stub with full pipeline**

Replace the contents of `pkg/report/report.go`:

```go
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/formats/cyclonedx"
	"github.com/ravan/cra-toolkit/pkg/formats/grype"
	"github.com/ravan/cra-toolkit/pkg/formats/sarif"
	"github.com/ravan/cra-toolkit/pkg/formats/spdx"
	"github.com/ravan/cra-toolkit/pkg/formats/trivy"
	"github.com/ravan/cra-toolkit/pkg/formats/csafvex"
	"github.com/ravan/cra-toolkit/pkg/formats/openvex"
	"github.com/ravan/cra-toolkit/pkg/policykit"
)

// Run executes the Art. 14 notification generation pipeline.
func Run(opts *Options, out io.Writer) error { //nolint:gocognit,gocyclo // pipeline has many sequential stages
	// 1. Parse inputs.
	components, err := parseSBOM(opts.SBOMPath)
	if err != nil {
		return fmt.Errorf("parse SBOM: %w", err)
	}

	var findings []formats.Finding
	for _, path := range opts.ScanPaths {
		f, err := parseScan(path)
		if err != nil {
			return fmt.Errorf("parse scan %s: %w", path, err)
		}
		findings = append(findings, f...)
	}

	cfg, err := LoadReportConfig(opts.ProductConfig)
	if err != nil {
		return fmt.Errorf("load product config: %w", err)
	}

	kev, err := policykit.LoadKEV(opts.KEVPath)
	if err != nil {
		return fmt.Errorf("load KEV: %w", err)
	}

	epss, err := LoadEPSS(opts.EPSSPath)
	if err != nil {
		return fmt.Errorf("load EPSS: %w", err)
	}

	var vexResults []formats.VEXResult
	if opts.VEXPath != "" {
		vr, err := parseVEXResults(opts.VEXPath)
		if err != nil {
			return fmt.Errorf("parse VEX: %w", err)
		}
		vexResults = vr
	}

	human, err := LoadHumanInput(opts.HumanInputPath)
	if err != nil {
		return fmt.Errorf("load human input: %w", err)
	}

	// 2. Aggregate exploitation signals.
	threshold := opts.EPSSThreshold
	if threshold == 0 {
		threshold = 0.7
	}
	exploited := AggregateExploitationSignals(findings, kev, epss, cfg.ExploitationOverrides, components, threshold)
	if len(exploited) == 0 {
		return ErrNoExploitedVulns
	}

	// 3. Build stage.
	var entries []VulnEntry
	switch opts.Stage {
	case StageEarlyWarning:
		entries = BuildEarlyWarning(exploited, cfg.Manufacturer)
	case StageNotification:
		entries = BuildNotification(exploited, cfg.Manufacturer, components, vexResults)
	case StageFinalReport:
		entries = BuildFinalReport(exploited, cfg.Manufacturer, components, vexResults, human, opts.CorrectiveMeasureDate)
	default:
		return fmt.Errorf("report: unknown stage %q", opts.Stage)
	}

	// 4. Lookup CSIRT coordinator.
	csirt, err := LookupCSIRT(cfg.Manufacturer.MemberState)
	if err != nil {
		return fmt.Errorf("lookup CSIRT: %w", err)
	}

	// 5. Build user notification.
	userNotify := BuildUserNotification(exploited, opts.CSAFAdvisoryRef)

	// 6. Assemble notification.
	notification := &Notification{
		NotificationID:    "CRA-NOTIF-" + time.Now().UTC().Format("20060102T150405Z"),
		ToolkitVersion:    "0.1.0",
		Timestamp:         time.Now().UTC().Format(time.RFC3339),
		Stage:             opts.Stage,
		CRAReference:      opts.Stage.CRAReference(),
		SubmissionChannel: SubmissionChannelENISA,
		Manufacturer:      cfg.Manufacturer,
		CSIRTCoordinator:  csirt,
		Vulnerabilities:   entries,
		UserNotification:  userNotify,
	}

	// 7. Compute completeness.
	notification.Completeness = ComputeCompleteness(notification)

	// 8. Render output.
	if opts.OutputFormat == "markdown" {
		_, err := io.WriteString(out, RenderMarkdown(notification))
		return err
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(notification)
}

// --- File parsing helpers (same pattern as pkg/csaf and pkg/vex) ---

func openDetected(path string) (formats.Format, *os.File, error) {
	df, err := os.Open(path) //nolint:gosec // CLI flag
	if err != nil {
		return formats.FormatUnknown, nil, fmt.Errorf("open for detection: %w", err)
	}
	format, err := formats.DetectFormat(df)
	_ = df.Close()
	if err != nil {
		return formats.FormatUnknown, nil, fmt.Errorf("detect format: %w", err)
	}
	pf, err := os.Open(path) //nolint:gosec // CLI flag
	if err != nil {
		return formats.FormatUnknown, nil, fmt.Errorf("open for parsing: %w", err)
	}
	return format, pf, nil
}

func parseSBOM(path string) ([]formats.Component, error) {
	format, f, err := openDetected(path)
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
		return nil, fmt.Errorf("unsupported SBOM format: %s", format)
	}
}

func parseScan(path string) ([]formats.Finding, error) {
	format, f, err := openDetected(path)
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
		return nil, fmt.Errorf("unsupported scan format: %s", format)
	}
}

func parseVEXResults(path string) ([]formats.VEXResult, error) {
	stmts, err := parseVEXStatements(path)
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
			Confidence:    formats.ConfidenceHigh,
			ResolvedBy:    "upstream_vex",
			Evidence:      s.StatusNotes,
		})
	}
	return results, nil
}

func parseVEXStatements(path string) ([]formats.VEXStatement, error) {
	format, f, err := openDetected(path)
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

- [ ] **Step 2: Replace CLI wiring**

Replace `internal/cli/report.go`:

```go
package cli

import (
	"context"
	"fmt"

	urfave "github.com/urfave/cli/v3"

	"github.com/ravan/cra-toolkit/pkg/report"
)

func newReportCmd() *urfave.Command {
	return &urfave.Command{
		Name:  "report",
		Usage: "Generate CRA Article 14 vulnerability notification documents",
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
				Name:     "stage",
				Usage:    "notification stage: early-warning, notification, final-report",
				Required: true,
			},
			&urfave.StringFlag{
				Name:     "product-config",
				Usage:    "path to product config YAML with manufacturer section",
				Required: true,
			},
			&urfave.StringFlag{
				Name:  "kev",
				Usage: "path to local CISA KEV catalog JSON (auto-fetched if omitted)",
			},
			&urfave.StringFlag{
				Name:  "epss-path",
				Usage: "path to EPSS scores JSON (optional)",
			},
			&urfave.Float64Flag{
				Name:  "epss-threshold",
				Value: 0.7,
				Usage: "EPSS score threshold for exploitation signal (0.0-1.0)",
			},
			&urfave.StringFlag{
				Name:  "vex",
				Usage: "path to VEX results (OpenVEX or CSAF VEX)",
			},
			&urfave.StringFlag{
				Name:  "human-input",
				Usage: "path to human input YAML for 14-day final report",
			},
			&urfave.StringFlag{
				Name:  "csaf-advisory-ref",
				Usage: "companion CSAF advisory ID for Art. 14(8) user notification",
			},
			&urfave.StringFlag{
				Name:  "corrective-measure-date",
				Usage: "ISO 8601 date when corrective measure became available (Art. 14(2)(c))",
			},
			&urfave.StringFlag{
				Name:  "format",
				Value: "json",
				Usage: "output format: json or markdown",
			},
		},
		Action: func(_ context.Context, cmd *urfave.Command) error {
			stage, err := report.ParseStage(cmd.String("stage"))
			if err != nil {
				return err
			}

			outputFormat := cmd.String("format")
			if outputFormat != "json" && outputFormat != "markdown" {
				return fmt.Errorf("unsupported format %q: must be json or markdown", outputFormat)
			}

			opts := &report.Options{
				SBOMPath:              cmd.String("sbom"),
				ScanPaths:             cmd.StringSlice("scan"),
				Stage:                 stage,
				ProductConfig:         cmd.String("product-config"),
				KEVPath:               cmd.String("kev"),
				EPSSPath:              cmd.String("epss-path"),
				EPSSThreshold:         cmd.Float64("epss-threshold"),
				VEXPath:               cmd.String("vex"),
				HumanInputPath:        cmd.String("human-input"),
				CSAFAdvisoryRef:       cmd.String("csaf-advisory-ref"),
				CorrectiveMeasureDate: cmd.String("corrective-measure-date"),
				OutputFormat:          outputFormat,
			}

			w, closer := OutputWriter(cmd)
			defer closer() //nolint:errcheck // output writer close errors are non-actionable

			return report.Run(opts, w)
		},
	}
}
```

- [ ] **Step 3: Verify it compiles**

Run: `go build ./...`
Expected: Success

- [ ] **Step 4: Run quality gates and commit**

Run: `task quality`

```bash
git add pkg/report/report.go internal/cli/report.go
git commit -m "feat(report): implement Run pipeline and CLI wiring for Art. 14 notifications"
```

---

### Task 10: Integration test fixtures (real data)

**Files:**
- Create: 6 directories under `testdata/integration/report-*/` with real data fixtures

- [ ] **Step 1: Create report-kev-early-warning fixtures**

The SBOM and Grype scan reuse the real golang.org/x/text data already in the project. The KEV file contains CVE-2022-32149 (same as policykit-kev-fail).

Create `testdata/integration/report-kev-early-warning/product-config.yaml`:
```yaml
product:
  name: "go-reachable-test"
  version: "1.0.0"
  support_period: "2031-01-01"
  update_mechanism: "automatic"

manufacturer:
  name: "SUSE LLC"
  member_state: "DE"
  contact_email: "security@suse.com"
  website: "https://suse.com"
  member_states_available:
    - DE
    - FR
    - NL
```

Create `testdata/integration/report-kev-early-warning/kev.json`:
```json
{"title": "CISA KEV Test Subset", "catalogVersion": "test", "dateReleased": "2026-04-03", "vulnerabilities": [{"cveID": "CVE-2022-32149"}]}
```

Copy `testdata/integration/csaf-single-cve/sbom.cdx.json` to `testdata/integration/report-kev-early-warning/sbom.cdx.json`

Copy `testdata/integration/csaf-single-cve/grype.json` to `testdata/integration/report-kev-early-warning/grype.json`

Create `testdata/integration/report-kev-early-warning/expected.json`:
```json
{
  "description": "CVE-2022-32149 KEV-signaled early warning with DE CSIRT coordinator",
  "assertions": {
    "stage": "early-warning",
    "vulnerability_count": 1,
    "cves": ["CVE-2022-32149"],
    "exploitation_signals": {"CVE-2022-32149": ["kev"]},
    "csirt_country": "DE",
    "csirt_name": "BSI (CERT-Bund)",
    "submission_channel": "ENISA Single Reporting Platform (Art. 16)",
    "has_user_notification": true,
    "min_completeness": 0.95,
    "error": ""
  }
}
```

- [ ] **Step 2: Create report-epss-notification fixtures**

Copy SBOM and Grype from csaf-single-cve. Create EPSS file with CVE-2022-32149 score above threshold.

Create `testdata/integration/report-epss-notification/epss.json`:
```json
{"model_version": "v2023.03.01", "score_date": "2026-04-04", "scores": {"CVE-2022-32149": 0.85}}
```

Create `testdata/integration/report-epss-notification/kev.json`:
```json
{"title": "CISA KEV Test Subset", "catalogVersion": "test", "dateReleased": "2026-04-03", "vulnerabilities": []}
```

Create `testdata/integration/report-epss-notification/product-config.yaml` (same as kev-early-warning).

Copy SBOM and Grype from csaf-single-cve.

Create `testdata/integration/report-epss-notification/expected.json`:
```json
{
  "description": "CVE-2022-32149 EPSS-signaled notification with 72h fields populated",
  "assertions": {
    "stage": "notification",
    "vulnerability_count": 1,
    "cves": ["CVE-2022-32149"],
    "exploitation_signals": {"CVE-2022-32149": ["epss"]},
    "csirt_country": "DE",
    "has_description": true,
    "has_corrective_actions": true,
    "has_impact": true,
    "min_completeness": 0.8,
    "error": ""
  }
}
```

- [ ] **Step 3: Create report-manual-final fixtures**

Copy SBOM and Grype from csaf-single-cve. Add manual override in product config and human input file.

Create `testdata/integration/report-manual-final/product-config.yaml`:
```yaml
product:
  name: "go-reachable-test"
  version: "1.0.0"

manufacturer:
  name: "SUSE LLC"
  member_state: "DE"
  contact_email: "security@suse.com"

exploitation_overrides:
  - cve: "CVE-2022-32149"
    source: "manual"
    reason: "Internal security team confirmed exploitation in customer environments"
```

Create `testdata/integration/report-manual-final/kev.json`:
```json
{"title": "CISA KEV Test Subset", "catalogVersion": "test", "dateReleased": "2026-04-03", "vulnerabilities": []}
```

Create `testdata/integration/report-manual-final/human-input.yaml`:
```yaml
vulnerabilities:
  CVE-2022-32149:
    corrective_measure_date: "2022-10-11"
    root_cause: "Algorithmic complexity vulnerability in ParseAcceptLanguage allows denial of service via crafted Accept-Language headers"
    threat_actor_info: "No specific threat actor identified; exploitation observed via automated scanning"
    security_update: "golang.org/x/text v0.3.8 fixes the vulnerability"
    preventive_measures:
      - "Added input length validation for Accept-Language headers"
      - "Implemented request rate limiting on language negotiation endpoints"
```

Copy SBOM and Grype from csaf-single-cve.

Create `testdata/integration/report-manual-final/expected.json`:
```json
{
  "description": "Manually flagged CVE-2022-32149 final report with human input merged",
  "assertions": {
    "stage": "final-report",
    "vulnerability_count": 1,
    "cves": ["CVE-2022-32149"],
    "exploitation_signals": {"CVE-2022-32149": ["manual"]},
    "has_root_cause": true,
    "has_threat_actor_info": true,
    "has_corrective_measure_date": true,
    "min_completeness": 0.9,
    "error": ""
  }
}
```

- [ ] **Step 4: Create report-no-exploited fixtures**

Copy SBOM and Grype from csaf-single-cve. Empty KEV, no EPSS, no overrides.

Create `testdata/integration/report-no-exploited/kev.json`:
```json
{"title": "CISA KEV Test Subset", "catalogVersion": "test", "dateReleased": "2026-04-03", "vulnerabilities": []}
```

Create `testdata/integration/report-no-exploited/product-config.yaml` (same as kev-early-warning but no overrides).

Copy SBOM and Grype from csaf-single-cve.

Create `testdata/integration/report-no-exploited/expected.json`:
```json
{
  "description": "No actively exploited CVEs - tool should return error, no document",
  "assertions": {
    "error": "no vulnerabilities with exploitation signals"
  }
}
```

- [ ] **Step 5: Create report-multi-cve fixtures**

Use the csaf-multi-cve fixtures (multiple CVEs in one scan). KEV matches one, EPSS matches another.

Copy SBOM and Grype from csaf-multi-cve.

Create `testdata/integration/report-multi-cve/kev.json` with one CVE:
```json
{"title": "CISA KEV Test Subset", "catalogVersion": "test", "dateReleased": "2026-04-03", "vulnerabilities": [{"cveID": "CVE-2022-32149"}]}
```

Create `testdata/integration/report-multi-cve/epss.json` — note: the second CVE in the multi-cve scan data needs to be identified first. Read the grype.json to get the CVE IDs, then create appropriate EPSS data.

Create product config and expected.json appropriate to the multi-cve data.

- [ ] **Step 6: Create report-mixed-exploited fixtures**

Use csaf-multi-component or csaf-mixed-status fixtures. Configure KEV for one CVE, EPSS for another, leave one with no signals.

Create appropriate kev.json, epss.json, product-config.yaml, and expected.json.

- [ ] **Step 7: Commit fixtures**

```bash
git add testdata/integration/report-*
git commit -m "test(report): add 6 integration test fixture directories with real data"
```

---

### Task 11: Integration tests

**Files:**
- Create: `pkg/report/integration_test.go`

- [ ] **Step 1: Write integration test runner**

Create `pkg/report/integration_test.go`:

```go
package report_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/report"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fixtureBase = "../../testdata/integration"

type expectedReport struct {
	Description string `json:"description"`
	Assertions  struct {
		Stage                   string              `json:"stage"`
		VulnerabilityCount      int                 `json:"vulnerability_count"`
		CVEs                    []string            `json:"cves"`
		ExploitationSignals     map[string][]string `json:"exploitation_signals"`
		CSIRTCountry            string              `json:"csirt_country"`
		CSIRTName               string              `json:"csirt_name"`
		SubmissionChannel       string              `json:"submission_channel"`
		HasUserNotification     bool                `json:"has_user_notification"`
		HasDescription          bool                `json:"has_description"`
		HasCorrectiveActions    bool                `json:"has_corrective_actions"`
		HasImpact               bool                `json:"has_impact"`
		HasRootCause            bool                `json:"has_root_cause"`
		HasThreatActorInfo      bool                `json:"has_threat_actor_info"`
		HasCorrectiveMeasureDate bool               `json:"has_corrective_measure_date"`
		MinCompleteness         float64             `json:"min_completeness"`
		Error                   string              `json:"error"`
	} `json:"assertions"`
}

func TestIntegration_ReportKEVEarlyWarning(t *testing.T) {
	runReportIntegration(t, "report-kev-early-warning", report.StageEarlyWarning)
}

func TestIntegration_ReportEPSSNotification(t *testing.T) {
	runReportIntegration(t, "report-epss-notification", report.StageNotification)
}

func TestIntegration_ReportManualFinal(t *testing.T) {
	runReportIntegration(t, "report-manual-final", report.StageFinalReport)
}

func TestIntegration_ReportNoExploited(t *testing.T) {
	runReportIntegration(t, "report-no-exploited", report.StageEarlyWarning)
}

func TestIntegration_ReportMultiCVE(t *testing.T) {
	runReportIntegration(t, "report-multi-cve", report.StageNotification)
}

func TestIntegration_ReportMixedExploited(t *testing.T) {
	runReportIntegration(t, "report-mixed-exploited", report.StageEarlyWarning)
}

func runReportIntegration(t *testing.T, scenario string, stage report.Stage) { //nolint:gocognit,gocyclo // integration test validates many optional assertions
	t.Helper()
	dir := filepath.Join(fixtureBase, scenario)

	expected := loadExpectedReport(t, dir)

	opts := &report.Options{
		SBOMPath:      filepath.Join(dir, "sbom.cdx.json"),
		ScanPaths:     []string{filepath.Join(dir, "grype.json")},
		Stage:         stage,
		ProductConfig: filepath.Join(dir, "product-config.yaml"),
		KEVPath:       filepath.Join(dir, "kev.json"),
		OutputFormat:  "json",
	}

	// Optional files.
	if _, err := os.Stat(filepath.Join(dir, "epss.json")); err == nil {
		opts.EPSSPath = filepath.Join(dir, "epss.json")
		opts.EPSSThreshold = 0.7
	}
	if _, err := os.Stat(filepath.Join(dir, "vex-results.json")); err == nil {
		opts.VEXPath = filepath.Join(dir, "vex-results.json")
	}
	if _, err := os.Stat(filepath.Join(dir, "human-input.yaml")); err == nil {
		opts.HumanInputPath = filepath.Join(dir, "human-input.yaml")
	}

	var buf bytes.Buffer
	err := report.Run(opts, &buf)

	// Check error case.
	if expected.Assertions.Error != "" {
		require.Error(t, err)
		assert.Contains(t, err.Error(), expected.Assertions.Error)
		return
	}
	require.NoError(t, err, "report.Run() error")

	var notification report.Notification
	require.NoError(t, json.Unmarshal(buf.Bytes(), &notification), "output is not valid JSON")

	// Stage.
	if expected.Assertions.Stage != "" {
		assert.Equal(t, report.Stage(expected.Assertions.Stage), notification.Stage)
	}

	// Vulnerability count.
	if expected.Assertions.VulnerabilityCount > 0 {
		assert.Equal(t, expected.Assertions.VulnerabilityCount, len(notification.Vulnerabilities))
	}

	// CVEs.
	if len(expected.Assertions.CVEs) > 0 {
		cveSet := make(map[string]bool)
		for _, v := range notification.Vulnerabilities {
			cveSet[v.CVE] = true
		}
		for _, cve := range expected.Assertions.CVEs {
			assert.True(t, cveSet[cve], "expected CVE %s not found", cve)
		}
	}

	// Exploitation signals.
	for cve, expectedSources := range expected.Assertions.ExploitationSignals {
		for _, v := range notification.Vulnerabilities {
			if v.CVE != cve {
				continue
			}
			var sources []string
			for _, s := range v.ExploitationSignals {
				sources = append(sources, string(s.Source))
			}
			for _, es := range expectedSources {
				assert.Contains(t, sources, es, "CVE %s missing signal %s", cve, es)
			}
		}
	}

	// CSIRT.
	if expected.Assertions.CSIRTCountry != "" {
		assert.Equal(t, expected.Assertions.CSIRTCountry, notification.CSIRTCoordinator.Country)
	}
	if expected.Assertions.CSIRTName != "" {
		assert.Equal(t, expected.Assertions.CSIRTName, notification.CSIRTCoordinator.Name)
	}
	if expected.Assertions.SubmissionChannel != "" {
		assert.Equal(t, expected.Assertions.SubmissionChannel, notification.SubmissionChannel)
	}

	// User notification.
	if expected.Assertions.HasUserNotification {
		assert.NotNil(t, notification.UserNotification)
	}

	// Notification-level fields.
	if expected.Assertions.HasDescription {
		for _, v := range notification.Vulnerabilities {
			assert.NotEmpty(t, v.Description, "expected description for %s", v.CVE)
		}
	}
	if expected.Assertions.HasCorrectiveActions {
		hasActions := false
		for _, v := range notification.Vulnerabilities {
			if len(v.CorrectiveActions) > 0 {
				hasActions = true
			}
		}
		assert.True(t, hasActions, "expected corrective actions")
	}
	if expected.Assertions.HasImpact {
		for _, v := range notification.Vulnerabilities {
			assert.NotNil(t, v.EstimatedImpact, "expected impact for %s", v.CVE)
		}
	}

	// Final report fields.
	if expected.Assertions.HasRootCause {
		for _, v := range notification.Vulnerabilities {
			assert.NotEqual(t, "[HUMAN INPUT REQUIRED]", v.RootCause, "root cause should be filled for %s", v.CVE)
		}
	}
	if expected.Assertions.HasThreatActorInfo {
		for _, v := range notification.Vulnerabilities {
			assert.NotEqual(t, "[HUMAN INPUT REQUIRED]", v.ThreatActorInfo, "threat actor should be filled for %s", v.CVE)
		}
	}
	if expected.Assertions.HasCorrectiveMeasureDate {
		for _, v := range notification.Vulnerabilities {
			assert.NotEmpty(t, v.CorrectiveMeasureDate, "corrective measure date expected for %s", v.CVE)
		}
	}

	// Completeness.
	if expected.Assertions.MinCompleteness > 0 {
		assert.GreaterOrEqual(t, notification.Completeness.Score, expected.Assertions.MinCompleteness,
			"completeness %.2f below minimum %.2f", notification.Completeness.Score, expected.Assertions.MinCompleteness)
	}

	// Submission channel should always be ENISA SRP.
	assert.Equal(t, report.SubmissionChannelENISA, notification.SubmissionChannel)
	assert.Equal(t, report.CompletenessNote, notification.Completeness.Note)

	t.Logf("%s: %d vulnerabilities, completeness %.0f%%, all assertions passed",
		scenario, len(notification.Vulnerabilities), notification.Completeness.Score*100)
}

func loadExpectedReport(t *testing.T, dir string) expectedReport {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "expected.json")) //nolint:gosec // test fixture path
	if err != nil {
		t.Fatalf("read expected.json: %v", err)
	}
	var expected expectedReport
	if err := json.Unmarshal(data, &expected); err != nil {
		t.Fatalf("parse expected.json: %v", err)
	}
	return expected
}
```

- [ ] **Step 2: Run integration tests**

Run: `task test:report`
Expected: All 6 scenarios pass (4 initially if multi-cve and mixed fixtures need data adjustment)

- [ ] **Step 3: Fix any test failures, adjust fixtures as needed**

Iterate until all 6 integration tests pass.

- [ ] **Step 4: Run full quality gates**

Run: `task quality`
Expected: All pass

- [ ] **Step 5: Commit**

```bash
git add pkg/report/integration_test.go
git commit -m "test(report): add 6 integration test scenarios with real data"
```

---

### Task 12: LLM judge test

**Files:**
- Create: `pkg/report/llm_judge_test.go`

- [ ] **Step 1: Write LLM judge test**

Create `pkg/report/llm_judge_test.go`:

```go
//go:build llmjudge

package report_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/report"
)

type reportLLMScores struct {
	RegulatoryAccuracy      int    `json:"regulatory_accuracy"`
	SignalTransparency      int    `json:"signal_transparency"`
	SubmissionHonesty       int    `json:"submission_honesty"`
	DeadlineAccuracy        int    `json:"deadline_accuracy"`
	UserNotificationQuality int    `json:"user_notification_quality"`
	OverallQuality          int    `json:"overall_quality"`
	Reasoning               string `json:"reasoning"`
}

func TestLLMJudge_ReportKEVNotification(t *testing.T) {
	geminiPath, err := exec.LookPath("gemini")
	if err != nil {
		t.Skip("gemini CLI not available, skipping LLM judge test")
	}

	dir := filepath.Join(fixtureBase, "report-kev-early-warning")
	opts := &report.Options{
		SBOMPath:      filepath.Join(dir, "sbom.cdx.json"),
		ScanPaths:     []string{filepath.Join(dir, "grype.json")},
		Stage:         report.StageNotification,
		ProductConfig: filepath.Join(dir, "product-config.yaml"),
		KEVPath:       filepath.Join(dir, "kev.json"),
		OutputFormat:  "json",
	}

	var buf bytes.Buffer
	if err := report.Run(opts, &buf); err != nil {
		t.Fatalf("report.Run() error: %v", err)
	}

	reportFile, err := os.CreateTemp(".", "report-generated-*.json")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	defer os.Remove(reportFile.Name()) //nolint:errcheck // test cleanup
	if _, err := reportFile.Write(buf.Bytes()); err != nil {
		t.Fatalf("write report: %v", err)
	}
	reportFile.Close()

	prompt := fmt.Sprintf(`You are a CRA (EU Cyber Resilience Act) Article 14 notification quality judge.

CRA Article 14 requires manufacturers to notify actively exploited vulnerabilities:
- Art. 14(1): Notify CSIRT and ENISA simultaneously via Single Reporting Platform
- Art. 14(2)(a): 24h early warning with CVE, severity, affected products, member states
- Art. 14(2)(b): 72h notification with description, exploit nature, corrective actions, sensitivity
- Art. 14(2)(c): 14-day final report (after corrective measure available) with root cause, threat actor, security update
- Art. 14(7): Submit via ENISA Single Reporting Platform, routed to Member State CSIRT
- Art. 14(8): Inform users in structured, machine-readable format

IMPORTANT: The tool should aggregate exploitation SIGNALS to support the manufacturer's determination.
It should NOT claim to make the regulatory determination itself. The submission channel should be
ENISA SRP, not direct CSIRT contact.

Read the GENERATED NOTIFICATION from: %s

Score on these dimensions (1-10 each):
1. regulatory_accuracy: Do fields map correctly to Art. 14(2) required content? Tool does not overstate its role?
2. signal_transparency: Are exploitation signals clearly labeled with source and confidence?
3. submission_honesty: Does output correctly identify ENISA SRP as submission channel, not direct CSIRT?
4. deadline_accuracy: Are deadline references correct per Art. 14(2)(a-c)?
5. user_notification_quality: Is Art. 14(8) section actionable for downstream users?
6. overall_quality: Would a compliance officer trust this for ENISA SRP submission?

Respond ONLY with valid JSON, no other text:
{"regulatory_accuracy": N, "signal_transparency": N, "submission_honesty": N, "deadline_accuracy": N, "user_notification_quality": N, "overall_quality": N, "reasoning": "brief explanation"}`,
		reportFile.Name())

	cmd := exec.Command(geminiPath, "--approval-mode", "plan", "-p", prompt) //nolint:gosec
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

	var scores reportLLMScores
	if err := json.Unmarshal([]byte(responseText[jsonStart:jsonEnd+1]), &scores); err != nil {
		t.Fatalf("parse scores: %v\nresponse: %s", err, responseText)
	}

	t.Logf("LLM Scores: regulatory=%d signals=%d submission=%d deadline=%d user_notif=%d overall=%d",
		scores.RegulatoryAccuracy, scores.SignalTransparency, scores.SubmissionHonesty,
		scores.DeadlineAccuracy, scores.UserNotificationQuality, scores.OverallQuality)
	t.Logf("Reasoning: %s", scores.Reasoning)

	threshold := 8
	dims := map[string]int{
		"regulatory_accuracy":       scores.RegulatoryAccuracy,
		"signal_transparency":       scores.SignalTransparency,
		"submission_honesty":        scores.SubmissionHonesty,
		"deadline_accuracy":         scores.DeadlineAccuracy,
		"user_notification_quality": scores.UserNotificationQuality,
		"overall_quality":           scores.OverallQuality,
	}
	for dim, score := range dims {
		if score < threshold {
			t.Errorf("%s: score %d < threshold %d", dim, score, threshold)
		}
	}
}
```

- [ ] **Step 2: Run quality gates (without LLM tag)**

Run: `task quality`
Expected: All pass (llm_judge_test.go skipped due to build tag)

- [ ] **Step 3: Run LLM judge test (optional, requires gemini)**

Run: `task test:report:llmjudge`
Expected: All dimensions >= 8

- [ ] **Step 4: Commit**

```bash
git add pkg/report/llm_judge_test.go
git commit -m "test(report): add LLM quality judge test for Art. 14 regulatory accuracy"
```

---

### Task 13: Final quality gates and cleanup

- [ ] **Step 1: Run full test suite**

Run: `task test`
Expected: All tests pass including new report tests

- [ ] **Step 2: Run full quality gates**

Run: `task quality`
Expected: All pass (fmt, vet, lint, test)

- [ ] **Step 3: Run report-specific integration tests**

Run: `task test:report`
Expected: All 6 scenarios pass

- [ ] **Step 4: Build the binary**

Run: `task build`
Expected: Binary builds successfully at `bin/cra`

- [ ] **Step 5: Smoke test the CLI**

Run: `bin/cra report --help`
Expected: Shows all flags (sbom, scan, stage, product-config, kev, epss-path, etc.)

- [ ] **Step 6: End-to-end CLI test with real data**

Run:
```bash
bin/cra report \
  --sbom testdata/integration/report-kev-early-warning/sbom.cdx.json \
  --scan testdata/integration/report-kev-early-warning/grype.json \
  --stage early-warning \
  --product-config testdata/integration/report-kev-early-warning/product-config.yaml \
  --kev testdata/integration/report-kev-early-warning/kev.json
```
Expected: Valid JSON notification output with CVE-2022-32149, KEV signal, CSIRT BSI, ENISA SRP submission channel

- [ ] **Step 7: Final commit if any cleanup needed**

```bash
git add -A
git commit -m "feat(report): complete cra-report Art. 14 notification generator"
```
