# cra-report: CRA Article 14 Notification Generator — Design Spec

## Overview

`cra-report` generates CRA Article 14 vulnerability notification documents from structured data. It implements the three-stage notification pipeline mandated by Art. 14(2): 24h early warning, 72h notification, and 14-day final report. It also generates Art. 14(8) user notification sections that reference companion CSAF advisories produced by `cra-csaf`.

**CRA Articles covered:** Art. 14(1), Art. 14(2)(a-c), Art. 14(7), Art. 14(8)

**Scope:**
- Actively exploited vulnerability notifications (Art. 14(1-2))
- User notification with CSAF advisory reference (Art. 14(8))
- NOT severe incident notifications (Art. 14(3-4)) — deferred to future work

**Phase 1 constraints:** Deterministic, no LLM. Template-based generation from structured data. Human input file for fields requiring judgment (root cause, threat actor info).

## Architecture: Stage-Based Pipeline

Stateless, single-stage generation. The user passes `--stage` to select which notification stage to produce. No state tracking between stages — the caller (CI/CD or Phase 2 agent) manages sequencing.

### Pipeline Flow

```
Run(opts, io.Writer)
|
+- 1. parseInputs(opts) -> NotificationContext
|     +- parseSBOM (reuse formats package)
|     +- parseScans (reuse formats package)
|     +- parseVEX (optional, reuse formats package)
|     +- parseProductConfig (extended with manufacturer)
|     +- parseHumanInput (optional, 14-day stage only)
|
+- 2. classifyExploitation(findings, kev, epssThreshold, manualFlags)
|     -> []ExploitedVuln (filtered to only exploited CVEs)
|
+- 3. buildStage(stage, exploitedVulns, context)
|     +- StageEarlyWarning  -> BuildEarlyWarning(vulns, manufacturer)
|     +- StageNotification  -> BuildNotification(vulns, manufacturer, sbomContext)
|     +- StageFinalReport   -> BuildFinalReport(vulns, manufacturer, sbomContext, humanInput)
|
+- 4. routeCSIRT(manufacturer.MemberState) -> CSIRTEndpoint
|
+- 5. buildUserNotification(vulns, csafRef) -> UserNotification
|
+- 6. computeCompleteness(notification) -> Completeness
|
+- 7. render(notification, format) -> output
```

### Key Design Decisions

- **No exploited vulns = no notification.** If the classifier finds zero exploited CVEs, `Run` returns `ErrNoExploitedVulns`. No document generated.
- **EPSS is optional.** If `--epss-path` is omitted, EPSS classification is skipped. Only KEV and manual sources used.
- **Stage validation.** The 14-day final report includes human input where available. Missing fields get `[HUMAN INPUT REQUIRED]` placeholders. Completeness score reflects it.
- **Shared code refactoring.** `LoadKEV` moves from `pkg/policykit` to `pkg/vuln`. Product config parsing moves to a shared location. Both `pkg/report` and `pkg/policykit` import from shared packages.

## Data Model

### Stage Constants

```go
type Stage string

const (
    StageEarlyWarning Stage = "early-warning"   // Art. 14(2)(a) -- 24h
    StageNotification Stage = "notification"     // Art. 14(2)(b) -- 72h
    StageFinalReport  Stage = "final-report"     // Art. 14(2)(c) -- 14d
)
```

### Exploitation Classification

```go
type ExploitationSource string

const (
    ExploitationKEV    ExploitationSource = "kev"
    ExploitationEPSS   ExploitationSource = "epss"
    ExploitationManual ExploitationSource = "manual"
)

type ExploitedVuln struct {
    CVE               string
    Source            ExploitationSource
    EPSSScore         float64            // 0-1, only set when Source=epss
    KEVDateAdded      string             // only set when Source=kev
    AffectedProducts  []AffectedProduct
    Severity          string
    CVSS              float64
    CVSSVector        string
    Description       string
    FixVersion        string
}

type AffectedProduct struct {
    Name    string
    Version string
    PURL    string
}
```

**Classification priority:** KEV > Manual > EPSS. A CVE matched by multiple sources gets the highest-confidence label.

**Edge cases:**
- CVE in KEV and manual: KEV wins (authoritative source)
- CVE in KEV but EPSS below threshold: still exploited (KEV is definitive)
- CVE with EPSS above threshold but not in KEV: classified as EPSS, labeled probabilistic
- Zero exploited CVEs: `ErrNoExploitedVulns` returned

### Notification Document

```go
type Notification struct {
    NotificationID   string              `json:"notification_id"`
    ToolkitVersion   string              `json:"toolkit_version"`
    Timestamp        string              `json:"timestamp"`
    Stage            Stage               `json:"stage"`
    Manufacturer     Manufacturer        `json:"manufacturer"`
    CSIRTEndpoint    CSIRTEndpoint       `json:"csirt_endpoint"`
    Vulnerabilities  []VulnEntry         `json:"vulnerabilities"`
    UserNotification *UserNotification   `json:"user_notification,omitempty"`
    Completeness     Completeness        `json:"completeness"`
}
```

### Vulnerability Entry (Progressive Enrichment)

```go
type VulnEntry struct {
    // All stages (24h early warning)
    CVE                string             `json:"cve"`
    ExploitationSource ExploitationSource `json:"exploitation_source"`
    Severity           string             `json:"severity"`
    CVSS               float64            `json:"cvss"`
    ActivelyExploited  bool               `json:"actively_exploited"`
    AffectedProducts   []AffectedProduct  `json:"affected_products"`
    MemberStates       []string           `json:"member_states,omitempty"`

    // 72h notification adds:
    Description          string   `json:"description,omitempty"`
    GeneralNature        string   `json:"general_nature,omitempty"`
    CorrectiveActions    []string `json:"corrective_actions,omitempty"`
    MitigatingMeasures   []string `json:"mitigating_measures,omitempty"`
    EstimatedImpact      *Impact  `json:"estimated_impact,omitempty"`
    InformationSensitivity string `json:"information_sensitivity,omitempty"`

    // 14-day final report adds:
    RootCause            string   `json:"root_cause,omitempty"`
    ThreatActorInfo      string   `json:"threat_actor_info,omitempty"`
    SecurityUpdate       string   `json:"security_update,omitempty"`
    PreventiveMeasures   []string `json:"preventive_measures,omitempty"`
}

type Impact struct {
    AffectedComponentCount int            `json:"affected_component_count"`
    SeverityDistribution   map[string]int `json:"severity_distribution"`
}
```

### Completeness

```go
type Completeness struct {
    Score            float64  `json:"score"`          // 0.0-1.0
    TotalFields      int      `json:"total_fields"`
    FilledFields     int      `json:"filled_fields"`
    MachineGenerated int      `json:"machine_generated"`
    HumanProvided    int      `json:"human_provided"`
    Pending          []string `json:"pending,omitempty"`
}
```

### CSIRT Routing

```go
type Manufacturer struct {
    Name                  string   `json:"name" yaml:"name"`
    MemberState           string   `json:"member_state" yaml:"member_state"`
    Address               string   `json:"address,omitempty" yaml:"address,omitempty"`
    ContactEmail          string   `json:"contact_email" yaml:"contact_email"`
    Website               string   `json:"website,omitempty" yaml:"website,omitempty"`
    MemberStatesAvailable []string `json:"member_states_available,omitempty" yaml:"member_states_available,omitempty"`
}

type CSIRTEndpoint struct {
    Name        string `json:"name"`
    Country     string `json:"country"`
    NotifyURL   string `json:"notify_url"`
    Email       string `json:"email"`
    ENISANotify bool   `json:"enisa_simultaneous"`
}

type UserNotification struct {
    AffectedProducts   []AffectedProduct `json:"affected_products"`
    RecommendedActions []string          `json:"recommended_actions"`
    Severity           string            `json:"severity"`
    CSAFAdvisoryRef    string            `json:"csaf_advisory_ref,omitempty"`
}
```

### CSIRT Lookup Table

Embedded Go data covering all 27 EU + 3 EEA Member States. Source: ENISA CSIRT-network directory + NIS2 Directive Art. 12(1). Examples:

| Code | CSIRT | URL |
|------|-------|-----|
| DE | BSI (CERT-Bund) | cert-bund.de |
| FR | CERT-FR (ANSSI) | cert.ssi.gouv.fr |
| NL | NCSC-NL | ncsc.nl |
| AT | CERT.at | cert.at |
| SE | CERT-SE | cert.se |

Routing per Art. 14(7): manufacturer's main EU establishment Member State determines the CSIRT. All notifications indicate `enisa_simultaneous: true` per Art. 14(1).

## CLI Options

```go
type Options struct {
    // Required inputs
    SBOMPath       string
    ScanPaths      []string
    Stage          Stage
    ProductConfig  string

    // Exploitation sources
    KEVPath        string   // local KEV JSON (auto-fetched if omitted)
    EPSSPath       string   // local EPSS JSON (optional)
    EPSSThreshold  float64  // default 0.7

    // Optional enrichment
    VEXPath         string
    HumanInputPath  string  // YAML with root cause, threat actor (14-day stage)
    CSAFAdvisoryRef string  // companion CSAF advisory ID for Art. 14(8)

    // Output
    OutputFormat   string   // "json" or "markdown"
}
```

### Product Config Extension

```yaml
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
```

### Human Input File (14-day final report)

```yaml
vulnerabilities:
  CVE-2021-44228:
    root_cause: "Insufficient input validation in JNDI lookup functionality..."
    threat_actor_info: "Multiple APT groups including..."
    preventive_measures:
      - "Implemented input validation for all JNDI lookups"
      - "Added runtime protection against recursive lookups"
```

### EPSS Data Format

```json
{
  "model_version": "v2023.03.01",
  "score_date": "2026-04-04",
  "scores": {
    "CVE-2021-44228": 0.975,
    "CVE-2022-32149": 0.42
  }
}
```

## Progressive Enrichment by Stage

### Early Warning -- Art. 14(2)(a) -- 24h

| Field | Source | Automatable |
|-------|--------|-------------|
| CVE identifier | Scanner findings | Yes |
| Actively exploited flag | Classifier | Yes |
| Exploitation source + confidence | Classifier | Yes |
| Affected product name/version | SBOM + product config | Yes |
| Severity (CVSS) | Scanner findings | Yes |
| Member States where product available | Product config | Yes |
| Manufacturer identity | Product config | Yes |
| CSIRT endpoint | Embedded table | Yes |

**Expected completeness: ~1.0**

### Notification -- Art. 14(2)(b) -- 72h

Everything from early warning, plus:

| Field | Source | Automatable |
|-------|--------|-------------|
| Vulnerability description | Scanner findings | Yes |
| General nature of exploit | Derived from CVSS vector: AV (attack vector) maps to network/local/physical, AC (attack complexity) maps to complexity description, PR (privileges required) maps to authentication needs | Yes (approximation) |
| Corrective actions planned | Derived from fix versions | Yes |
| Mitigating measures for users | Derived from VEX justifications | Partial (needs VEX) |
| Estimated impact | Component count from SBOM | Yes |
| Information sensitivity | Default "high", configurable | Yes |

**Expected completeness: ~0.85-0.95**

### Final Report -- Art. 14(2)(c) -- 14 days

Everything from notification, plus:

| Field | Source | Automatable |
|-------|--------|-------------|
| Root cause analysis | Human input file | No (Phase 1) |
| Vulnerability severity & impact detail | Machine + human refinement | Partial |
| Threat actor information | Human input file | No (Phase 1) |
| Security update details | Fix versions + human input | Partial |
| Corrective measures applied | Human input file | No (Phase 1) |
| Preventive measures | Human input file | No (Phase 1) |

**Expected completeness without human input: ~0.55-0.65**
**Expected completeness with human input: ~0.95-1.0**

## Package Layout

```
pkg/report/
+-- report.go              # Run() pipeline, Options, Stage constants
+-- types.go               # Notification, VulnEntry, Completeness, etc.
+-- classify.go            # Exploitation classifier (KEV/EPSS/manual)
+-- classify_test.go
+-- early_warning.go       # BuildEarlyWarning()
+-- early_warning_test.go
+-- notification.go        # BuildNotification()
+-- notification_test.go
+-- final_report.go        # BuildFinalReport() + human input merge
+-- final_report_test.go
+-- completeness.go        # computeCompleteness()
+-- completeness_test.go
+-- csirt.go               # Embedded CSIRT table + routeCSIRT()
+-- csirt_test.go
+-- user_notify.go         # buildUserNotification() for Art. 14(8)
+-- user_notify_test.go
+-- render.go              # RenderMarkdown()
+-- render_test.go
+-- epss.go                # EPSS file parser
+-- epss_test.go
+-- integration_test.go    # 6 scenario integration tests
+-- llm_judge_test.go      # LLM quality judge (//go:build llmjudge)
```

### Shared Code Refactoring

| Function | Current Location | New Location |
|----------|-----------------|--------------|
| `LoadKEV` | `pkg/policykit` | `pkg/vuln` |
| Product config parsing | `pkg/policykit` | Shared location (both packages import) |

## Integration Tests

### Six Scenarios

| Scenario | Exploitation Path | Stage | Key Assertion |
|----------|------------------|-------|---------------|
| `report-kev-early-warning` | Log4Shell (CVE-2021-44228) in KEV | early-warning | KEV classification, CSIRT routing DE, completeness ~1.0 |
| `report-epss-notification` | CVE-2022-32149 with EPSS 0.85 | notification | EPSS source labeled, 72h fields populated, impact from SBOM |
| `report-manual-final` | Manually flagged CVE + human input | final-report | Human input merged, root cause present, completeness ~0.95+ |
| `report-no-exploited` | CVE below EPSS threshold, not in KEV | N/A | `ErrNoExploitedVulns` returned, no document |
| `report-multi-cve` | Log4Shell (KEV) + second CVE (EPSS) | notification | Both vulns, different sources, severity ordering |
| `report-mixed-exploited` | 3 CVEs: KEV + EPSS + not exploited | early-warning | 2 exploited in output, 1 filtered out |

### Test Fixture Structure

```
testdata/integration/report-kev-early-warning/
+-- sbom.cdx.json
+-- grype.json
+-- kev.json
+-- epss.json              # optional
+-- product-config.yaml
+-- human-input.yaml       # only for final-report scenario
+-- vex-results.json       # optional
+-- expected.json
```

### Expected.json Structure

```json
{
  "description": "Log4Shell KEV-confirmed early warning with DE CSIRT routing",
  "assertions": {
    "stage": "early-warning",
    "vulnerability_count": 1,
    "cves": ["CVE-2021-44228"],
    "exploitation_sources": {"CVE-2021-44228": "kev"},
    "csirt_country": "DE",
    "csirt_name": "BSI (CERT-Bund)",
    "has_user_notification": true,
    "min_completeness": 0.95,
    "error": ""
  }
}
```

## LLM Judge Test

Build tag: `//go:build llmjudge`

Uses Gemini CLI (same pattern as csaf and policykit LLM judges). Generates a `notification` stage document from the Log4Shell KEV scenario, then scores against CRA Article 14 requirements.

### Scoring Dimensions (1-10 each, threshold 8)

| Dimension | What It Checks |
|-----------|---------------|
| `regulatory_accuracy` | Fields map correctly to Art. 14(2)(a-c) required content |
| `exploitation_classification` | KEV/EPSS/manual source correctly identified and justified |
| `completeness_accuracy` | Completeness score honestly reflects filled vs. pending fields |
| `csirt_routing` | Correct Member State CSIRT identified per Art. 14(7) |
| `user_notification_quality` | Art. 14(8) section actionable for downstream users |
| `overall_quality` | Compliance officer would trust this for ENISA submission |

## Output Formats

### JSON

Canonical `Notification` struct serialized as indented JSON. Machine-consumable by evidence bundler and Phase 2 agent.

### Markdown

Human-readable report following policykit's `RenderMarkdown` pattern:

```markdown
# CRA Article 14 Vulnerability Notification

## Metadata
| Field | Value |
| --- | --- |
| Notification ID | CRA-NOTIF-20260404T120000Z |
| Stage | Early Warning (24h) |
| Generated | 2026-04-04T12:00:00Z |

## Manufacturer
| Field | Value |
| --- | --- |
| Name | SUSE LLC |
| Member State | DE |

## CSIRT Routing
| Field | Value |
| --- | --- |
| CSIRT | BSI (CERT-Bund) |
| Country | DE |
| ENISA Simultaneous | Yes |

## Actively Exploited Vulnerabilities

### CVE-2021-44228
- **Exploitation Source:** KEV (confirmed)
- **Severity:** Critical (CVSS 10.0)
- **Affected Products:** ...

## User Notification (Art. 14(8))
...

## Completeness
| Metric | Value |
| --- | --- |
| Score | 100% |
| Machine Generated | 8 |
| Human Provided | 0 |
| Pending | 0 |
```
