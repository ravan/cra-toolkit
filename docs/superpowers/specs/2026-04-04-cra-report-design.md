# cra-report: CRA Article 14 Notification Generator — Design Spec

## Overview

`cra-report` generates CRA Article 14 vulnerability notification documents from structured data. It implements the three-stage notification pipeline mandated by Art. 14(2): 24h early warning, 72h notification, and 14-day final report. It also generates Art. 14(8) user notification sections that reference companion CSAF advisories produced by `cra-csaf`.

**CRA Articles covered:** Art. 14(1), Art. 14(2)(a-c), Art. 14(7), Art. 14(8)

**Scope:**
- Actively exploited vulnerability notifications (Art. 14(1-2))
- User notification with CSAF advisory reference (Art. 14(8))
- NOT severe incident notifications (Art. 14(3-4)) — deferred to future work

**Phase 1 constraints:** Deterministic, no LLM. Template-based generation from structured data. Human input file for fields requiring judgment (root cause, threat actor info).

## Regulatory Honesty Notes

These constraints are documented upfront so the tool does not create false confidence:

1. **Submission channel.** Per Art. 14(1) and Art. 14(7), all notifications are submitted via the ENISA Single Reporting Platform (SRP) established under Art. 16. This tool generates notification *documents* — it does not submit them. The SRP API schema is not yet published (Art. 14(10) allows the Commission to specify format by implementing acts). When the SRP schema is available, a format adapter will be added. Until then, the tool produces documents for manual upload to the SRP portal.

2. **Exploitation determination is the manufacturer's responsibility.** Art. 14(1) says the manufacturer notifies vulnerabilities "that it becomes aware of." The tool aggregates exploitation *signals* (CISA KEV matches, EPSS scores, manual flags) to support the manufacturer's determination. It does not make the regulatory determination itself. Output labels signals with their source and confidence, not as definitive classifications.

3. **14-day final report deadline.** Art. 14(2)(c) triggers "no later than 14 days after a corrective or mitigating measure is available" — NOT 14 days from awareness. The tool accepts the corrective measure availability date as input.

4. **Completeness score is a toolkit quality metric.** The CRA does not define completeness percentages or thresholds. The completeness tracking in this tool is our own quality metric to help users identify unfilled fields. It is not a regulatory compliance measure.

5. **Format may change.** Art. 14(10) empowers the Commission to specify notification format via implementing acts. Our structured format is based on the Art. 14(2) required fields as written in the regulation. It will need adaptation when implementing acts are published.

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
+- 2. aggregateExploitationSignals(findings, kev, epss, manualFlags)
|     -> []ExploitedVuln (filtered to CVEs with at least one exploitation signal)
|
+- 3. buildStage(stage, exploitedVulns, context)
|     +- StageEarlyWarning  -> BuildEarlyWarning(vulns, manufacturer)
|     +- StageNotification  -> BuildNotification(vulns, manufacturer, sbomContext)
|     +- StageFinalReport   -> BuildFinalReport(vulns, manufacturer, sbomContext, humanInput)
|
+- 4. lookupCSIRT(manufacturer.MemberState) -> CSIRTInfo (informational metadata only)
|
+- 5. buildUserNotification(vulns, csafRef) -> UserNotification
|
+- 6. computeCompleteness(notification) -> Completeness
|
+- 7. render(notification, format) -> output
```

### Key Design Decisions

- **No exploitation signals = no notification.** If the aggregator finds zero CVEs with exploitation signals, `Run` returns `ErrNoExploitedVulns`. No document generated.
- **Signals, not determinations.** The tool presents exploitation signals with their sources. The manufacturer makes the regulatory determination per Art. 14(1).
- **EPSS is optional.** If `--epss-path` is omitted, EPSS signal aggregation is skipped. Only KEV and manual sources used.
- **14-day deadline anchors to corrective measure date.** Per Art. 14(2)(c), not discovery date. The tool accepts this date as input and includes it in the output.
- **Stage validation.** The 14-day final report includes human input where available. Missing fields get `[HUMAN INPUT REQUIRED]` placeholders. Completeness score (toolkit metric) reflects it.
- **Submission is the user's responsibility.** The tool generates documents. Submission to the ENISA SRP is out of scope until the SRP API is published.
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

### Exploitation Signal Aggregation

The tool does NOT determine whether a vulnerability is "actively exploited" in the regulatory
sense — that is the manufacturer's responsibility per Art. 14(1). The tool aggregates signals
from external data sources to support the manufacturer's determination.

```go
type ExploitationSource string

const (
    ExploitationKEV    ExploitationSource = "kev"     // CISA KEV catalog match — strong signal
    ExploitationEPSS   ExploitationSource = "epss"    // EPSS score above threshold — probabilistic signal
    ExploitationManual ExploitationSource = "manual"   // Manufacturer's explicit determination
)

type ExploitedVuln struct {
    CVE               string
    Source            ExploitationSource  // Which signal triggered inclusion
    EPSSScore         float64            // 0-1, only set when Source=epss
    KEVDateAdded      string             // only set when Source=kev
    ManualReason      string             // only set when Source=manual
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

**Signal priority:** When multiple signals match a CVE, the output records the strongest:
KEV > Manual > EPSS. All matching signals are preserved in the output for transparency.

**Edge cases:**
- CVE in KEV and manual: KEV is primary signal (authoritative source), manual reason also recorded
- CVE in KEV but EPSS below threshold: KEV signal is sufficient regardless of EPSS
- CVE with EPSS above threshold but not in KEV: EPSS signal — output clearly labels this as probabilistic, not confirmed exploitation
- Zero signaled CVEs: `ErrNoExploitedVulns` returned — no document generated

### Notification Document

```go
type Notification struct {
    NotificationID    string              `json:"notification_id"`
    ToolkitVersion    string              `json:"toolkit_version"`
    Timestamp         string              `json:"timestamp"`
    Stage             Stage               `json:"stage"`
    CRAReference      string              `json:"cra_reference"`       // e.g., "Art. 14(2)(a)"
    SubmissionChannel string              `json:"submission_channel"`  // Always "ENISA Single Reporting Platform (Art. 16)"
    Manufacturer      Manufacturer        `json:"manufacturer"`
    CSIRTCoordinator  CSIRTInfo           `json:"csirt_coordinator"`   // Informational — identifies the designated CSIRT
    Vulnerabilities   []VulnEntry         `json:"vulnerabilities"`
    UserNotification  *UserNotification   `json:"user_notification,omitempty"`
    Completeness      Completeness        `json:"completeness"`
}
```

### Vulnerability Entry (Progressive Enrichment)

```go
type VulnEntry struct {
    // All stages (24h early warning)
    CVE                  string               `json:"cve"`
    ExploitationSignals  []ExploitationSignal  `json:"exploitation_signals"`
    Severity             string               `json:"severity"`
    CVSS                 float64              `json:"cvss"`
    AffectedProducts     []AffectedProduct    `json:"affected_products"`
    MemberStates         []string             `json:"member_states,omitempty"`

    // 72h notification adds:
    Description          string   `json:"description,omitempty"`
    GeneralNature        string   `json:"general_nature,omitempty"`       // from CVE description, supplemented by CVSS vector metadata
    CorrectiveActions    []string `json:"corrective_actions,omitempty"`
    MitigatingMeasures   []string `json:"mitigating_measures,omitempty"`
    EstimatedImpact      *Impact  `json:"estimated_impact,omitempty"`
    InformationSensitivity string `json:"information_sensitivity,omitempty"`

    // 14-day final report adds:
    CorrectiveMeasureDate string   `json:"corrective_measure_date,omitempty"` // Art. 14(2)(c) deadline anchor
    RootCause            string   `json:"root_cause,omitempty"`
    ThreatActorInfo      string   `json:"threat_actor_info,omitempty"`
    SecurityUpdate       string   `json:"security_update,omitempty"`
    PreventiveMeasures   []string `json:"preventive_measures,omitempty"`
}

// ExploitationSignal records one data source's indication of active exploitation.
// Multiple signals may exist for a single CVE (e.g., both KEV and EPSS).
type ExploitationSignal struct {
    Source    ExploitationSource `json:"source"`
    Detail   string             `json:"detail"`    // e.g., "Added to KEV 2021-12-10" or "EPSS 0.975" or user-provided reason
}

type Impact struct {
    AffectedComponentCount int            `json:"affected_component_count"`
    SeverityDistribution   map[string]int `json:"severity_distribution"`
}
```

### Completeness

**This is a toolkit quality metric, not a regulatory requirement.** The CRA does not define
completeness percentages or thresholds. This metric helps users identify which fields still
need attention before submission. A "complete" notification per this metric does not guarantee
regulatory compliance — the manufacturer is responsible for ensuring all Art. 14(2) required
information is accurate and sufficient.

```go
type Completeness struct {
    Score            float64  `json:"score"`          // 0.0-1.0
    TotalFields      int      `json:"total_fields"`
    FilledFields     int      `json:"filled_fields"`
    MachineGenerated int      `json:"machine_generated"`
    HumanProvided    int      `json:"human_provided"`
    Pending          []string `json:"pending,omitempty"`
    Note             string   `json:"note"`           // Always set: "Toolkit quality metric. CRA Art. 14 does not define completeness thresholds."
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

// CSIRTInfo identifies the designated CSIRT coordinator for the manufacturer's
// Member State. This is informational metadata for the notification document.
// Actual submission is via the ENISA Single Reporting Platform (Art. 16),
// NOT directly to the CSIRT.
type CSIRTInfo struct {
    Name              string `json:"name"`               // e.g., "BSI (CERT-Bund)"
    Country           string `json:"country"`            // ISO 3166-1 alpha-2
    SubmissionChannel string `json:"submission_channel"` // Always "ENISA Single Reporting Platform (Art. 16)"
}

type UserNotification struct {
    AffectedProducts   []AffectedProduct `json:"affected_products"`
    RecommendedActions []string          `json:"recommended_actions"`
    Severity           string            `json:"severity"`
    CSAFAdvisoryRef    string            `json:"csaf_advisory_ref,omitempty"`
}
```

### CSIRT Lookup Table

Embedded Go data covering all 27 EU + 3 EEA Member States mapping ISO country code to the designated CSIRT coordinator name. Source: ENISA CSIRT-network member list.

**This is informational metadata only.** The tool identifies which CSIRT is the coordinator for the manufacturer's Member State so the notification document is correctly addressed. The manufacturer does NOT contact the CSIRT directly — per Art. 14(7), submission is via the ENISA Single Reporting Platform (Art. 16), which routes to the appropriate CSIRT.

| Code | CSIRT Coordinator |
|------|-------------------|
| DE | BSI (CERT-Bund) |
| FR | CERT-FR (ANSSI) |
| NL | NCSC-NL |
| AT | CERT.at |
| SE | CERT-SE |

Per Art. 14(7), the CSIRT coordinator is determined by the manufacturer's main EU establishment Member State. The `submission_channel` field is always set to `"ENISA Single Reporting Platform (Art. 16)"` to prevent confusion about where notifications are actually submitted.

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
    VEXPath                string
    HumanInputPath         string  // YAML with root cause, threat actor (14-day stage)
    CSAFAdvisoryRef        string  // companion CSAF advisory ID for Art. 14(8)
    CorrectiveMeasureDate  string  // ISO 8601 date when corrective measure became available
                                   // Art. 14(2)(c) 14-day deadline anchors to this date, not discovery date

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
    corrective_measure_date: "2021-12-12"   # when the fix/mitigation became available
    root_cause: "Insufficient input validation in JNDI lookup functionality..."
    threat_actor_info: "Multiple APT groups including..."
    security_update: "Log4j 2.17.0 disables JNDI by default"
    preventive_measures:
      - "Implemented input validation for all JNDI lookups"
      - "Added runtime protection against recursive lookups"
```

Note: `corrective_measure_date` can also be provided via `--corrective-measure-date` CLI flag.
Per Art. 14(2)(c), the 14-day final report deadline is "no later than 14 days after a corrective
or mitigating measure is available" — not 14 days from discovery.

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

| Field | Source | Art. 14 Ref | Automatable |
|-------|--------|-------------|-------------|
| CVE identifier | Scanner findings | 14(2)(a) | Yes |
| Exploitation signals | Signal aggregator (KEV/EPSS/manual) | 14(1) "actively exploited" | Yes — signals only, not regulatory determination |
| Affected product name/version | SBOM + product config | 14(2)(a) | Yes |
| Severity (CVSS) | Scanner findings | 14(2)(a) | Yes |
| Member States where product available | Product config | 14(2)(a) "where applicable" | Yes |
| Manufacturer identity | Product config | 14(1) | Yes |
| CSIRT coordinator (informational) | Embedded lookup table | 14(7) | Yes — metadata only, submission via ENISA SRP |

**Expected completeness: ~1.0** (toolkit metric)

### Notification -- Art. 14(2)(b) -- 72h

Everything from early warning, plus:

| Field | Source | Art. 14 Ref | Automatable |
|-------|--------|-------------|-------------|
| Vulnerability description | Scanner findings (CVE description field — Grype/Trivy populate this from NVD/OSV) | 14(2)(b) "general information... about the vulnerability" | Yes |
| General nature of exploit | CVE description is the primary source. CVSS vector metadata (AV/AC/PR) supplements as structured context. We do not synthesize exploit analysis. | 14(2)(b) "the general nature of the exploit" | Yes (from existing scanner data) |
| Corrective actions planned | Fix versions from scanner findings | 14(2)(b) "corrective or mitigating measures taken" | Yes (if fix version exists) |
| Mitigating measures for users | VEX justifications if provided | 14(2)(b) "corrective or mitigating measures that users can take" | Partial (needs VEX input) |
| Estimated impact | Component count from SBOM, severity distribution | 14(2)(b) "general information about the product" | Yes |
| Information sensitivity | Default "high" for actively exploited, configurable via product config | 14(2)(b) "how sensitive the manufacturer considers the notified information" | Yes |

**Expected completeness: ~0.85-0.95** (toolkit metric — depends on whether VEX and fix versions are available in scanner data)

### Final Report -- Art. 14(2)(c) -- 14 days

Everything from notification, plus:

**Deadline: 14 days after corrective or mitigating measure is available (NOT 14 days from awareness). Per Art. 14(2)(c).**

| Field | Source | Art. 14 Ref | Automatable |
|-------|--------|-------------|-------------|
| Corrective measure date | `--corrective-measure-date` flag or human input file | 14(2)(c) "after a corrective or mitigating measure is available" | No — manufacturer must provide |
| Vulnerability severity & impact | Machine (CVSS, component count) + human refinement | 14(2)(c)(i) "description of the vulnerability, including its severity and impact" | Partial |
| Root cause analysis | Human input file | 14(2)(c)(i) | No (Phase 1) |
| Threat actor information | Human input file | 14(2)(c)(ii) "where available" | No (Phase 1) |
| Security update details | Fix versions from scanner + human input | 14(2)(c)(iii) "details about the security update" | Partial |
| Corrective measures applied | Human input file | 14(2)(c)(iii) "other corrective measures" | No (Phase 1) |
| Preventive measures | Human input file | (good practice, not explicitly in 14(2)(c)) | No (Phase 1) |

**Expected completeness without human input: ~0.55-0.65** (toolkit metric)
**Expected completeness with human input: ~0.95-1.0** (toolkit metric)

## Package Layout

```
pkg/report/
+-- report.go              # Run() pipeline, Options, Stage constants
+-- types.go               # Notification, VulnEntry, Completeness, etc.
+-- signals.go             # Exploitation signal aggregator (KEV/EPSS/manual)
+-- signals_test.go
+-- early_warning.go       # BuildEarlyWarning()
+-- early_warning_test.go
+-- notification.go        # BuildNotification()
+-- notification_test.go
+-- final_report.go        # BuildFinalReport() + human input merge
+-- final_report_test.go
+-- completeness.go        # computeCompleteness()
+-- completeness_test.go
+-- csirt.go               # Embedded CSIRT coordinator table + lookupCSIRT() (informational metadata)
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
| `report-manual-final` | Manually flagged CVE + human input + corrective measure date | final-report | Human input merged, root cause present, corrective measure date anchors deadline, completeness ~0.95+ |
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
  "description": "Log4Shell KEV-signaled early warning with DE CSIRT coordinator identified",
  "assertions": {
    "stage": "early-warning",
    "vulnerability_count": 1,
    "cves": ["CVE-2021-44228"],
    "exploitation_signals": {"CVE-2021-44228": ["kev"]},
    "csirt_country": "DE",
    "csirt_name": "BSI (CERT-Bund)",
    "submission_channel": "ENISA Single Reporting Platform (Art. 16)",
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
| `regulatory_accuracy` | Fields map correctly to Art. 14(2)(a-c) required content. Tool does not overstate its role (signals vs. determinations). |
| `signal_transparency` | Exploitation signals clearly labeled with source and confidence. KEV/EPSS/manual distinguished. No false certainty. |
| `submission_honesty` | Output correctly identifies ENISA SRP as submission channel, not direct CSIRT contact. CSIRT info is metadata only. |
| `deadline_accuracy` | 14-day final report deadline correctly anchored to corrective measure date per Art. 14(2)(c), not discovery date. |
| `user_notification_quality` | Art. 14(8) section actionable for downstream users. References companion CSAF advisory. |
| `overall_quality` | Compliance officer would trust this as input for ENISA SRP submission. Tool is honest about what it can and cannot automate. |

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
| Stage | Early Warning (24h) — Art. 14(2)(a) |
| Generated | 2026-04-04T12:00:00Z |
| Submission Channel | ENISA Single Reporting Platform (Art. 16) |

## Manufacturer
| Field | Value |
| --- | --- |
| Name | SUSE LLC |
| Member State | DE |

## CSIRT Coordinator (Informational)
| Field | Value |
| --- | --- |
| CSIRT | BSI (CERT-Bund) |
| Country | DE |

> **Note:** Per Art. 14(7), this notification is submitted via the ENISA Single
> Reporting Platform, which routes to the CSIRT coordinator simultaneously with ENISA.

## Vulnerabilities with Exploitation Signals

### CVE-2021-44228
- **Exploitation Signals:** KEV (Added 2021-12-10)
- **Severity:** Critical (CVSS 10.0)
- **Affected Products:** ...

> **Note:** Exploitation signals are provided to support the manufacturer's
> determination per Art. 14(1). The manufacturer is responsible for the
> regulatory decision to notify.

## User Notification (Art. 14(8))
...

## Completeness (Toolkit Quality Metric)
| Metric | Value |
| --- | --- |
| Score | 100% |
| Machine Generated | 8 |
| Human Provided | 0 |
| Pending | 0 |

> This is a toolkit quality metric. CRA Art. 14 does not define completeness thresholds.
```
