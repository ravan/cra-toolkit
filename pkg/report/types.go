// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

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
	CVE                    string               `json:"cve"`
	ExploitationSignals    []ExploitationSignal `json:"exploitation_signals"`
	Severity               string               `json:"severity"`
	CVSS                   float64              `json:"cvss"`
	AffectedProducts       []AffectedProduct    `json:"affected_products"`
	MemberStates           []string             `json:"member_states,omitempty"`
	Description            string               `json:"description,omitempty"`
	GeneralNature          string               `json:"general_nature,omitempty"`
	CorrectiveActions      []string             `json:"corrective_actions,omitempty"`
	MitigatingMeasures     []string             `json:"mitigating_measures,omitempty"`
	EstimatedImpact        *Impact              `json:"estimated_impact,omitempty"`
	InformationSensitivity string               `json:"information_sensitivity,omitempty"`
	CorrectiveMeasureDate  string               `json:"corrective_measure_date,omitempty"`
	RootCause              string               `json:"root_cause,omitempty"`
	ThreatActorInfo        string               `json:"threat_actor_info,omitempty"`
	SecurityUpdate         string               `json:"security_update,omitempty"`
	PreventiveMeasures     []string             `json:"preventive_measures,omitempty"`
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
	Product               ProductSection         `json:"product" yaml:"product"`
	Manufacturer          Manufacturer           `json:"manufacturer" yaml:"manufacturer"`
	ExploitationOverrides []ExploitationOverride `json:"exploitation_overrides" yaml:"exploitation_overrides"`
}

// ProductSection is the product metadata section of the config.
type ProductSection struct {
	Name            string `json:"name" yaml:"name"`
	Version         string `json:"version" yaml:"version"`
	SupportPeriod   string `json:"support_period" yaml:"support_period"`
	UpdateMechanism string `json:"update_mechanism" yaml:"update_mechanism"`
}
