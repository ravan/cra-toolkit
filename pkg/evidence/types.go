// Package evidence bundles compliance outputs (SBOM, VEX, provenance, scans, policy reports)
// into a signed, versioned CRA evidence package for Annex VII technical documentation.
package evidence

import "errors"

// ErrNoProductConfig is returned when no product config is provided.
var ErrNoProductConfig = errors.New("evidence: product config is required")

// ErrNoOutputDir is returned when no output directory is specified.
var ErrNoOutputDir = errors.New("evidence: output directory is required")

// ErrNoArtifacts is returned when no artifacts are provided.
var ErrNoArtifacts = errors.New("evidence: at least one artifact is required")

// CompletenessNote is the constant disclaimer on the completeness metric.
const CompletenessNote = "Toolkit quality metric. CRA Annex VII does not define completeness thresholds."

// Options configures the evidence bundler.
type Options struct {
	// Toolkit-generated artifacts.
	SBOMPath     string
	VEXPath      string
	ScanPaths    []string
	PolicyReport string
	CSAFPath     string
	ReportPath   string // Art. 14 notification

	// Manufacturer-provided documents.
	RiskAssessment    string
	ArchitectureDocs  string
	ProductionProcess string
	EUDeclaration     string
	CVDPolicy         string
	StandardsDoc      string

	// Configuration.
	ProductConfig string
	OutputDir     string
	OutputFormat  string // "json" or "markdown"
	Archive       bool   // produce .tar.gz alongside directory
	SigningKey    string // optional Cosign key path (keyless if empty)
}

// Bundle is the top-level evidence package output.
type Bundle struct {
	BundleID       string             `json:"bundle_id"`
	ToolkitVersion string             `json:"toolkit_version"`
	Timestamp      string             `json:"timestamp"`
	Product        ProductIdentity    `json:"product"`
	Artifacts      []ArtifactEntry    `json:"artifacts"`
	Validation     ValidationReport   `json:"validation"`
	Completeness   CompletenessReport `json:"completeness"`
	Summary        AnnexVIISummary    `json:"annex_vii_summary"`
	Manifest       Manifest           `json:"manifest"`
	Signature      *SignatureInfo     `json:"signature,omitempty"`
}

// ProductIdentity holds product metadata from extended product config.
type ProductIdentity struct {
	Name                string `json:"name"`
	Version             string `json:"version"`
	Manufacturer        string `json:"manufacturer"`
	IntendedPurpose     string `json:"intended_purpose"`
	ProductClass        string `json:"product_class"`
	SupportPeriodEnd    string `json:"support_period_end"`
	ConformityProcedure string `json:"conformity_procedure"`
	SecurityContact     string `json:"security_contact"`
	CVDPolicyURL        string `json:"cvd_policy_url"`
}

// ArtifactEntry describes one file in the bundle.
type ArtifactEntry struct {
	Path        string `json:"path"`
	AnnexVIIRef string `json:"annex_vii_ref"`
	Format      string `json:"format"`
	SHA256      string `json:"sha256"`
	Source      string `json:"source"`
	Description string `json:"description"`
}

// ValidationReport captures format validation and cross-validation results.
type ValidationReport struct {
	Checks   []ValidationCheck `json:"checks"`
	Passed   int               `json:"passed"`
	Failed   int               `json:"failed"`
	Warnings int               `json:"warnings"`
}

// ValidationCheck is a single validation or cross-validation result.
type ValidationCheck struct {
	CheckID     string `json:"check_id"`
	Description string `json:"description"`
	Status      string `json:"status"`
	Details     string `json:"details"`
	ArtifactA   string `json:"artifact_a"`
	ArtifactB   string `json:"artifact_b,omitempty"`
}

// CompletenessReport maps Annex VII sections to artifact presence.
type CompletenessReport struct {
	Sections      []AnnexVIISection `json:"sections"`
	Score         float64           `json:"score"`
	TotalWeight   int               `json:"total_weight"`
	CoveredWeight int               `json:"covered_weight"`
	Note          string            `json:"note"`
}

// AnnexVIISection describes coverage of one Annex VII documentation section.
type AnnexVIISection struct {
	ID        string   `json:"id"`
	Title     string   `json:"title"`
	CRARef    string   `json:"cra_ref"`
	Required  bool     `json:"required"`
	Covered   bool     `json:"covered"`
	Weight    int      `json:"weight"`
	Artifacts []string `json:"artifacts,omitempty"`
	Gap       string   `json:"gap,omitempty"`
}

// AnnexVIISummary is generated from real parsed artifact data.
type AnnexVIISummary struct {
	ProductDescription    string             `json:"product_description"`
	SBOMStats             *SBOMStats         `json:"sbom_stats,omitempty"`
	VulnHandlingStats     *VulnHandlingStats `json:"vuln_handling_stats,omitempty"`
	PolicyComplianceStats *PolicyStats       `json:"policy_compliance_stats,omitempty"`
	ScanStats             *ScanStats         `json:"scan_stats,omitempty"`
	SupportPeriod         string             `json:"support_period"`
	ConformityProcedure   string             `json:"conformity_procedure"`
	StandardsApplied      []string           `json:"standards_applied,omitempty"`
}

// SBOMStats holds statistics extracted from a real SBOM.
type SBOMStats struct {
	Format         string `json:"format"`
	ComponentCount int    `json:"component_count"`
	ProductName    string `json:"product_name"`
	ProductVersion string `json:"product_version"`
}

// VulnHandlingStats holds statistics extracted from a real VEX document.
type VulnHandlingStats struct {
	TotalAssessed      int            `json:"total_assessed"`
	StatusDistribution map[string]int `json:"status_distribution"`
}

// PolicyStats holds statistics extracted from a real policy report.
type PolicyStats struct {
	Total   int `json:"total"`
	Passed  int `json:"passed"`
	Failed  int `json:"failed"`
	Skipped int `json:"skipped"`
	Human   int `json:"human"`
}

// ScanStats holds statistics extracted from real scan results.
type ScanStats struct {
	TotalFindings        int            `json:"total_findings"`
	SeverityDistribution map[string]int `json:"severity_distribution"`
	ScannerCount         int            `json:"scanner_count"`
}

// Manifest is the SHA-256 file manifest for the bundle.
type Manifest struct {
	Algorithm string            `json:"algorithm"`
	Entries   map[string]string `json:"entries"`
}

// SignatureInfo describes the cryptographic signature of the manifest.
type SignatureInfo struct {
	Method      string `json:"method"`
	Signature   string `json:"signature"`
	Certificate string `json:"certificate,omitempty"`
	LogIndex    *int64 `json:"log_index,omitempty"`
}

// EvidenceConfig is the extended product config with evidence section.
type EvidenceConfig struct {
	Product  EvidenceProductSection `yaml:"product"`
	Evidence EvidenceSection        `yaml:"evidence"`
}

// EvidenceProductSection is the product metadata from the shared config.
type EvidenceProductSection struct {
	Name             string `yaml:"name"`
	Version          string `yaml:"version"`
	Manufacturer     string `yaml:"manufacturer"`
	MemberState      string `yaml:"member_state"`
	SupportPeriodEnd string `yaml:"support_end_date"`
}

// EvidenceSection holds the evidence-specific extensions.
type EvidenceSection struct {
	IntendedPurpose     string   `yaml:"intended_purpose"`
	ProductClass        string   `yaml:"product_class"`
	ConformityProcedure string   `yaml:"conformity_procedure"`
	SecurityContact     string   `yaml:"security_contact"`
	CVDPolicyURL        string   `yaml:"cvd_policy_url"`
	StandardsApplied    []string `yaml:"standards_applied"`
}

// bundleContext is the internal context built during the collect stage.
type bundleContext struct { //nolint:unused // used in tasks 3-6
	config     *EvidenceConfig
	product    ProductIdentity
	artifacts  []artifactInput
	components []componentInfo
	findings   []findingInfo
	vexResults []vexInfo
	policyData *policyReportData
}

// artifactInput tracks a single input artifact and its metadata.
type artifactInput struct {
	sourcePath  string
	format      string
	annexVIIRef string
	source      string // "toolkit" or "manufacturer"
	description string
}

// componentInfo holds parsed SBOM component data for cross-validation.
type componentInfo struct { //nolint:unused // used in tasks 3-6
	Name    string
	Version string
	PURL    string
}

// findingInfo holds parsed scan finding data for cross-validation.
type findingInfo struct { //nolint:unused // used in tasks 3-6
	CVE          string
	AffectedPURL string
	Severity     string
}

// vexInfo holds parsed VEX result data for cross-validation.
type vexInfo struct { //nolint:unused // used in tasks 3-6
	CVE           string
	ComponentPURL string
	Status        string
}

// policyReportData holds parsed policy report data for summary stats.
type policyReportData struct { //nolint:unused // used in tasks 3-6
	Total   int `json:"total"`
	Passed  int `json:"passed"`
	Failed  int `json:"failed"`
	Skipped int `json:"skipped"`
	Human   int `json:"human"`
}
