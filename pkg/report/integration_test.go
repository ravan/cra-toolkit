package report_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/report"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fixtureBase = "../../testdata/integration"

type expectedReport struct {
	Description string `json:"description"`
	Assertions  struct {
		Stage                    string              `json:"stage"`
		VulnerabilityCount       int                 `json:"vulnerability_count"`
		CVEs                     []string            `json:"cves"`
		ExploitationSignals      map[string][]string `json:"exploitation_signals"`
		CSIRTCountry             string              `json:"csirt_country"`
		CSIRTName                string              `json:"csirt_name"`
		SubmissionChannel        string              `json:"submission_channel"`
		HasUserNotification      bool                `json:"has_user_notification"`
		HasDescription           bool                `json:"has_description"`
		HasCorrectiveActions     bool                `json:"has_corrective_actions"`
		HasImpact                bool                `json:"has_impact"`
		HasRootCause             bool                `json:"has_root_cause"`
		HasThreatActorInfo       bool                `json:"has_threat_actor_info"`
		HasCorrectiveMeasureDate bool                `json:"has_corrective_measure_date"`
		MinCompleteness          float64             `json:"min_completeness"`
		Error                    string              `json:"error"`
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
		for i := range notification.Vulnerabilities {
			cveSet[notification.Vulnerabilities[i].CVE] = true
		}
		for _, cve := range expected.Assertions.CVEs {
			assert.True(t, cveSet[cve], "expected CVE %s not found", cve)
		}
	}

	// Exploitation signals.
	for cve, expectedSources := range expected.Assertions.ExploitationSignals {
		for i := range notification.Vulnerabilities {
			v := &notification.Vulnerabilities[i]
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
		for i := range notification.Vulnerabilities {
			v := &notification.Vulnerabilities[i]
			assert.NotEmpty(t, v.Description, "expected description for %s", v.CVE)
		}
	}
	if expected.Assertions.HasCorrectiveActions {
		hasActions := false
		for i := range notification.Vulnerabilities {
			if len(notification.Vulnerabilities[i].CorrectiveActions) > 0 {
				hasActions = true
			}
		}
		assert.True(t, hasActions, "expected corrective actions")
	}
	if expected.Assertions.HasImpact {
		for i := range notification.Vulnerabilities {
			v := &notification.Vulnerabilities[i]
			assert.NotNil(t, v.EstimatedImpact, "expected impact for %s", v.CVE)
		}
	}

	// Final report fields.
	if expected.Assertions.HasRootCause {
		for i := range notification.Vulnerabilities {
			v := &notification.Vulnerabilities[i]
			assert.NotEqual(t, "[HUMAN INPUT REQUIRED]", v.RootCause, "root cause should be filled for %s", v.CVE)
		}
	}
	if expected.Assertions.HasThreatActorInfo {
		for i := range notification.Vulnerabilities {
			v := &notification.Vulnerabilities[i]
			assert.NotEqual(t, "[HUMAN INPUT REQUIRED]", v.ThreatActorInfo, "threat actor should be filled for %s", v.CVE)
		}
	}
	if expected.Assertions.HasCorrectiveMeasureDate {
		for i := range notification.Vulnerabilities {
			v := &notification.Vulnerabilities[i]
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
