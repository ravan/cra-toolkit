// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

// Package report generates CRA Article 14 vulnerability notification documents.
// It supports the three-stage pipeline: 24h early warning, 72h notification, 14-day final report.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/formats/csafvex"
	"github.com/ravan/cra-toolkit/pkg/formats/cyclonedx"
	"github.com/ravan/cra-toolkit/pkg/formats/grype"
	"github.com/ravan/cra-toolkit/pkg/formats/openvex"
	"github.com/ravan/cra-toolkit/pkg/formats/sarif"
	"github.com/ravan/cra-toolkit/pkg/formats/spdx"
	"github.com/ravan/cra-toolkit/pkg/formats/trivy"
	"github.com/ravan/cra-toolkit/pkg/policykit"
)

// RunOption configures a Run() call with extensions.
type RunOption func(*runConfig)

type runConfig struct{}

// Run executes the Art. 14 notification generation pipeline.
func Run(opts *Options, out io.Writer, _ ...RunOption) error { //nolint:gocognit,gocyclo // pipeline has many sequential stages
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
		entries = BuildEarlyWarning(exploited, &cfg.Manufacturer)
	case StageNotification:
		entries = BuildNotification(exploited, &cfg.Manufacturer, components, vexResults)
	case StageFinalReport:
		entries = BuildFinalReport(exploited, &cfg.Manufacturer, components, vexResults, human, opts.CorrectiveMeasureDate)
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

// --- File parsing helpers ---

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
