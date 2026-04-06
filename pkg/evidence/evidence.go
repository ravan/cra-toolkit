// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package evidence

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// RunOption configures a Run() call with extensions.
type RunOption func(*runConfig)

type runConfig struct{}

// Run executes the evidence bundling pipeline.
func Run(opts *Options, out io.Writer, _ ...RunOption) error { //nolint:gocognit,gocyclo // pipeline has many sequential stages
	// 0. Validate required options.
	if opts.ProductConfig == "" {
		return ErrNoProductConfig
	}
	if opts.OutputDir == "" {
		return ErrNoOutputDir
	}

	// 1. Parse inputs.
	cfg, err := LoadEvidenceConfig(opts.ProductConfig)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	product := BuildProductIdentity(cfg)

	arts, err := ResolveArtifacts(opts)
	if err != nil {
		return fmt.Errorf("resolve artifacts: %w", err)
	}

	if len(arts) == 0 {
		return ErrNoArtifacts
	}

	// 2. Validate artifact formats.
	formatChecks, err := ValidateArtifacts(opts)
	if err != nil {
		return fmt.Errorf("validate artifacts: %w", err)
	}

	// 3. Cross-validate consistency.
	crossChecks, err := CrossValidate(opts.SBOMPath, opts.VEXPath, opts.ScanPaths, opts.PolicyReport, opts.CSAFPath, opts.ReportPath)
	if err != nil {
		return fmt.Errorf("cross-validate: %w", err)
	}

	// Merge all validation checks.
	formatChecks = append(formatChecks, crossChecks...)
	allChecks := formatChecks
	var passed, failed, warnings int
	for _, c := range allChecks {
		switch c.Status {
		case "pass":
			passed++
		case "fail":
			failed++
		case "warn":
			warnings++
		}
	}

	// 4. Assemble directory structure.
	entries, err := Assemble(opts.OutputDir, opts.ProductConfig, arts)
	if err != nil {
		return fmt.Errorf("assemble: %w", err)
	}

	// 5. Summarize.
	completeness := ComputeCompleteness(entries, &product)
	summary := BuildSummary(&product, opts.SBOMPath, opts.VEXPath, opts.ScanPaths, opts.PolicyReport)
	summary.StandardsApplied = cfg.Evidence.StandardsApplied

	// 6. Compute manifest.
	manifest, err := ComputeManifest(opts.OutputDir)
	if err != nil {
		return fmt.Errorf("compute manifest: %w", err)
	}
	manifestPath := filepath.Join(opts.OutputDir, "manifest.sha256")
	if err := WriteManifest(manifest, manifestPath); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}

	// 7. Sign.
	sig := SignManifest(manifestPath, opts.SigningKey)

	// 8. Build bundle.
	bundle := &Bundle{
		BundleID:       "CRA-EVD-" + time.Now().UTC().Format("20060102T150405Z"),
		ToolkitVersion: "0.1.0",
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Product:        product,
		Artifacts:      entries,
		Validation: ValidationReport{
			Checks:   allChecks,
			Passed:   passed,
			Failed:   failed,
			Warnings: warnings,
		},
		Completeness: completeness,
		Summary:      summary,
		Manifest:     manifest,
		Signature:    sig,
	}

	// Write rendered markdown files into the bundle directory.
	if err := writeMarkdownFiles(opts.OutputDir, completeness, &summary, bundle.Validation); err != nil {
		return fmt.Errorf("write markdown files: %w", err)
	}

	// Write bundle.json into the output directory.
	bundleJSON, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal bundle: %w", err)
	}
	if err := writeFileBytes(filepath.Join(opts.OutputDir, "bundle.json"), bundleJSON); err != nil {
		return fmt.Errorf("write bundle.json: %w", err)
	}

	// 9. Archive (optional).
	if opts.Archive {
		archivePath := opts.OutputDir + ".tar.gz"
		if err := CreateArchive(opts.OutputDir, archivePath); err != nil {
			return fmt.Errorf("create archive: %w", err)
		}
	}

	// 10. Write to output writer.
	if opts.OutputFormat == "markdown" {
		_, err := io.WriteString(out, RenderCompletenessMarkdown(completeness))
		if err != nil {
			return err
		}
		_, err = io.WriteString(out, RenderSummaryMarkdown(&summary))
		return err
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(bundle)
}

func writeMarkdownFiles(dir string, comp CompletenessReport, summary *AnnexVIISummary, validation ValidationReport) error {
	if err := writeFileBytes(filepath.Join(dir, "completeness.md"), []byte(RenderCompletenessMarkdown(comp))); err != nil {
		return err
	}
	if err := writeFileBytes(filepath.Join(dir, "annex-vii-summary.md"), []byte(RenderSummaryMarkdown(summary))); err != nil {
		return err
	}
	return writeFileBytes(filepath.Join(dir, "validation.md"), []byte(RenderValidationMarkdown(validation)))
}

func writeFileBytes(path string, data []byte) error {
	return os.WriteFile(path, data, 0o644) //nolint:gosec // output file
}
