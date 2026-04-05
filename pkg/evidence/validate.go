// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package evidence

import (
	"fmt"
	"os"

	"github.com/ravan/cra-toolkit/pkg/formats"
)

// ValidateArtifacts resolves artifacts from opts and checks that each
// toolkit-generated artifact has a valid, recognized format.
// Manufacturer-provided documents receive existence-only checks.
func ValidateArtifacts(opts *Options) ([]ValidationCheck, error) {
	arts, err := ResolveArtifacts(opts)
	if err != nil {
		return nil, err
	}
	return validateArtifacts(arts), nil
}

// validateArtifacts is the internal implementation operating on []artifactInput.
func validateArtifacts(arts []artifactInput) []ValidationCheck {
	checks := make([]ValidationCheck, 0, len(arts))
	for i := range arts {
		a := &arts[i]
		if a.source == "manufacturer" {
			checks = append(checks, ValidationCheck{
				CheckID:     fmt.Sprintf("FV-%s", a.annexVIIRef),
				Description: fmt.Sprintf("File exists: %s", a.description),
				Status:      "pass",
				Details:     fmt.Sprintf("Manufacturer document present at %s", a.sourcePath),
				ArtifactA:   a.sourcePath,
			})
			continue
		}
		checks = append(checks, validateToolkitArtifact(a))
	}
	return checks
}

// TestArtifactInput is an exported mirror of artifactInput for use in external tests.
type TestArtifactInput struct {
	SourcePath  string
	Format      string
	AnnexVIIRef string
	Source      string
	Description string
}

// ValidateTestArtifacts converts TestArtifactInput to artifactInput and validates.
// This is a test helper for external test packages.
func ValidateTestArtifacts(arts []TestArtifactInput) []ValidationCheck {
	internal := make([]artifactInput, len(arts))
	for i, a := range arts {
		internal[i] = artifactInput{
			sourcePath:  a.SourcePath,
			format:      a.Format,
			annexVIIRef: a.AnnexVIIRef,
			source:      a.Source,
			description: a.Description,
		}
	}
	return validateArtifacts(internal)
}

func validateToolkitArtifact(a *artifactInput) ValidationCheck {
	f, err := os.Open(a.sourcePath) //nolint:gosec // CLI flag
	if err != nil {
		return ValidationCheck{
			CheckID:     fmt.Sprintf("FV-%s", a.annexVIIRef),
			Description: fmt.Sprintf("Format validation: %s", a.description),
			Status:      "fail",
			Details:     fmt.Sprintf("Cannot open file: %v", err),
			ArtifactA:   a.sourcePath,
		}
	}
	defer f.Close() //nolint:errcheck // read-only

	format, err := formats.DetectFormat(f)
	if err != nil || format == formats.FormatUnknown {
		return ValidationCheck{
			CheckID:     fmt.Sprintf("FV-%s", a.annexVIIRef),
			Description: fmt.Sprintf("Format validation: %s", a.description),
			Status:      "fail",
			Details:     fmt.Sprintf("Unrecognized format for %s", a.sourcePath),
			ArtifactA:   a.sourcePath,
		}
	}

	return ValidationCheck{
		CheckID:     fmt.Sprintf("FV-%s", a.annexVIIRef),
		Description: fmt.Sprintf("Format validation: %s", a.description),
		Status:      "pass",
		Details:     fmt.Sprintf("Detected format: %s", format),
		ArtifactA:   a.sourcePath,
	}
}
