// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package evidence

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// annexVIIDir maps Annex VII references to directory names.
var annexVIIDir = map[string]string{
	"2b": "2b-vulnerability-handling",
	"2a": "2a-design-development",
	"2c": "2c-production-monitoring",
	"3":  "3-risk-assessment",
	"5":  "5-standards",
	"6":  "6-test-reports",
	"7":  "7-eu-declaration",
}

// annexVIIDirs lists all Annex VII section directories to create.
var annexVIIDirs = []string{
	"1-general-description",
	"2a-design-development",
	"2b-vulnerability-handling",
	"2c-production-monitoring",
	"3-risk-assessment",
	"4-support-period",
	"5-standards",
	"6-test-reports",
	"7-eu-declaration",
	"8-sbom",
}

// Assemble creates the Annex VII directory structure and copies artifacts.
func Assemble(outputDir, configPath string, artifacts []artifactInput) ([]ArtifactEntry, error) {
	annexDir := filepath.Join(outputDir, "annex-vii")

	if err := createAnnexDirs(annexDir); err != nil {
		return nil, err
	}

	entries := make([]ArtifactEntry, 0, len(artifacts)+2)

	if configPath != "" {
		entry, err := copyConfigArtifact(annexDir, configPath)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}

	artifactEntries, sbomDst, err := copyArtifacts(annexDir, artifacts)
	if err != nil {
		return nil, err
	}
	entries = append(entries, artifactEntries...)

	if sbomDst != "" {
		entry, err := copySBOMToSection8(annexDir, sbomDst)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

// createAnnexDirs creates all Annex VII section subdirectories.
func createAnnexDirs(annexDir string) error {
	for _, d := range annexVIIDirs {
		if err := os.MkdirAll(filepath.Join(annexDir, d), 0o750); err != nil { //nolint:gosec // output dir
			return fmt.Errorf("create dir %s: %w", d, err)
		}
	}
	return nil
}

// copyConfigArtifact copies the product config to section 1.
func copyConfigArtifact(annexDir, configPath string) (ArtifactEntry, error) {
	dst := filepath.Join(annexDir, "1-general-description", "product-config.yaml")
	if err := copyFile(configPath, dst); err != nil {
		return ArtifactEntry{}, fmt.Errorf("copy product config: %w", err)
	}
	hash, err := hashFile(dst)
	if err != nil {
		return ArtifactEntry{}, fmt.Errorf("hash %s: %w", dst, err)
	}
	return ArtifactEntry{
		Path:        filepath.Join("annex-vii", "1-general-description", "product-config.yaml"),
		AnnexVIIRef: "1a",
		Format:      "yaml",
		SHA256:      hash,
		Source:      "toolkit",
		Description: "Product configuration",
	}, nil
}

// copyArtifacts copies all artifacts to their Annex VII section directories.
// Returns entries and the path of the first toolkit SBOM (for section 8 duplication).
func copyArtifacts(annexDir string, artifacts []artifactInput) ([]ArtifactEntry, string, error) {
	entries := make([]ArtifactEntry, 0, len(artifacts))
	var sbomDst string

	for _, a := range artifacts {
		dir, ok := annexVIIDir[a.annexVIIRef]
		if !ok {
			dir = "6-test-reports"
		}

		filename := filepath.Base(a.sourcePath)
		dst := filepath.Join(annexDir, dir, filename)
		if err := copyFile(a.sourcePath, dst); err != nil {
			return nil, "", fmt.Errorf("copy %s: %w", a.sourcePath, err)
		}

		hash, err := hashFile(dst)
		if err != nil {
			return nil, "", fmt.Errorf("hash %s: %w", dst, err)
		}
		entries = append(entries, ArtifactEntry{
			Path:        filepath.Join("annex-vii", dir, filename),
			AnnexVIIRef: a.annexVIIRef,
			Format:      a.format,
			SHA256:      hash,
			Source:      a.source,
			Description: a.description,
		})

		if a.annexVIIRef == "2b" && a.source == "toolkit" && sbomDst == "" {
			sbomDst = dst
		}
	}

	return entries, sbomDst, nil
}

// copySBOMToSection8 copies the SBOM to the dedicated section 8 directory.
func copySBOMToSection8(annexDir, sbomDst string) (ArtifactEntry, error) {
	filename := filepath.Base(sbomDst)
	dst8 := filepath.Join(annexDir, "8-sbom", filename)
	if err := copyFile(sbomDst, dst8); err != nil {
		return ArtifactEntry{}, fmt.Errorf("copy SBOM to section 8: %w", err)
	}
	hash, err := hashFile(dst8)
	if err != nil {
		return ArtifactEntry{}, fmt.Errorf("hash %s: %w", dst8, err)
	}
	return ArtifactEntry{
		Path:        filepath.Join("annex-vii", "8-sbom", filename),
		AnnexVIIRef: "8",
		Format:      "CycloneDX",
		SHA256:      hash,
		Source:      "toolkit",
		Description: "SBOM for market surveillance (Annex VII point 8)",
	}, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src) //nolint:gosec // internal path
	if err != nil {
		return err
	}
	defer in.Close() //nolint:errcheck // read-only

	out, err := os.Create(dst) //nolint:gosec // output file
	if err != nil {
		return err
	}
	defer out.Close() //nolint:errcheck // will check write err

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}
