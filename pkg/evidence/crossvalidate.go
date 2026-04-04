package evidence

import (
	"fmt"
	"os"
	"strings"
)

// CrossValidate runs consistency checks across bundled artifacts.
// Only checks applicable to the provided artifacts are executed.
func CrossValidate(sbomPath, vexPath string, scanPaths []string, policyPath, csafPath, reportPath string) ([]ValidationCheck, error) {
	artifacts, err := loadCrossValidateArtifacts(sbomPath, vexPath, scanPaths)
	if err != nil {
		return nil, err
	}
	return runCrossChecks(sbomPath, vexPath, scanPaths, reportPath, artifacts)
}

// crossValidateArtifacts holds parsed artifact data for cross-validation.
type crossValidateArtifacts struct {
	components []componentInfo
	vex        []vexInfo
	findings   []findingInfo
}

func loadCrossValidateArtifacts(sbomPath, vexPath string, scanPaths []string) (crossValidateArtifacts, error) {
	var a crossValidateArtifacts

	if sbomPath != "" {
		comps, err := parseSBOMComponents(sbomPath)
		if err != nil {
			return a, fmt.Errorf("cross-validate parse SBOM: %w", err)
		}
		a.components = comps
	}

	if vexPath != "" {
		vex, err := parseVEXData(vexPath)
		if err != nil {
			return a, fmt.Errorf("cross-validate parse VEX: %w", err)
		}
		a.vex = vex
	}

	if len(scanPaths) > 0 {
		findings, err := parseScanFindings(scanPaths)
		if err != nil {
			return a, fmt.Errorf("cross-validate parse scans: %w", err)
		}
		a.findings = findings
	}

	return a, nil
}

func runCrossChecks(sbomPath, vexPath string, scanPaths []string, reportPath string, a crossValidateArtifacts) ([]ValidationCheck, error) {
	var checks []ValidationCheck

	// CV-SBOM-VEX-PURL: VEX subject PURLs must exist in SBOM.
	if sbomPath != "" && vexPath != "" {
		checks = append(checks, checkSBOMvsVEX(a.components, a.vex))
	}

	// CV-SBOM-SCAN-COMP: Scanned component PURLs must exist in SBOM.
	if sbomPath != "" && len(scanPaths) > 0 {
		checks = append(checks, checkSBOMvsScans(a.components, a.findings))
	}

	// CV-SCAN-VEX-CVE: CVEs in scan results should have VEX assessments.
	if len(scanPaths) > 0 && vexPath != "" {
		checks = append(checks, checkScanVsVEX(a.findings, a.vex))
	}

	// CV-REPORT-SCAN: Art. 14 notification CVEs must exist in scan results.
	if reportPath != "" && len(scanPaths) > 0 {
		c, err := checkReportVsScans(reportPath, a.findings)
		if err != nil {
			c = ValidationCheck{
				CheckID:     "CV-REPORT-SCAN",
				Description: "Art. 14 notification CVEs exist in scan results",
				Status:      "fail",
				Details:     fmt.Sprintf("Cannot read Art. 14 report: %v", err),
				ArtifactA:   "art14-report",
				ArtifactB:   "scans",
			}
		}
		checks = append(checks, c)
	}

	return checks, nil
}

func checkSBOMvsVEX(components []componentInfo, vex []vexInfo) ValidationCheck {
	purlSet := make(map[string]bool, len(components))
	for i := range components {
		if components[i].PURL != "" {
			purlSet[components[i].PURL] = true
		}
	}

	var missing []string
	for i := range vex {
		if vex[i].ComponentPURL != "" && !purlSet[vex[i].ComponentPURL] {
			missing = append(missing, vex[i].ComponentPURL)
		}
	}

	if len(missing) > 0 {
		return ValidationCheck{
			CheckID:     "CV-SBOM-VEX-PURL",
			Description: "VEX subject PURLs exist in SBOM",
			Status:      "fail",
			Details:     fmt.Sprintf("VEX references %d PURLs not in SBOM: %s", len(missing), strings.Join(missing, ", ")),
			ArtifactA:   "sbom",
			ArtifactB:   "vex",
		}
	}

	return ValidationCheck{
		CheckID:     "CV-SBOM-VEX-PURL",
		Description: "VEX subject PURLs exist in SBOM",
		Status:      "pass",
		Details:     fmt.Sprintf("All %d VEX subject PURLs found in SBOM", len(vex)),
		ArtifactA:   "sbom",
		ArtifactB:   "vex",
	}
}

func checkSBOMvsScans(components []componentInfo, findings []findingInfo) ValidationCheck {
	purlSet := make(map[string]bool, len(components))
	for i := range components {
		if components[i].PURL != "" {
			purlSet[components[i].PURL] = true
		}
	}

	var missing []string
	seen := make(map[string]bool)
	for i := range findings {
		purl := findings[i].AffectedPURL
		if purl != "" && !purlSet[purl] && !seen[purl] {
			missing = append(missing, purl)
			seen[purl] = true
		}
	}

	if len(missing) > 0 {
		return ValidationCheck{
			CheckID:     "CV-SBOM-SCAN-COMP",
			Description: "Scanned components exist in SBOM",
			Status:      "fail",
			Details:     fmt.Sprintf("Scan references %d PURLs not in SBOM: %s", len(missing), strings.Join(missing, ", ")),
			ArtifactA:   "sbom",
			ArtifactB:   "scans",
		}
	}

	return ValidationCheck{
		CheckID:     "CV-SBOM-SCAN-COMP",
		Description: "Scanned components exist in SBOM",
		Status:      "pass",
		Details:     "All scanned component PURLs found in SBOM",
		ArtifactA:   "sbom",
		ArtifactB:   "scans",
	}
}

func checkScanVsVEX(findings []findingInfo, vex []vexInfo) ValidationCheck {
	vexCVEs := make(map[string]bool, len(vex))
	for i := range vex {
		vexCVEs[vex[i].CVE] = true
	}

	var unassessed []string
	seen := make(map[string]bool)
	for i := range findings {
		cve := findings[i].CVE
		if cve != "" && !vexCVEs[cve] && !seen[cve] {
			unassessed = append(unassessed, cve)
			seen[cve] = true
		}
	}

	if len(unassessed) > 0 {
		return ValidationCheck{
			CheckID:     "CV-SCAN-VEX-CVE",
			Description: "Scan CVEs have VEX assessments",
			Status:      "warn",
			Details:     fmt.Sprintf("%d scan CVEs without VEX assessment: %s", len(unassessed), strings.Join(unassessed, ", ")),
			ArtifactA:   "scans",
			ArtifactB:   "vex",
		}
	}

	return ValidationCheck{
		CheckID:     "CV-SCAN-VEX-CVE",
		Description: "Scan CVEs have VEX assessments",
		Status:      "pass",
		Details:     "All scan CVEs have VEX assessments",
		ArtifactA:   "scans",
		ArtifactB:   "vex",
	}
}

func checkReportVsScans(reportPath string, findings []findingInfo) (ValidationCheck, error) {
	data, err := os.ReadFile(reportPath) //nolint:gosec // CLI flag
	if err != nil {
		return ValidationCheck{}, err
	}

	var raw struct {
		Vulnerabilities []struct {
			CVE string `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := jsonUnmarshal(data, &raw); err != nil {
		return ValidationCheck{}, err
	}

	scanCVEs := make(map[string]bool, len(findings))
	for i := range findings {
		scanCVEs[findings[i].CVE] = true
	}

	var missing []string
	for _, v := range raw.Vulnerabilities {
		if v.CVE != "" && !scanCVEs[v.CVE] {
			missing = append(missing, v.CVE)
		}
	}

	if len(missing) > 0 {
		return ValidationCheck{
			CheckID:     "CV-REPORT-SCAN",
			Description: "Art. 14 notification CVEs exist in scan results",
			Status:      "fail",
			Details:     fmt.Sprintf("Art. 14 references %d CVEs not in scans: %s", len(missing), strings.Join(missing, ", ")),
			ArtifactA:   "art14-report",
			ArtifactB:   "scans",
		}, nil
	}

	return ValidationCheck{
		CheckID:     "CV-REPORT-SCAN",
		Description: "Art. 14 notification CVEs exist in scan results",
		Status:      "pass",
		Details:     "All Art. 14 notification CVEs found in scan results",
		ArtifactA:   "art14-report",
		ArtifactB:   "scans",
	}, nil
}
