// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package vex

import (
	"fmt"
	"strings"

	packageurl "github.com/package-url/packageurl-go"
	"github.com/ravan/cra-toolkit/pkg/formats"
	"golang.org/x/mod/semver"
)

// versionFilter resolves findings when the installed component version is >= the fix version,
// indicating the installed version is outside the affected range.
type versionFilter struct{}

// NewVersionFilter returns a Filter that marks a finding not_affected when the
// installed version is at or above the fix version.
func NewVersionFilter() Filter {
	return &versionFilter{}
}

func (f *versionFilter) Name() string { return "version" }

// normalizeSemver ensures the version string has a "v" prefix as required by golang.org/x/mod/semver.
func normalizeSemver(v string) string {
	if !strings.HasPrefix(v, "v") {
		return "v" + v
	}
	return v
}

//nolint:gocyclo // version comparison requires validation and matching steps
func (f *versionFilter) Evaluate(finding *formats.Finding, components []formats.Component) (Result, bool) {
	if finding.FixVersion == "" {
		return Result{}, false
	}

	fixVer := normalizeSemver(finding.FixVersion)
	if !semver.IsValid(fixVer) {
		return Result{}, false
	}

	affectedPURL, err := packageurl.FromString(finding.AffectedPURL)
	if err != nil {
		return Result{}, false
	}

	for i := range components {
		compPURL, err := packageurl.FromString(components[i].PURL)
		if err != nil {
			continue
		}
		// Match by type+namespace+name (ignore version in PURL; use Component.Version field).
		if compPURL.Type != affectedPURL.Type ||
			compPURL.Namespace != affectedPURL.Namespace ||
			compPURL.Name != affectedPURL.Name {
			continue
		}

		installedVer := normalizeSemver(components[i].Version)
		if !semver.IsValid(installedVer) {
			continue
		}

		// semver.Compare returns >= 0 when installed >= fix.
		if semver.Compare(installedVer, fixVer) >= 0 {
			return Result{
				CVE:           finding.CVE,
				ComponentPURL: components[i].PURL,
				Status:        formats.StatusNotAffected,
				Justification: formats.JustificationVulnerableCodeNotPresent,
				Confidence:    formats.ConfidenceHigh,
				ResolvedBy:    "version",
				Evidence: fmt.Sprintf(
					"Installed version %s >= fix version %s; component is outside the affected range.",
					components[i].Version, finding.FixVersion,
				),
			}, true
		}
	}

	return Result{}, false
}
