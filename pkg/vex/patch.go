// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package vex

import (
	"fmt"

	packageurl "github.com/package-url/packageurl-go"
	"github.com/ravan/cra-toolkit/pkg/formats"
	"golang.org/x/mod/semver"
)

// patchFilter resolves findings when the installed component version is >= the fix version,
// returning StatusFixed to indicate the vulnerability has been patched.
type patchFilter struct{}

// NewPatchFilter returns a Filter that marks a finding fixed when the installed version
// is at or above the fix version. Unlike the version filter (which returns not_affected),
// this filter returns fixed — more semantically precise for patched packages.
func NewPatchFilter() Filter {
	return &patchFilter{}
}

func (f *patchFilter) Name() string { return "patch" }

//nolint:gocyclo // patch comparison requires validation and matching steps
func (f *patchFilter) Evaluate(finding *formats.Finding, components []formats.Component) (Result, bool) {
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
		if compPURL.Type != affectedPURL.Type ||
			compPURL.Namespace != affectedPURL.Namespace ||
			compPURL.Name != affectedPURL.Name {
			continue
		}

		installedVer := normalizeSemver(components[i].Version)
		if !semver.IsValid(installedVer) {
			continue
		}

		if semver.Compare(installedVer, fixVer) >= 0 {
			return Result{
				CVE:           finding.CVE,
				ComponentPURL: components[i].PURL,
				Status:        formats.StatusFixed,
				Confidence:    formats.ConfidenceHigh,
				ResolvedBy:    "patch",
				Evidence: fmt.Sprintf(
					"Installed version %s >= fix version %s; patch has been applied.",
					components[i].Version, finding.FixVersion,
				),
			}, true
		}
	}

	return Result{}, false
}
