package vex

import (
	"fmt"
	"strings"

	packageurl "github.com/package-url/packageurl-go"
	"github.com/ravan/suse-cra-toolkit/pkg/formats"
)

// platformFilter resolves findings when the CVE's affected platforms do not include
// the component's target platform.
type platformFilter struct{}

// NewPlatformFilter returns a Filter that marks a finding not_affected when the
// component's platform is not in the CVE's affected platform list.
func NewPlatformFilter() Filter {
	return &platformFilter{}
}

func (f *platformFilter) Name() string { return "platform" }

//nolint:gocognit,gocyclo // platform matching requires comparing multiple qualifiers
func (f *platformFilter) Evaluate(finding *formats.Finding, components []formats.Component) (Result, bool) {
	if len(finding.Platforms) == 0 {
		// No platform restriction in the CVE — cannot determine via platform.
		return Result{}, false
	}

	affectedPURL, err := packageurl.FromString(finding.AffectedPURL)
	if err != nil {
		return Result{}, false
	}

	// Find the matching component.
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

		// Determine the component's platform: prefer PURL qualifier, fall back to Component.Platform field.
		compPlatform := components[i].Platform
		if p := compPURL.Qualifiers.Map()["os"]; p != "" {
			compPlatform = p
		}

		if compPlatform == "" {
			// No platform info on the component side — cannot determine.
			return Result{}, false
		}

		// Check if the component's platform is in the CVE's affected list.
		for _, affectedPlatform := range finding.Platforms {
			if strings.EqualFold(compPlatform, affectedPlatform) {
				// Platform matches — finding may apply; not resolved.
				return Result{}, false
			}
		}

		// Component platform is not in the affected list.
		return Result{
			CVE:           finding.CVE,
			ComponentPURL: components[i].PURL,
			Status:        formats.StatusNotAffected,
			Justification: formats.JustificationVulnerableCodeNotPresent,
			Confidence:    formats.ConfidenceHigh,
			ResolvedBy:    "platform",
			Evidence: fmt.Sprintf(
				"Component platform %q is not in CVE's affected platforms %v.",
				compPlatform, finding.Platforms,
			),
		}, true
	}

	return Result{}, false
}
