package evidence

type annexVIISectionDef struct {
	id       string
	title    string
	craRef   string
	weight   int
	required bool
}

var annexVIISections = []annexVIISectionDef{
	{"1a", "General description — intended purpose", "Annex VII, point 1(a)", 10, true},
	{"1b", "Versions affecting compliance", "Annex VII, point 1(b)", 5, true},
	{"1c", "Hardware photos/illustrations", "Annex VII, point 1(c)", 0, false},
	{"1d", "User information per Annex II", "Annex VII, point 1(d)", 5, true},
	{"2a", "Design/development/architecture", "Annex VII, point 2(a)", 10, true},
	{"2b-sbom", "Vulnerability handling — SBOM", "Annex VII, point 2(b)", 15, true},
	{"2b-cvd", "Vulnerability handling — CVD policy", "Annex VII, point 2(b)", 10, true},
	{"2b-updates", "Vulnerability handling — secure update mechanism", "Annex VII, point 2(b)", 5, true},
	{"2c", "Production/monitoring processes", "Annex VII, point 2(c)", 5, true},
	{"3", "Cybersecurity risk assessment", "Annex VII, point 3", 15, true},
	{"4", "Support period determination", "Annex VII, point 4", 5, true},
	{"5", "Harmonised standards applied", "Annex VII, point 5", 5, true},
	{"6", "Test/verification reports", "Annex VII, point 6", 10, true},
	{"7", "EU declaration of conformity", "Annex VII, point 7", 10, true},
	{"8", "SBOM (market surveillance)", "Annex VII, point 8", 5, true},
}

// sectionChecker is a function that determines coverage for one Annex VII section.
type sectionChecker func(artifacts []ArtifactEntry, product *ProductIdentity) (covered bool, paths []string, gap string)

// sectionCheckers maps each Annex VII section ID to its coverage checker function.
var sectionCheckers = map[string]sectionChecker{
	"1a": func(a []ArtifactEntry, p *ProductIdentity) (bool, []string, string) {
		return coverageFromProductField(p.IntendedPurpose, "Set intended_purpose in product config")
	},
	"1b": func(a []ArtifactEntry, p *ProductIdentity) (bool, []string, string) {
		return coverageFromToolkitSBOM(a, "Provide an SBOM to document versions affecting compliance")
	},
	"1c": func(_ []ArtifactEntry, _ *ProductIdentity) (bool, []string, string) {
		// Always weight 0 for software products — never a gap
		return true, nil, ""
	},
	"1d": func(_ []ArtifactEntry, p *ProductIdentity) (bool, []string, string) {
		return coverageFromUserInfo(p)
	},
	"2a": func(a []ArtifactEntry, _ *ProductIdentity) (bool, []string, string) {
		return coverageFromManufacturerArtifact(a, "2a", "Provide architecture/design documentation")
	},
	"2b-sbom": func(a []ArtifactEntry, _ *ProductIdentity) (bool, []string, string) {
		return coverageFromToolkitSBOM(a, "Generate an SBOM using the toolkit")
	},
	"2b-cvd": coverageFrom2bCVD,
	"2b-updates": func(a []ArtifactEntry, _ *ProductIdentity) (bool, []string, string) {
		// Covered when a manufacturer "2b" artifact is present (the CVD policy doc
		// covers the update mechanism documentation requirement broadly)
		return coverageFromManufacturerArtifact(a, "2b", "Provide documentation of the secure update mechanism")
	},
	"2c": func(a []ArtifactEntry, _ *ProductIdentity) (bool, []string, string) {
		return coverageFromManufacturerArtifact(a, "2c", "Provide production and monitoring process documentation")
	},
	"3": func(a []ArtifactEntry, _ *ProductIdentity) (bool, []string, string) {
		return coverageFromManufacturerArtifact(a, "3", "Provide a cybersecurity risk assessment")
	},
	"4": func(_ []ArtifactEntry, p *ProductIdentity) (bool, []string, string) {
		return coverageFromProductField(p.SupportPeriodEnd, "Set support_period_end in product config")
	},
	"5": func(a []ArtifactEntry, _ *ProductIdentity) (bool, []string, string) {
		return coverageFromManufacturerArtifact(a, "5", "Provide documentation of harmonised standards applied")
	},
	"6": func(a []ArtifactEntry, _ *ProductIdentity) (bool, []string, string) {
		return coverageFromAnyArtifact(a, "6", "Provide test and verification reports (VEX, scan, policy reports)")
	},
	"7": func(a []ArtifactEntry, _ *ProductIdentity) (bool, []string, string) {
		return coverageFromManufacturerArtifact(a, "7", "Provide the EU declaration of conformity")
	},
	"8": func(a []ArtifactEntry, _ *ProductIdentity) (bool, []string, string) {
		return coverageFromToolkitSBOM(a, "Generate an SBOM for market surveillance authority access")
	},
}

// ComputeCompleteness calculates Annex VII documentation coverage from collected artifacts
// and product identity metadata. It returns a CompletenessReport with per-section coverage
// and an overall weighted score.
func ComputeCompleteness(artifacts []ArtifactEntry, product *ProductIdentity) CompletenessReport {
	sections := make([]AnnexVIISection, 0, len(annexVIISections))

	for _, def := range annexVIISections {
		section := AnnexVIISection{
			ID:       def.id,
			Title:    def.title,
			CRARef:   def.craRef,
			Required: def.required,
			Weight:   def.weight,
		}

		if checker, ok := sectionCheckers[def.id]; ok {
			section.Covered, section.Artifacts, section.Gap = checker(artifacts, product)
		} else {
			section.Gap = "Unknown section"
		}

		sections = append(sections, section)
	}

	var totalWeight, coveredWeight int
	for _, s := range sections {
		if s.Weight > 0 {
			totalWeight += s.Weight
			if s.Covered {
				coveredWeight += s.Weight
			}
		}
	}

	score := 0.0
	if totalWeight > 0 {
		score = float64(coveredWeight) / float64(totalWeight) * 100
	}

	return CompletenessReport{
		Sections:      sections,
		Score:         score,
		TotalWeight:   totalWeight,
		CoveredWeight: coveredWeight,
		Note:          CompletenessNote,
	}
}

// coverageFromProductField returns covered=true when the given product metadata field is non-empty.
func coverageFromProductField(field, gapMsg string) (covered bool, paths []string, gap string) {
	if field != "" {
		return true, nil, ""
	}
	return false, nil, gapMsg
}

// coverageFromUserInfo returns covered when any user-facing contact or policy field is set.
func coverageFromUserInfo(product *ProductIdentity) (covered bool, paths []string, gap string) {
	if product.SecurityContact != "" || product.CVDPolicyURL != "" || product.SupportPeriodEnd != "" {
		return true, nil, ""
	}
	return false, nil, "Set security_contact, cvd_policy_url, or support_period_end in product config"
}

// coverageFromToolkitSBOM returns covered when the toolkit SBOM artifact (annex ref "2b") is present.
func coverageFromToolkitSBOM(artifacts []ArtifactEntry, gapMsg string) (covered bool, paths []string, gap string) {
	ok, artifactPaths := hasArtifactRef(artifacts, "2b", "toolkit")
	if ok {
		return true, artifactPaths, ""
	}
	return false, nil, gapMsg
}

// coverageFromManufacturerArtifact returns covered when a manufacturer artifact with the given annex ref is present.
func coverageFromManufacturerArtifact(artifacts []ArtifactEntry, ref, gapMsg string) (covered bool, paths []string, gap string) {
	ok, artifactPaths := hasArtifactRef(artifacts, ref, "manufacturer")
	if ok {
		return true, artifactPaths, ""
	}
	return false, nil, gapMsg
}

// coverageFrom2bCVD covers the CVD policy section via manufacturer artifact or product config URL.
func coverageFrom2bCVD(artifacts []ArtifactEntry, product *ProductIdentity) (covered bool, paths []string, gap string) {
	ok, artifactPaths := hasArtifactRef(artifacts, "2b", "manufacturer")
	if ok {
		return true, artifactPaths, ""
	}
	if product.CVDPolicyURL != "" {
		return true, nil, ""
	}
	return false, nil, "Provide a CVD policy document or set cvd_policy_url in product config"
}

// coverageFromAnyArtifact returns covered when any artifact (regardless of source) has the given annex ref.
func coverageFromAnyArtifact(artifacts []ArtifactEntry, ref, gapMsg string) (covered bool, paths []string, gap string) {
	for _, a := range artifacts {
		if a.AnnexVIIRef == ref {
			paths = append(paths, a.Path)
		}
	}
	if len(paths) > 0 {
		return true, paths, ""
	}
	return false, nil, gapMsg
}

// hasArtifactRef returns true and the artifact paths when artifacts matching ref and source are found.
func hasArtifactRef(artifacts []ArtifactEntry, ref, source string) (found bool, paths []string) {
	for _, a := range artifacts {
		if a.AnnexVIIRef == ref && a.Source == source {
			paths = append(paths, a.Path)
		}
	}
	return len(paths) > 0, paths
}
