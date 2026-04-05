// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package report

import "fmt"

// BuildUserNotification creates the Art. 14(8) user notification section.
func BuildUserNotification(vulns []ExploitedVuln, csafRef string) *UserNotification {
	var allProducts []AffectedProduct
	var maxSeverity string
	var actions []string

	for i := range vulns {
		v := &vulns[i]
		allProducts = append(allProducts, v.AffectedProducts...)
		if compareSeverity(v.Severity, maxSeverity) > 0 {
			maxSeverity = v.Severity
		}
		if v.FixVersion != "" {
			name := v.CVE
			if len(v.AffectedProducts) > 0 {
				name = v.AffectedProducts[0].Name
			}
			actions = append(actions, fmt.Sprintf("Update %s to version %s or later", name, v.FixVersion))
		}
	}

	if len(actions) == 0 {
		actions = []string{"Monitor vendor advisories for patches and mitigations"}
	}

	return &UserNotification{
		AffectedProducts:   allProducts,
		RecommendedActions: actions,
		Severity:           maxSeverity,
		CSAFAdvisoryRef:    csafRef,
	}
}

func compareSeverity(a, b string) int {
	order := map[string]int{"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	return order[a] - order[b]
}
