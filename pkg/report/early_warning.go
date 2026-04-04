package report

// BuildEarlyWarning creates VulnEntry values for the 24h early warning stage.
// Per Art. 14(2)(a): CVE, exploitation signals, severity, affected products, member states.
func BuildEarlyWarning(vulns []ExploitedVuln, mfr *Manufacturer) []VulnEntry {
	entries := make([]VulnEntry, 0, len(vulns))
	for i := range vulns {
		v := &vulns[i]
		entries = append(entries, VulnEntry{
			CVE:                 v.CVE,
			ExploitationSignals: v.Signals,
			Severity:            v.Severity,
			CVSS:                v.CVSS,
			AffectedProducts:    v.AffectedProducts,
			MemberStates:        mfr.MemberStatesAvailable,
		})
	}
	return entries
}
