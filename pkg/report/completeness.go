// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package report

// ComputeCompleteness calculates the toolkit quality metric for a notification.
// This is NOT a regulatory compliance measure.
func ComputeCompleteness(n *Notification) Completeness {
	var total, filled, machine, human int
	var pending []string

	for i := range n.Vulnerabilities {
		fields := completenessFields(n.Stage, &n.Vulnerabilities[i])
		for _, f := range fields {
			total++
			if f.filled {
				filled++
				if f.source == "human" {
					human++
				} else {
					machine++
				}
			} else {
				pending = append(pending, f.name)
			}
		}
	}

	score := 0.0
	if total > 0 {
		score = float64(filled) / float64(total)
	}

	return Completeness{
		Score:            score,
		TotalFields:      total,
		FilledFields:     filled,
		MachineGenerated: machine,
		HumanProvided:    human,
		Pending:          pending,
		Note:             CompletenessNote,
	}
}

type fieldCheck struct {
	name   string
	filled bool
	source string // "machine" or "human"
}

func completenessFields(stage Stage, v *VulnEntry) []fieldCheck { //nolint:gocyclo // field enumeration by stage
	var fields []fieldCheck

	// Early warning fields (all stages).
	fields = append(fields,
		fieldCheck{"cve", v.CVE != "", "machine"},
		fieldCheck{"exploitation_signals", len(v.ExploitationSignals) > 0, "machine"},
		fieldCheck{"severity", v.Severity != "", "machine"},
		fieldCheck{"affected_products", len(v.AffectedProducts) > 0, "machine"},
	)

	if stage == StageEarlyWarning {
		return fields
	}

	// Notification fields (72h+).
	fields = append(fields,
		fieldCheck{"description", v.Description != "", "machine"},
		fieldCheck{"general_nature", v.GeneralNature != "", "machine"},
		fieldCheck{"corrective_actions", len(v.CorrectiveActions) > 0, "machine"},
		fieldCheck{"estimated_impact", v.EstimatedImpact != nil, "machine"},
		fieldCheck{"information_sensitivity", v.InformationSensitivity != "", "machine"},
	)

	if stage == StageNotification {
		return fields
	}

	// Final report fields (14d).
	fields = append(fields,
		fieldCheck{"corrective_measure_date", v.CorrectiveMeasureDate != "", "human"},
		fieldCheck{"root_cause", v.RootCause != "" && v.RootCause != humanInputRequired, "human"},
		fieldCheck{"threat_actor_info", v.ThreatActorInfo != "" && v.ThreatActorInfo != humanInputRequired, "human"},
		fieldCheck{"security_update", v.SecurityUpdate != "" && v.SecurityUpdate != humanInputRequired, "human"},
	)

	return fields
}
