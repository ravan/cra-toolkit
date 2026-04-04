package csaf

import (
	"encoding/json"
	"testing"
)

func TestCSAFDocumentSerializesToValidJSON(t *testing.T) {
	doc := csafDocument{
		Document: documentMeta{
			Category:    "csaf_security_advisory",
			CSAFVersion: "2.0",
			Title:       "Test Advisory",
			Publisher: publisher{
				Category:  "vendor",
				Name:      "SUSE",
				Namespace: "https://www.suse.com",
			},
			Tracking: tracking{
				ID:                 "SUSE-SU-2024:0001-1",
				Status:             "final",
				Version:            "1",
				InitialReleaseDate: "2024-01-15T00:00:00Z",
				CurrentReleaseDate: "2024-01-15T00:00:00Z",
				RevisionHistory: []revision{
					{Date: "2024-01-15T00:00:00Z", Number: "1", Summary: "Initial release"},
				},
			},
			AggregateSeverity: &aggregateSeverity{
				Text: "important",
			},
		},
		ProductTree: productTree{
			Branches: []branch{
				{
					Category: "vendor",
					Name:     "SUSE",
					Branches: []branch{
						{
							Category: "product_name",
							Name:     "SUSE Linux Enterprise Server 15 SP5",
							Branches: []branch{
								{
									Category: "product_version",
									Name:     "1.2.3-150500.1.1",
									Product: &product{
										Name:      "openssl-1.2.3-150500.1.1.x86_64",
										ProductID: "CSAFPID-0001",
										PIHelper: &piHelper{
											PURL: "pkg:rpm/suse/openssl@1.2.3-150500.1.1?arch=x86_64",
										},
									},
								},
							},
						},
					},
				},
			},
		},
		Vulnerabilities: []vulnerability{
			{
				CVE: "CVE-2024-0001",
				Notes: []note{
					{Category: "description", Text: "A test vulnerability", Title: "CVE-2024-0001"},
				},
				Scores: []score{
					{
						Products: []string{"CSAFPID-0001"},
						CVSS3: &cvssV3{
							Version:      "3.1",
							VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
							BaseScore:    7.5,
							BaseSeverity: "HIGH",
						},
					},
				},
				ProductStatus: productStatus{
					KnownAffected: []string{"CSAFPID-0001"},
				},
				Remediations: []remediation{
					{
						Category:   "vendor_fix",
						Details:    "Update to version 1.2.4",
						ProductIDs: []string{"CSAFPID-0001"},
						URL:        "https://www.suse.com/security/cve/CVE-2024-0001",
					},
				},
				Threats: []threat{
					{
						Category: "impact",
						Details:  "Important",
					},
				},
			},
		},
	}

	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// Verify it's valid JSON by unmarshalling into a generic map.
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("produced invalid JSON: %v", err)
	}

	// Verify top-level document fields.
	docMap, ok := raw["document"].(map[string]interface{})
	if !ok {
		t.Fatal("missing 'document' key")
	}
	if got := docMap["category"]; got != "csaf_security_advisory" {
		t.Errorf("category = %v, want csaf_security_advisory", got)
	}
	if got := docMap["csaf_version"]; got != "2.0" {
		t.Errorf("csaf_version = %v, want 2.0", got)
	}

	// Verify product_tree branches exist.
	pt, ok := raw["product_tree"].(map[string]interface{})
	if !ok {
		t.Fatal("missing 'product_tree' key")
	}
	branches, ok := pt["branches"].([]interface{})
	if !ok || len(branches) == 0 {
		t.Fatal("product_tree.branches is empty or missing")
	}

	// Verify vulnerability fields.
	vulns, ok := raw["vulnerabilities"].([]interface{})
	if !ok || len(vulns) == 0 {
		t.Fatal("missing 'vulnerabilities'")
	}
	vuln := vulns[0].(map[string]interface{})
	if got := vuln["cve"]; got != "CVE-2024-0001" {
		t.Errorf("cve = %v, want CVE-2024-0001", got)
	}

	// Verify scores with baseScore.
	scores, ok := vuln["scores"].([]interface{})
	if !ok || len(scores) == 0 {
		t.Fatal("missing scores")
	}
	scoreMap := scores[0].(map[string]interface{})
	cvss, ok := scoreMap["cvss_v3"].(map[string]interface{})
	if !ok {
		t.Fatal("missing cvss_v3 in score")
	}
	if got := cvss["baseScore"]; got != 7.5 {
		t.Errorf("baseScore = %v, want 7.5", got)
	}

	// Verify remediations with vendor_fix.
	rems, ok := vuln["remediations"].([]interface{})
	if !ok || len(rems) == 0 {
		t.Fatal("missing remediations")
	}
	rem := rems[0].(map[string]interface{})
	if got := rem["category"]; got != "vendor_fix" {
		t.Errorf("remediation category = %v, want vendor_fix", got)
	}
}
