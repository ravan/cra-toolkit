// Package csafvex implements parsing and writing of CSAF VEX profile documents.
package csafvex

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
)

// Parser parses CSAF VEX profile JSON documents.
type Parser struct{}

// Writer writes VEX results as CSAF VEX profile JSON documents.
type Writer struct{}

// --- CSAF JSON types ---

type csafDocument struct {
	Document        csafDocumentMeta `json:"document"`
	ProductTree     productTree      `json:"product_tree"`
	Vulnerabilities []vulnerability  `json:"vulnerabilities"`
}

type csafDocumentMeta struct {
	Category    string    `json:"category"`
	CSAFVersion string    `json:"csaf_version"`
	Title       string    `json:"title"`
	Publisher   publisher `json:"publisher"`
	Tracking    tracking  `json:"tracking"`
}

type publisher struct {
	Category  string `json:"category"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type tracking struct {
	ID                 string     `json:"id"`
	Status             string     `json:"status"`
	Version            string     `json:"version"`
	InitialReleaseDate string     `json:"initial_release_date"`
	CurrentReleaseDate string     `json:"current_release_date"`
	RevisionHistory    []revision `json:"revision_history"`
	Generator          *generator `json:"generator,omitempty"`
}

type revision struct {
	Date    string `json:"date"`
	Number  string `json:"number"`
	Summary string `json:"summary"`
}

type generator struct {
	Date   string          `json:"date"`
	Engine generatorEngine `json:"engine"`
}

type generatorEngine struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type productTree struct {
	Branches []branch `json:"branches,omitempty"`
}

type branch struct {
	Category string   `json:"category"`
	Name     string   `json:"name"`
	Branches []branch `json:"branches,omitempty"`
	Product  *product `json:"product,omitempty"`
}

type product struct {
	Name      string    `json:"name"`
	ProductID string    `json:"product_id"`
	PIHelper  *piHelper `json:"product_identification_helper,omitempty"`
}

type piHelper struct {
	PURL string `json:"purl,omitempty"`
	CPE  string `json:"cpe,omitempty"`
}

type vulnerability struct {
	CVE           string        `json:"cve"`
	ProductStatus productStatus `json:"product_status"`
	Flags         []flag        `json:"flags,omitempty"`
}

type productStatus struct {
	KnownNotAffected   []string `json:"known_not_affected,omitempty"`
	Fixed              []string `json:"fixed,omitempty"`
	KnownAffected      []string `json:"known_affected,omitempty"`
	UnderInvestigation []string `json:"under_investigation,omitempty"`
}

type flag struct {
	Label      string   `json:"label"`
	ProductIDs []string `json:"product_ids"`
}

// Parse reads a CSAF VEX JSON document and returns VEX statements.
// It maps product IDs to PURLs via the product_tree where available.
//
//nolint:gocognit // CSAF parsing requires nested traversal
func (p Parser) Parse(r io.Reader) ([]formats.VEXStatement, error) {
	var doc csafDocument
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("csafvex: decode JSON: %w", err)
	}

	// Build a map from product ID -> PURL (or product ID if no PURL available)
	productPURLs := buildProductPURLMap(doc.ProductTree.Branches)

	// Build flag lookup: product_id -> justification label
	var stmts []formats.VEXStatement
	for i := range doc.Vulnerabilities {
		vuln := &doc.Vulnerabilities[i]
		// Build flag map: product_id -> flag label
		flagMap := map[string]string{}
		for _, f := range vuln.Flags {
			for _, pid := range f.ProductIDs {
				flagMap[pid] = f.Label
			}
		}

		// known_not_affected
		for _, pid := range vuln.ProductStatus.KnownNotAffected {
			stmts = append(stmts, formats.VEXStatement{
				CVE:           vuln.CVE,
				ProductPURL:   productPURLs[pid],
				Status:        formats.StatusNotAffected,
				Justification: mapFlagLabel(flagMap[pid]),
			})
		}

		// fixed
		for _, pid := range vuln.ProductStatus.Fixed {
			stmts = append(stmts, formats.VEXStatement{
				CVE:         vuln.CVE,
				ProductPURL: productPURLs[pid],
				Status:      formats.StatusFixed,
			})
		}

		// known_affected
		for _, pid := range vuln.ProductStatus.KnownAffected {
			stmts = append(stmts, formats.VEXStatement{
				CVE:         vuln.CVE,
				ProductPURL: productPURLs[pid],
				Status:      formats.StatusAffected,
			})
		}

		// under_investigation
		for _, pid := range vuln.ProductStatus.UnderInvestigation {
			stmts = append(stmts, formats.VEXStatement{
				CVE:         vuln.CVE,
				ProductPURL: productPURLs[pid],
				Status:      formats.StatusUnderInvestigation,
			})
		}
	}

	return stmts, nil
}

// Write serializes VEX results to CSAF VEX profile JSON format.
//
//nolint:gocyclo // CSAF document construction has many required fields
func (w Writer) Write(out io.Writer, results []formats.VEXResult) error {
	now := time.Now().UTC().Format(time.RFC3339)

	// Build product tree branches and vulnerability product_status
	branches := make([]branch, 0, len(results))
	vulnMap := map[string]*vulnerability{}

	for i := range results {
		r := &results[i]
		productID := purlToProductID(r.ComponentPURL)

		// Add product tree branch
		branches = append(branches, branch{
			Category: "product_version",
			Name:     productID,
			Product: &product{
				Name:      productID,
				ProductID: productID,
				PIHelper: &piHelper{
					PURL: r.ComponentPURL,
				},
			},
		})

		// Accumulate vulnerability
		if _, exists := vulnMap[r.CVE]; !exists {
			vulnMap[r.CVE] = &vulnerability{
				CVE: r.CVE,
			}
		}
		v := vulnMap[r.CVE]

		switch r.Status {
		case formats.StatusNotAffected:
			v.ProductStatus.KnownNotAffected = append(v.ProductStatus.KnownNotAffected, productID)
			if r.Justification != "" {
				v.Flags = append(v.Flags, flag{
					Label:      justificationToCSAF(r.Justification),
					ProductIDs: []string{productID},
				})
			}
		case formats.StatusFixed:
			v.ProductStatus.Fixed = append(v.ProductStatus.Fixed, productID)
		case formats.StatusAffected:
			v.ProductStatus.KnownAffected = append(v.ProductStatus.KnownAffected, productID)
		case formats.StatusUnderInvestigation:
			v.ProductStatus.UnderInvestigation = append(v.ProductStatus.UnderInvestigation, productID)
		}
	}

	// Collect vulnerabilities in deterministic order
	vulns := make([]vulnerability, 0, len(vulnMap))
	seen := map[string]bool{}
	for i := range results {
		cve := results[i].CVE
		if !seen[cve] {
			seen[cve] = true
			vulns = append(vulns, *vulnMap[cve])
		}
	}

	doc := csafDocument{
		Document: csafDocumentMeta{
			Category:    "csaf_vex",
			CSAFVersion: "2.0",
			Title:       "SUSE CRA Toolkit VEX Document",
			Publisher: publisher{
				Category:  "vendor",
				Name:      "SUSE CRA Toolkit",
				Namespace: "https://suse.com",
			},
			Tracking: tracking{
				ID:                 "suse-cra-vex-" + time.Now().UTC().Format("20060102T150405Z"),
				Status:             "final",
				Version:            "1",
				InitialReleaseDate: now,
				CurrentReleaseDate: now,
				RevisionHistory: []revision{
					{
						Date:    now,
						Number:  "1",
						Summary: "Initial version",
					},
				},
			},
		},
		ProductTree: productTree{
			Branches: branches,
		},
		Vulnerabilities: vulns,
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("csafvex: encode JSON: %w", err)
	}
	return nil
}

// buildProductPURLMap walks the product tree branch tree and builds a map
// from product_id to PURL (or product_id if no PURL is defined).
func buildProductPURLMap(branches []branch) map[string]string {
	m := map[string]string{}
	walkBranches(branches, m)
	return m
}

func walkBranches(branches []branch, m map[string]string) {
	for _, b := range branches {
		if b.Product != nil {
			pid := b.Product.ProductID
			if b.Product.PIHelper != nil && b.Product.PIHelper.PURL != "" {
				m[pid] = b.Product.PIHelper.PURL
			} else {
				// Fall back to using product_id as the identifier
				m[pid] = pid
			}
		}
		walkBranches(b.Branches, m)
	}
}

// mapFlagLabel converts a CSAF flag label to an internal Justification.
func mapFlagLabel(label string) formats.Justification {
	switch label {
	case "component_not_present":
		return formats.JustificationComponentNotPresent
	case "vulnerable_code_not_present":
		return formats.JustificationVulnerableCodeNotPresent
	case "vulnerable_code_not_in_execute_path":
		return formats.JustificationVulnerableCodeNotInExecutePath
	case "inline_mitigations_already_exist":
		return formats.JustificationInlineMitigationsAlreadyExist
	default:
		return formats.Justification(label)
	}
}

// justificationToCSAF converts an internal Justification to a CSAF flag label.
func justificationToCSAF(j formats.Justification) string {
	return string(j)
}

// purlToProductID converts a PURL to a sanitized product ID for use in CSAF.
func purlToProductID(purl string) string {
	return purl
}
