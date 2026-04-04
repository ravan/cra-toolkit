package csaf

// csafDocument is the top-level CSAF 2.0 security advisory document.
type csafDocument struct {
	Document        documentMeta    `json:"document"`
	ProductTree     productTree     `json:"product_tree"`
	Vulnerabilities []vulnerability `json:"vulnerabilities"`
}

// documentMeta holds the /document section of a CSAF advisory.
type documentMeta struct {
	Category          string             `json:"category"`
	CSAFVersion       string             `json:"csaf_version"`
	Title             string             `json:"title"`
	Publisher         publisher          `json:"publisher"`
	Tracking          tracking           `json:"tracking"`
	Notes             []note             `json:"notes,omitempty"`
	References        []reference        `json:"references,omitempty"`
	AggregateSeverity *aggregateSeverity `json:"aggregate_severity,omitempty"`
}

// publisher identifies the issuing authority.
type publisher struct {
	Category  string `json:"category"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// tracking holds document lifecycle metadata.
type tracking struct {
	ID                 string     `json:"id"`
	Status             string     `json:"status"`
	Version            string     `json:"version"`
	InitialReleaseDate string     `json:"initial_release_date"`
	CurrentReleaseDate string     `json:"current_release_date"`
	RevisionHistory    []revision `json:"revision_history"`
	Generator          *generator `json:"generator,omitempty"`
}

// revision is a single entry in the revision history.
type revision struct {
	Date    string `json:"date"`
	Number  string `json:"number"`
	Summary string `json:"summary"`
}

// generator describes the tool that produced the advisory.
type generator struct {
	Date   string          `json:"date"`
	Engine generatorEngine `json:"engine"`
}

// generatorEngine identifies the generating software.
type generatorEngine struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// aggregateSeverity is the overall severity label for the advisory.
type aggregateSeverity struct {
	Text string `json:"text"`
}

// productTree contains the hierarchical product definitions.
type productTree struct {
	Branches []branch `json:"branches"`
}

// branch is a node in the product tree (vendor → product_name → product_version).
type branch struct {
	Category string   `json:"category"`
	Name     string   `json:"name"`
	Branches []branch `json:"branches,omitempty"`
	Product  *product `json:"product,omitempty"`
}

// product identifies a specific product version.
type product struct {
	Name      string    `json:"name"`
	ProductID string    `json:"product_id"`
	PIHelper  *piHelper `json:"product_identification_helper,omitempty"`
}

// piHelper provides machine-readable product identification.
type piHelper struct {
	PURL   string   `json:"purl,omitempty"`
	Hashes []piHash `json:"hashes,omitempty"`
}

// piHash is a cryptographic hash for product identification.
type piHash struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// vulnerability describes a single CVE and its impact/remediation.
type vulnerability struct {
	CVE           string        `json:"cve"`
	Notes         []note        `json:"notes,omitempty"`
	Scores        []score       `json:"scores,omitempty"`
	ProductStatus productStatus `json:"product_status"`
	Remediations  []remediation `json:"remediations,omitempty"`
	Threats       []threat      `json:"threats,omitempty"`
	Flags         []flag        `json:"flags,omitempty"`
	CWE           *cwe          `json:"cwe,omitempty"`
}

// productStatus groups product IDs by their vulnerability status.
type productStatus struct {
	KnownNotAffected   []string `json:"known_not_affected,omitempty"`
	Fixed              []string `json:"fixed,omitempty"`
	KnownAffected      []string `json:"known_affected,omitempty"`
	UnderInvestigation []string `json:"under_investigation,omitempty"`
}

// score pairs a CVSS assessment with the affected products.
type score struct {
	Products []string `json:"products"`
	CVSS3    *cvssV3  `json:"cvss_v3,omitempty"`
}

// cvssV3 holds CVSS v3.x scoring data. Field names use camelCase per the
// CVSS JSON schema (not the CSAF envelope).
type cvssV3 struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

// remediation describes how to fix or mitigate a vulnerability.
type remediation struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	ProductIDs []string `json:"product_ids"`
	URL        string   `json:"url,omitempty"`
}

// threat describes the impact or exploit status of a vulnerability.
type threat struct {
	Category string `json:"category"`
	Details  string `json:"details"`
}

// flag provides additional status labels for products within a vulnerability.
type flag struct {
	Label      string   `json:"label"`
	ProductIDs []string `json:"product_ids"`
}

// cwe identifies the weakness type.
type cwe struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// note is a textual annotation (used in both document and vulnerability).
type note struct {
	Category string `json:"category"`
	Text     string `json:"text"`
	Title    string `json:"title,omitempty"`
}

// reference is a link to external information.
type reference struct {
	Category string `json:"category,omitempty"`
	Summary  string `json:"summary"`
	URL      string `json:"url"`
}
