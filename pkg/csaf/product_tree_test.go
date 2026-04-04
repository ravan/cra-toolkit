package csaf

import (
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
)

func TestBuildProductTree_SingleComponent(t *testing.T) { //nolint:gocognit,gocyclo // test validates hierarchical tree structure
	components := []formats.Component{
		{
			Name:      "golang.org/x/text",
			Version:   "v0.3.7",
			PURL:      "pkg:golang/golang.org/x/text@v0.3.7",
			Type:      "golang",
			Namespace: "golang.org/x",
			Hashes:    map[string]string{"SHA-256": "abc123def456"},
			Supplier:  "golang.org",
		},
	}

	pt := buildProductTree(components, "ACME Corp")

	// 1 top-level branch with category="vendor", name="ACME Corp"
	if len(pt.Branches) != 1 {
		t.Fatalf("expected 1 top-level branch, got %d", len(pt.Branches))
	}
	vendor := pt.Branches[0]
	if vendor.Category != "vendor" {
		t.Errorf("expected vendor category, got %q", vendor.Category)
	}
	if vendor.Name != "ACME Corp" {
		t.Errorf("expected vendor name 'ACME Corp', got %q", vendor.Name)
	}

	// 1 child branch with category="product_name", name="golang.org/x/text"
	if len(vendor.Branches) != 1 {
		t.Fatalf("expected 1 product branch, got %d", len(vendor.Branches))
	}
	prodBranch := vendor.Branches[0]
	if prodBranch.Category != "product_name" {
		t.Errorf("expected product_name category, got %q", prodBranch.Category)
	}
	if prodBranch.Name != "golang.org/x/text" {
		t.Errorf("expected product name 'golang.org/x/text', got %q", prodBranch.Name)
	}

	// 1 leaf branch with category="product_version"
	if len(prodBranch.Branches) != 1 {
		t.Fatalf("expected 1 version branch, got %d", len(prodBranch.Branches))
	}
	verBranch := prodBranch.Branches[0]
	if verBranch.Category != "product_version" {
		t.Errorf("expected product_version category, got %q", verBranch.Category)
	}

	// Verify that ProductID matches the component PURL
	if verBranch.Product == nil {
		t.Fatal("expected product on version branch, got nil")
	}
	if verBranch.Product.ProductID != "pkg:golang/golang.org/x/text@v0.3.7" {
		t.Errorf("expected ProductID to be PURL, got %q", verBranch.Product.ProductID)
	}

	// Verify that PIHelper PURL matches the component PURL
	if verBranch.Product.PIHelper == nil {
		t.Fatal("expected PIHelper on product, got nil")
	}
	if verBranch.Product.PIHelper.PURL != "pkg:golang/golang.org/x/text@v0.3.7" {
		t.Errorf("expected PIHelper PURL to match, got %q", verBranch.Product.PIHelper.PURL)
	}

	// 1 hash with algorithm="SHA-256"
	if len(verBranch.Product.PIHelper.Hashes) != 1 {
		t.Fatalf("expected 1 hash, got %d", len(verBranch.Product.PIHelper.Hashes))
	}
	h := verBranch.Product.PIHelper.Hashes[0]
	if h.Algorithm != "SHA-256" {
		t.Errorf("expected hash algorithm 'SHA-256', got %q", h.Algorithm)
	}
	if h.Value != "abc123def456" {
		t.Errorf("expected hash value 'abc123def456', got %q", h.Value)
	}
}

func TestBuildProductTree_MultipleComponents(t *testing.T) {
	components := []formats.Component{
		{
			Name:    "golang.org/x/text",
			Version: "v0.3.7",
			PURL:    "pkg:golang/golang.org/x/text@v0.3.7",
		},
		{
			Name:    "golang.org/x/net",
			Version: "v0.1.0",
			PURL:    "pkg:golang/golang.org/x/net@v0.1.0",
		},
	}

	pt := buildProductTree(components, "ACME Corp")

	vendor := pt.Branches[0]
	if len(vendor.Branches) != 2 {
		t.Fatalf("expected 2 product branches, got %d", len(vendor.Branches))
	}

	// Verify order matches input
	if vendor.Branches[0].Name != "golang.org/x/text" {
		t.Errorf("expected first product 'golang.org/x/text', got %q", vendor.Branches[0].Name)
	}
	if vendor.Branches[1].Name != "golang.org/x/net" {
		t.Errorf("expected second product 'golang.org/x/net', got %q", vendor.Branches[1].Name)
	}
}

func TestBuildProductTree_NoHashes_OmitsHashesField(t *testing.T) {
	components := []formats.Component{
		{
			Name:    "golang.org/x/text",
			Version: "v0.3.7",
			PURL:    "pkg:golang/golang.org/x/text@v0.3.7",
		},
	}

	pt := buildProductTree(components, "ACME Corp")

	verBranch := pt.Branches[0].Branches[0].Branches[0]
	if verBranch.Product == nil || verBranch.Product.PIHelper == nil {
		t.Fatal("expected product with PIHelper")
	}
	if len(verBranch.Product.PIHelper.Hashes) != 0 {
		t.Errorf("expected empty hashes, got %d", len(verBranch.Product.PIHelper.Hashes))
	}
}
