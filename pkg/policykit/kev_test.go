package policykit

import (
	"os"
	"strings"
	"testing"
)

func TestParseKEV_RealSnapshot(t *testing.T) {
	f, err := os.Open("../../testdata/policykit/kev-snapshot.json")
	if err != nil {
		t.Fatalf("open snapshot: %v", err)
	}
	defer func() { _ = f.Close() }() //nolint:errcheck // read-only test file

	cat, err := ParseKEV(f)
	if err != nil {
		t.Fatalf("ParseKEV: %v", err)
	}

	if cat.CatalogDate == "" {
		t.Error("CatalogDate should not be empty")
	}

	if !cat.Contains("CVE-2024-3094") {
		t.Error("expected CVE-2024-3094 to be in catalog")
	}

	if cat.Contains("CVE-9999-99999") {
		t.Error("expected CVE-9999-99999 to NOT be in catalog")
	}

	if len(cat.CVEs) == 0 {
		t.Error("CVEs map should not be empty")
	}
}

func TestParseKEV_MalformedJSON(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"invalid json", "{bad json!!!"},
		{"wrong structure", `{"foo": "bar"}`},
		{"null vulnerabilities", `{"dateReleased": "2024-01-01", "vulnerabilities": null}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cat, err := ParseKEV(strings.NewReader(tc.input))
			if err != nil {
				// error is acceptable for malformed input
				return
			}
			// If no error, catalog should be usable (not nil) and not crash
			if cat == nil {
				t.Fatal("expected non-nil catalog even for empty input")
			}
			// Contains should not panic
			_ = cat.Contains("CVE-2024-3094")
		})
	}
}

func TestMatchFindings(t *testing.T) {
	f, err := os.Open("../../testdata/policykit/kev-snapshot.json")
	if err != nil {
		t.Fatalf("open snapshot: %v", err)
	}
	defer func() { _ = f.Close() }() //nolint:errcheck // read-only test file

	cat, err := ParseKEV(f)
	if err != nil {
		t.Fatalf("ParseKEV: %v", err)
	}

	input := []string{"CVE-2024-3094", "CVE-9999-99999", "CVE-0000-0000"}
	matches := cat.MatchFindings(input)

	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %v", len(matches), matches)
	}
	if matches[0] != "CVE-2024-3094" {
		t.Errorf("expected CVE-2024-3094, got %s", matches[0])
	}

	// Empty input should return empty result
	empty := cat.MatchFindings(nil)
	if len(empty) != 0 {
		t.Errorf("expected 0 matches for nil input, got %d", len(empty))
	}
}
