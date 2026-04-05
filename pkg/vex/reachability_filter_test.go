package vex_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
	"github.com/ravan/suse-cra-toolkit/pkg/vex"
	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability"
)

// stubAnalyzer is a test double that returns a preconfigured result.
type stubAnalyzer struct {
	lang   string
	result reachability.Result
	err    error
}

func (s *stubAnalyzer) Language() string { return s.lang }

func (s *stubAnalyzer) Analyze(_ context.Context, _ string, _ *formats.Finding) (reachability.Result, error) {
	return s.result, s.err
}

func TestReachabilityFilter_Name(t *testing.T) {
	f := vex.NewReachabilityFilter("/tmp", nil)
	if name := f.Name(); name != "reachability" {
		t.Fatalf("expected name 'reachability', got %q", name)
	}
}

//nolint:gocognit // table-driven test with thorough assertions
func TestReachabilityFilter_Resolution(t *testing.T) {
	tests := []struct {
		name           string
		analyzerLang   string
		analyzerResult reachability.Result
		analyzerMap    string // key in analyzer map
		findingLang    string
		findingCVE     string
		expectedStatus formats.VEXStatus
		expectedConfid formats.Confidence
		expectedJustif formats.Justification
		checkJustif    bool
	}{
		{
			name:         "reachable go code",
			analyzerLang: "go",
			analyzerResult: reachability.Result{
				Reachable: true, Confidence: formats.ConfidenceHigh,
				Evidence: "function ParseAcceptLanguage is called",
				Symbols:  []string{"ParseAcceptLanguage"},
			},
			analyzerMap:    "go",
			findingLang:    "go",
			findingCVE:     "CVE-2022-32149",
			expectedStatus: formats.StatusAffected,
			expectedConfid: formats.ConfidenceHigh,
		},
		{
			name:         "not reachable go code",
			analyzerLang: "go",
			analyzerResult: reachability.Result{
				Reachable: false, Confidence: formats.ConfidenceHigh,
				Evidence: "vulnerable function not called",
			},
			analyzerMap:    "go",
			findingLang:    "go",
			findingCVE:     "CVE-2022-32149",
			expectedStatus: formats.StatusNotAffected,
			expectedConfid: formats.ConfidenceHigh,
			expectedJustif: formats.JustificationVulnerableCodeNotInExecutePath,
			checkJustif:    true,
		},
		{
			name:         "generic fallback for python",
			analyzerLang: "generic",
			analyzerResult: reachability.Result{
				Reachable: true, Confidence: formats.ConfidenceMedium,
				Evidence: "import found via grep",
			},
			analyzerMap:    "generic",
			findingLang:    "python",
			findingCVE:     "CVE-2020-1747",
			expectedStatus: formats.StatusAffected,
			expectedConfid: formats.ConfidenceMedium,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyzer := &stubAnalyzer{lang: tt.analyzerLang, result: tt.analyzerResult}
			f := vex.NewReachabilityFilter("/tmp/source", map[string]reachability.Analyzer{
				tt.analyzerMap: analyzer,
			})

			finding := formats.Finding{
				CVE:          tt.findingCVE,
				AffectedPURL: "pkg:golang/golang.org/x/text@v0.3.7",
				AffectedName: "golang.org/x/text",
				Language:     tt.findingLang,
			}

			result, resolved := f.Evaluate(&finding, nil)
			if !resolved {
				t.Fatal("expected filter to resolve")
			}
			if result.Status != tt.expectedStatus {
				t.Errorf("expected status %v, got %v", tt.expectedStatus, result.Status)
			}
			if result.Confidence != tt.expectedConfid {
				t.Errorf("expected confidence %v, got %v", tt.expectedConfid, result.Confidence)
			}
			if tt.checkJustif && result.Justification != tt.expectedJustif {
				t.Errorf("expected justification %v, got %v", tt.expectedJustif, result.Justification)
			}
			if result.ResolvedBy != "reachability_analysis" {
				t.Errorf("expected ResolvedBy='reachability_analysis', got %q", result.ResolvedBy)
			}
		})
	}
}

func TestReachabilityFilter_NoAnalyzer(t *testing.T) {
	f := vex.NewReachabilityFilter("/tmp/source", map[string]reachability.Analyzer{})

	finding := formats.Finding{
		CVE:      "CVE-2020-1747",
		Language: "python",
	}

	_, resolved := f.Evaluate(&finding, nil)
	if resolved {
		t.Error("expected filter to NOT resolve when no analyzer available")
	}
}

func TestReachabilityFilter_AnalyzerError(t *testing.T) {
	analyzer := &stubAnalyzer{
		lang: "go",
		err:  errors.New("tool not found"),
	}

	f := vex.NewReachabilityFilter("/tmp/source", map[string]reachability.Analyzer{
		"go": analyzer,
	})

	finding := formats.Finding{
		CVE:      "CVE-2022-32149",
		Language: "go",
	}

	_, resolved := f.Evaluate(&finding, nil)
	if resolved {
		t.Error("expected filter to NOT resolve when analyzer returns error")
	}
}

func TestReachabilityFilter_CallPathEvidence(t *testing.T) {
	t.Run("paths present", func(t *testing.T) {
		analyzer := &stubAnalyzer{
			lang: "go",
			result: reachability.Result{
				Reachable:  true,
				Confidence: formats.ConfidenceHigh,
				Evidence:   "vulnerable symbol is called",
				Paths: []reachability.CallPath{
					{
						Nodes: []reachability.CallNode{
							{Symbol: "main.handler", File: "cmd/main.go", Line: 42},
							{Symbol: "vuln.Parse", File: "vendor/vuln/parse.go", Line: 10},
						},
					},
				},
			},
		}

		f := vex.NewReachabilityFilter("/tmp/source", map[string]reachability.Analyzer{
			"go": analyzer,
		})

		finding := formats.Finding{
			CVE:          "CVE-2022-32149",
			AffectedPURL: "pkg:golang/golang.org/x/text@v0.3.7",
			Language:     "go",
		}

		result, resolved := f.Evaluate(&finding, nil)
		if !resolved {
			t.Fatal("expected filter to resolve")
		}
		if !strings.Contains(result.Evidence, "Call paths:") {
			t.Errorf("expected evidence to contain 'Call paths:', got: %q", result.Evidence)
		}
		wantPath := "main.handler (cmd/main.go:42) -> vuln.Parse (vendor/vuln/parse.go:10)"
		if !strings.Contains(result.Evidence, wantPath) {
			t.Errorf("expected evidence to contain path %q, got: %q", wantPath, result.Evidence)
		}
	})

	t.Run("paths empty", func(t *testing.T) {
		analyzer := &stubAnalyzer{
			lang: "go",
			result: reachability.Result{
				Reachable:  true,
				Confidence: formats.ConfidenceMedium,
				Evidence:   "symbol found via grep",
				Paths:      nil,
			},
		}

		f := vex.NewReachabilityFilter("/tmp/source", map[string]reachability.Analyzer{
			"go": analyzer,
		})

		finding := formats.Finding{
			CVE:          "CVE-2022-32149",
			AffectedPURL: "pkg:golang/golang.org/x/text@v0.3.7",
			Language:     "go",
		}

		result, resolved := f.Evaluate(&finding, nil)
		if !resolved {
			t.Fatal("expected filter to resolve")
		}
		if strings.Contains(result.Evidence, "Call paths:") {
			t.Errorf("expected no 'Call paths:' line when Paths is empty, got: %q", result.Evidence)
		}
	})
}
