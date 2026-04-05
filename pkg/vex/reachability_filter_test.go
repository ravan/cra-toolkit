// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package vex_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/vex"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability"
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

func assertEntryFilesContain(t *testing.T, entryFiles []string, want ...string) {
	t.Helper()
	entrySet := map[string]bool{}
	for _, ef := range entryFiles {
		entrySet[ef] = true
	}
	for _, w := range want {
		if !entrySet[w] {
			t.Errorf("EntryFiles = %v, missing %q", entryFiles, w)
		}
	}
}

func TestReachabilityFilter_StructuredFields_TreeSitter(t *testing.T) {
	analyzer := &stubAnalyzer{
		lang: "python",
		result: reachability.Result{
			Reachable:  true,
			Confidence: formats.ConfidenceHigh,
			Evidence:   "vulnerable symbol is called",
			Symbols:    []string{"yaml.load", "yaml.unsafe_load"},
			Paths: []reachability.CallPath{
				{
					Nodes: []reachability.CallNode{
						{Symbol: "app.main", File: "src/app.py", Line: 10},
						{Symbol: "app.process", File: "src/app.py", Line: 25},
						{Symbol: "yaml.load", File: "vendor/yaml/__init__.py", Line: 100},
					},
				},
				{
					Nodes: []reachability.CallNode{
						{Symbol: "cli.run", File: "src/cli.py", Line: 5},
						{Symbol: "yaml.unsafe_load", File: "vendor/yaml/__init__.py", Line: 200},
					},
				},
			},
		},
	}

	f := vex.NewReachabilityFilter("/tmp/source", map[string]reachability.Analyzer{
		"python": analyzer,
	})

	finding := formats.Finding{
		CVE:          "CVE-2020-1747",
		AffectedPURL: "pkg:pypi/pyyaml@5.3",
		AffectedName: "PyYAML",
		Language:     "python",
	}

	result, resolved := f.Evaluate(&finding, nil)
	if !resolved {
		t.Fatal("expected filter to resolve")
	}

	if len(result.CallPaths) != 2 {
		t.Fatalf("CallPaths count = %d, want 2", len(result.CallPaths))
	}
	if result.CallPaths[0].Depth() != 3 {
		t.Errorf("CallPaths[0].Depth() = %d, want 3", result.CallPaths[0].Depth())
	}
	if len(result.Symbols) != 2 {
		t.Errorf("Symbols count = %d, want 2", len(result.Symbols))
	}
	if result.MaxCallDepth != 3 {
		t.Errorf("MaxCallDepth = %d, want 3", result.MaxCallDepth)
	}
	if len(result.EntryFiles) != 2 {
		t.Errorf("EntryFiles count = %d, want 2", len(result.EntryFiles))
	}
	assertEntryFilesContain(t, result.EntryFiles, "src/app.py", "src/cli.py")
	if result.AnalysisMethod != "tree_sitter" {
		t.Errorf("AnalysisMethod = %q, want tree_sitter", result.AnalysisMethod)
	}
}

func TestReachabilityFilter_StructuredFields_GenericAnalyzer(t *testing.T) {
	analyzer := &stubAnalyzer{
		lang: "generic",
		result: reachability.Result{
			Reachable:  true,
			Confidence: formats.ConfidenceMedium,
			Evidence:   "import found via grep",
			Symbols:    []string{"yaml.load"},
			Paths:      nil,
		},
	}

	f := vex.NewReachabilityFilter("/tmp/source", map[string]reachability.Analyzer{
		"generic": analyzer,
	})

	finding := formats.Finding{
		CVE:          "CVE-2020-1747",
		AffectedPURL: "pkg:pypi/pyyaml@5.3",
		Language:     "unknown-lang",
	}

	result, resolved := f.Evaluate(&finding, nil)
	if !resolved {
		t.Fatal("expected filter to resolve")
	}

	if result.AnalysisMethod != "pattern_match" {
		t.Errorf("AnalysisMethod = %q, want pattern_match", result.AnalysisMethod)
	}
	if result.CallPaths != nil {
		t.Errorf("CallPaths = %v, want nil for generic analyzer", result.CallPaths)
	}
	if result.MaxCallDepth != 0 {
		t.Errorf("MaxCallDepth = %d, want 0", result.MaxCallDepth)
	}
	if len(result.Symbols) != 1 || result.Symbols[0] != "yaml.load" {
		t.Errorf("Symbols = %v, want [yaml.load]", result.Symbols)
	}
}

func TestReachabilityFilter_StructuredFields_NotReachable(t *testing.T) {
	analyzer := &stubAnalyzer{
		lang: "go",
		result: reachability.Result{
			Reachable:  false,
			Confidence: formats.ConfidenceHigh,
			Evidence:   "vulnerable function not called",
			Symbols:    []string{"text.Parse"},
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

	if result.AnalysisMethod != "govulncheck" {
		t.Errorf("AnalysisMethod = %q, want govulncheck", result.AnalysisMethod)
	}
	if len(result.Symbols) != 1 || result.Symbols[0] != "text.Parse" {
		t.Errorf("Symbols = %v, want [text.Parse]", result.Symbols)
	}
	if result.CallPaths != nil {
		t.Errorf("CallPaths should be nil for not-reachable, got %v", result.CallPaths)
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
