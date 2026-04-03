// Package generic implements a reachability analyzer using ripgrep for
// language-aware symbol searching.
package generic

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability"
)

// Analyzer uses ripgrep to perform grep-based reachability analysis.
type Analyzer struct {
	language string
}

// New returns a new generic reachability analyzer for the given language.
// If language is empty, it defaults to a broad search.
func New(language string) *Analyzer {
	return &Analyzer{language: language}
}

func (a *Analyzer) Language() string {
	if a.language == "" {
		return "generic"
	}
	return a.language
}

// Analyze searches the source directory for imports and symbol usage of the
// affected component.
func (a *Analyzer) Analyze(ctx context.Context, sourceDir string, finding *formats.Finding) (reachability.Result, error) {
	lang := a.language
	if lang == "" {
		lang = finding.Language
	}

	moduleName := NormalizeModuleName(finding.AffectedName, lang)
	patterns, glob := importPatterns(moduleName, lang)

	// Check if the module is imported.
	imported, err := searchPatterns(ctx, sourceDir, patterns, glob)
	if err != nil {
		return reachability.Result{}, fmt.Errorf("ripgrep import search: %w", err)
	}

	if !imported {
		return reachability.Result{
			Reachable:  false,
			Confidence: formats.ConfidenceMedium,
			Evidence:   fmt.Sprintf("no import of %s found in source (searched for %s)", finding.AffectedName, moduleName),
		}, nil
	}

	// Module is imported. If symbols are known, search for them.
	if len(finding.Symbols) > 0 {
		symbolFound, foundSymbols, err := searchSymbols(ctx, sourceDir, finding.Symbols, glob)
		if err != nil {
			return reachability.Result{}, fmt.Errorf("ripgrep symbol search: %w", err)
		}
		if symbolFound {
			return reachability.Result{
				Reachable:  true,
				Confidence: formats.ConfidenceMedium,
				Evidence:   fmt.Sprintf("import of %s found and symbol(s) %s referenced in source", finding.AffectedName, strings.Join(foundSymbols, ", ")),
				Symbols:    foundSymbols,
			}, nil
		}
		// Imported but symbols not found.
		return reachability.Result{
			Reachable:  false,
			Confidence: formats.ConfidenceMedium,
			Evidence:   fmt.Sprintf("import of %s found but vulnerable symbols %v not referenced in source", finding.AffectedName, finding.Symbols),
		}, nil
	}

	// Imported but no symbol info available; assume reachable.
	return reachability.Result{
		Reachable:  true,
		Confidence: formats.ConfidenceMedium,
		Evidence:   fmt.Sprintf("import of %s found in source (no symbol info to narrow search)", finding.AffectedName),
	}, nil
}

// searchPatterns runs ripgrep with the given patterns and returns true if any match.
func searchPatterns(ctx context.Context, dir string, patterns []string, glob string) (bool, error) {
	for _, pattern := range patterns {
		args := []string{"-q", "-l", "--glob", glob, pattern, dir}
		cmd := exec.CommandContext(ctx, "rg", args...) //nolint:gosec // args are constructed internally
		if err := cmd.Run(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				// Exit code 1 = no match, which is fine.
				if exitErr.ExitCode() == 1 {
					continue
				}
			}
			// rg not found or other error.
			return false, err
		}
		// Match found.
		return true, nil
	}
	return false, nil
}

// searchSymbols searches for any of the given symbols in source files.
func searchSymbols(ctx context.Context, dir string, symbols []string, glob string) (matched bool, foundSymbols []string, err error) {
	found := make([]string, 0, len(symbols))
	for _, sym := range symbols {
		args := []string{"-q", "-l", "--glob", glob, sym, dir}
		cmd := exec.CommandContext(ctx, "rg", args...) //nolint:gosec // args are constructed internally
		if err := cmd.Run(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
				continue
			}
			return false, nil, err
		}
		found = append(found, sym)
	}
	return len(found) > 0, found, nil
}
