// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package python

import (
	"strings"

	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter"
)

// entryPointDecorators is the set of decorator prefixes that mark entry points.
// These cover Flask, FastAPI, Starlette, Celery, and Click patterns.
var entryPointDecorators = []string{
	// Flask / Starlette / Quart
	"@app.route", "@bp.route", "@blueprint.route",
	// FastAPI / Flask HTTP method shortcuts
	"@app.get", "@app.post", "@app.put", "@app.delete", "@app.patch", "@app.head", "@app.options",
	"@router.get", "@router.post", "@router.put", "@router.delete", "@router.patch",
	"@router.head", "@router.options", "@router.on_event",
	// Celery
	"@app.task", "@shared_task", "@celery.task",
	// Click CLI
	"@click.command", "@click.group",
	// FastAPI/APIRouter events
	"@app.on_event", "@app.middleware",
}

// isEntryPointDecorator returns true if the given decorator string matches any
// known entry point pattern.
func isEntryPointDecorator(dec string) bool {
	// Normalize: strip the decorator text to just the first "word" (before any '(')
	trimmed := strings.TrimSpace(dec)
	// Remove leading '@' if present in the text representation
	if !strings.HasPrefix(trimmed, "@") {
		trimmed = "@" + trimmed
	}
	// Get just the decorator name without arguments
	name := trimmed
	if idx := strings.IndexByte(trimmed, '('); idx >= 0 {
		name = trimmed[:idx]
	}

	for _, pattern := range entryPointDecorators {
		if name == pattern {
			return true
		}
	}
	return false
}

// FindEntryPoints returns SymbolIDs of functions/methods that are entry points.
//
// An entry point is identified by:
//  1. A recognized decorator (Flask route, FastAPI route, Celery task, Click command)
//  2. A function named "main" (common Python convention)
//
// The extractor's decorator map (populated during ExtractSymbols) is used for
// decorator-based detection.
//
//nolint:gocognit,gocyclo // entry point detection checks multiple decorator patterns and name conventions
func (e *Extractor) FindEntryPoints(symbols []*treesitter.Symbol, _ string) []treesitter.SymbolID {
	var eps []treesitter.SymbolID

	for _, sym := range symbols {
		if sym == nil {
			continue
		}
		if sym.Kind != treesitter.SymbolFunction && sym.Kind != treesitter.SymbolMethod {
			continue
		}

		// Check decorator-based entry points
		decs, hasDecs := e.decorators[sym.ID]
		if hasDecs {
			for _, dec := range decs {
				if isEntryPointDecorator(dec) {
					eps = append(eps, sym.ID)
					break
				}
			}
		}

		// Also treat functions named "main" as potential entry points
		if sym.Name == "main" {
			eps = append(eps, sym.ID)
		}
	}

	return eps
}
