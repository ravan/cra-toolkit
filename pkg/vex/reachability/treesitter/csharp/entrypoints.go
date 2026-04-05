package csharp

import (
	"strings"

	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter"
)

// httpEntryPointAttributes are ASP.NET Core attributes that mark controller actions as entry points.
var httpEntryPointAttributes = []string{
	"@HttpGet",
	"@HttpPost",
	"@HttpPut",
	"@HttpDelete",
	"@HttpPatch",
	"@Route",
}

// isHTTPAttribute returns true if the attribute text matches any known HTTP entry point attribute.
func isHTTPAttribute(attr string) bool {
	// Normalize: strip argument list if present, e.g. "@HttpPost("path")" → "@HttpPost"
	name := attr
	if idx := strings.IndexByte(attr, '('); idx > 0 {
		name = attr[:idx]
	}
	name = strings.TrimSpace(name)

	for _, pattern := range httpEntryPointAttributes {
		if name == pattern {
			return true
		}
	}
	return false
}

// isMainMethod returns true if the symbol is the C# application entry point.
// Requires: method named "Main" AND declared with "static" modifier.
// Both "static void Main(string[] args)" and "static async Task Main(string[] args)" qualify.
func (e *Extractor) isMainMethod(sym *treesitter.Symbol) bool {
	return sym.Name == "Main" && e.staticMethods[sym.ID]
}

// isExecuteAsync returns true if the symbol is an IHostedService/BackgroundService entry point.
// ExecuteAsync is the standard method overridden in BackgroundService subclasses.
func isExecuteAsync(sym *treesitter.Symbol) bool {
	return sym.Name == "ExecuteAsync"
}

// FindEntryPoints returns SymbolIDs of methods that are application entry points.
//
// Detection strategies:
//  1. static void Main / static async Task Main — standard C# application entry point
//  2. ASP.NET [HttpGet] / [HttpPost] / [HttpPut] / [HttpDelete] / [HttpPatch] — controller actions
//  3. [Route] — route handlers
//  4. BackgroundService.ExecuteAsync / IHostedService.ExecuteAsync — background workers
//
//nolint:gocognit // entry point detection checks multiple strategies
func (e *Extractor) FindEntryPoints(symbols []*treesitter.Symbol, _ string) []treesitter.SymbolID {
	var eps []treesitter.SymbolID

	for _, sym := range symbols {
		if sym == nil {
			continue
		}
		if sym.Kind != treesitter.SymbolMethod {
			continue
		}

		// 1. Main entry point
		if e.isMainMethod(sym) {
			eps = append(eps, sym.ID)
			continue
		}

		// 2/3. HTTP attribute-based entry points
		attrs, hasAttrs := e.attributes[sym.ID]
		if hasAttrs {
			for _, attr := range attrs {
				if isHTTPAttribute(attr) {
					eps = append(eps, sym.ID)
					break
				}
			}
		}

		// 4. BackgroundService.ExecuteAsync
		if isExecuteAsync(sym) {
			eps = append(eps, sym.ID)
		}
	}

	return eps
}
