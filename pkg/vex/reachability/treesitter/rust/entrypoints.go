// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package rust

import (
	"path/filepath"
	"strings"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)

// FindEntryPoints identifies Rust entry point symbols.
//
// Detection strategies:
//  1. fn main() — standard Rust binary entry point
//  2. Functions in main.rs — all top-level functions in the binary crate root
//  3. Functions named test_* — Rust test functions (convention)
func (e *Extractor) FindEntryPoints(symbols []*treesitter.Symbol, _ string) []treesitter.SymbolID {
	var eps []treesitter.SymbolID

	for _, sym := range symbols {
		if sym == nil {
			continue
		}

		// Only consider functions and methods
		if sym.Kind != treesitter.SymbolFunction && sym.Kind != treesitter.SymbolMethod {
			continue
		}

		// 1. fn main() is always an entry point
		if sym.Name == "main" {
			eps = append(eps, sym.ID)
			continue
		}

		// 2. Functions in main.rs are entry points
		if filepath.Base(sym.File) == "main.rs" {
			eps = append(eps, sym.ID)
			continue
		}

		// 3. test_ prefixed functions are entry points
		if strings.HasPrefix(sym.Name, "test_") {
			eps = append(eps, sym.ID)
			continue
		}
	}

	return eps
}
