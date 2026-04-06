// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package cli

import "github.com/ravan/cra-toolkit/pkg/toolkit"

// buildHooks converts RunConfig pre/post hooks into a toolkit.Hook slice
// for a specific package.
func buildHooks(cfg RunConfig, pkg string) []toolkit.Hook {
	var hooks []toolkit.Hook
	for _, fn := range cfg.PreHooks[pkg] {
		hooks = append(hooks, toolkit.Hook{Phase: toolkit.Pre, Fn: fn})
	}
	for _, fn := range cfg.PostHooks[pkg] {
		hooks = append(hooks, toolkit.Hook{Phase: toolkit.Post, Fn: fn})
	}
	return hooks
}
