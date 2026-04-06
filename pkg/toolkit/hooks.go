// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package toolkit

import (
	"context"
	"fmt"
)

// HookPhase determines when a hook fires relative to a Run() function.
type HookPhase int

const (
	// Pre hooks fire before the Run() function executes.
	Pre HookPhase = iota
	// Post hooks fire after the Run() function executes.
	Post
)

// HookFunc receives the package name ("vex", "report", etc.),
// the options struct (as any), and for Post hooks, the error result from Run().
type HookFunc func(ctx context.Context, pkg string, opts any, err error) error

// Hook runs before or after a package's Run() function.
type Hook struct {
	Phase HookPhase
	Fn    HookFunc
}

// ExecuteWithHooks wraps a function call with pre and post hooks.
// Pre hooks fire in order before fn. If any pre hook returns an error, fn is not called.
// Post hooks fire in order after fn, receiving fn's error. If fn errored and all post
// hooks return nil, the original fn error is returned.
func ExecuteWithHooks(ctx context.Context, pkg string, hooks []Hook, opts any, fn func() error) error {
	for _, h := range hooks {
		if h.Phase == Pre {
			if err := h.Fn(ctx, pkg, opts, nil); err != nil {
				return fmt.Errorf("%s pre-hook: %w", pkg, err)
			}
		}
	}

	fnErr := fn()

	for _, h := range hooks {
		if h.Phase == Post {
			if err := h.Fn(ctx, pkg, opts, fnErr); err != nil {
				return fmt.Errorf("%s post-hook: %w", pkg, err)
			}
		}
	}

	return fnErr
}
