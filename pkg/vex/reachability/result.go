// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package reachability

import "github.com/ravan/suse-cra-toolkit/pkg/formats"

// Result holds the outcome of a reachability analysis.
type Result struct {
	Reachable  bool               // whether the vulnerable code is reachable
	Confidence formats.Confidence // confidence level of the determination
	Evidence   string             // human-readable evidence description
	Symbols    []string           // symbols found to be reachable (if any)
	Paths      []formats.CallPath // call paths from entry points to vulnerable symbols
}

// CallPath is an alias for formats.CallPath for backward compatibility.
type CallPath = formats.CallPath

// CallNode is an alias for formats.CallNode for backward compatibility.
type CallNode = formats.CallNode
