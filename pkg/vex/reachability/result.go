package reachability

import "github.com/ravan/suse-cra-toolkit/pkg/formats"

// Result holds the outcome of a reachability analysis.
type Result struct {
	Reachable  bool               // whether the vulnerable code is reachable
	Confidence formats.Confidence // confidence level of the determination
	Evidence   string             // human-readable evidence description
	Symbols    []string           // symbols found to be reachable (if any)
}
