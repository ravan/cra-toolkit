package vex

import (
	"fmt"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
)

// upstreamFilter resolves findings using vendor-supplied VEX statements.
type upstreamFilter struct {
	// index maps "CVE|PURL" to the corresponding VEX statement.
	index map[string]formats.VEXStatement
}

// NewUpstreamFilter returns a Filter that resolves findings against known upstream VEX statements.
func NewUpstreamFilter(statements []formats.VEXStatement) Filter {
	idx := make(map[string]formats.VEXStatement, len(statements))
	for _, s := range statements {
		key := fmt.Sprintf("%s|%s", s.CVE, s.ProductPURL)
		idx[key] = s
	}
	return &upstreamFilter{index: idx}
}

func (f *upstreamFilter) Name() string { return "upstream" }

func (f *upstreamFilter) Evaluate(finding *formats.Finding, _ []formats.Component) (Result, bool) {
	key := fmt.Sprintf("%s|%s", finding.CVE, finding.AffectedPURL)
	stmt, ok := f.index[key]
	if !ok {
		return Result{}, false
	}
	return Result{
		CVE:           finding.CVE,
		ComponentPURL: finding.AffectedPURL,
		Status:        stmt.Status,
		Justification: stmt.Justification,
		Confidence:    formats.ConfidenceHigh,
		ResolvedBy:    "upstream",
		Evidence:      fmt.Sprintf("Vendor VEX statement: %s", stmt.StatusNotes),
	}, true
}
