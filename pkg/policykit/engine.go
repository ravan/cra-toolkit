// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package policykit

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/open-policy-agent/opa/v1/rego"
)

// Engine wraps OPA policy evaluation for CRA Rego policies.
type Engine struct {
	modules map[string]string // filename -> rego source
}

// NewEngine creates an Engine with the given policy modules (filename -> rego source).
func NewEngine(modules map[string]string) (*Engine, error) {
	if len(modules) == 0 {
		return nil, fmt.Errorf("policykit: at least one policy module is required")
	}
	copied := make(map[string]string, len(modules))
	for k, v := range modules {
		copied[k] = v
	}
	return &Engine{modules: copied}, nil
}

// AddCustomPolicies adds additional policies to the engine, prefixed with "custom/".
func (e *Engine) AddCustomPolicies(modules map[string]string) error {
	for name, src := range modules {
		e.modules["custom/"+name] = src
	}
	return nil
}

// Evaluate runs all loaded policies against the given input and returns results.
// It returns an error if duplicate rule_ids are detected across packages.
func (e *Engine) Evaluate(ctx context.Context, input map[string]any) ([]PolicyResult, error) { //nolint:gocognit,gocyclo // OPA result unmarshalling requires sequential package iteration
	opts := []func(*rego.Rego){
		rego.Query("data.cra"),
	}
	for name, src := range e.modules {
		opts = append(opts, rego.Module(name, src))
	}

	prepared, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("policykit: prepare eval: %w", err)
	}

	rs, err := prepared.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("policykit: eval: %w", err)
	}

	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, fmt.Errorf("policykit: no results from policy evaluation")
	}

	// The result of querying data.cra is a map keyed by package name suffix.
	// Each value is a map with a "result" key containing the PolicyResult fields.
	packages, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("policykit: unexpected result type %T", rs[0].Expressions[0].Value)
	}

	// Collect package names and sort for deterministic output.
	pkgNames := make([]string, 0, len(packages))
	for name := range packages {
		pkgNames = append(pkgNames, name)
	}
	sort.Strings(pkgNames)

	results := make([]PolicyResult, 0, len(pkgNames))
	seen := make(map[string]string, len(pkgNames)) // rule_id -> package name

	for _, pkgName := range pkgNames {
		pkgVal := packages[pkgName]
		pkgMap, ok := pkgVal.(map[string]any)
		if !ok {
			continue
		}

		resultVal, ok := pkgMap["result"]
		if !ok {
			continue
		}

		// Marshal/unmarshal to convert to PolicyResult.
		raw, err := json.Marshal(resultVal)
		if err != nil {
			return nil, fmt.Errorf("policykit: marshal result from %s: %w", pkgName, err)
		}

		var pr PolicyResult
		if err := json.Unmarshal(raw, &pr); err != nil {
			return nil, fmt.Errorf("policykit: unmarshal result from %s: %w", pkgName, err)
		}

		// Check for duplicate rule_ids.
		if existingPkg, exists := seen[pr.RuleID]; exists {
			return nil, fmt.Errorf("policykit: duplicate rule_id %q found in packages %q and %q", pr.RuleID, existingPkg, pkgName)
		}
		seen[pr.RuleID] = pkgName

		results = append(results, pr)
	}

	return results, nil
}
