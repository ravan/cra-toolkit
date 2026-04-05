// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package policykit_test

import (
	"context"
	"os"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/policykit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadTestPolicy(t *testing.T) map[string]string {
	t.Helper()
	src, err := os.ReadFile("../../testdata/policykit/test_policy.rego")
	require.NoError(t, err)
	return map[string]string{"test_policy.rego": string(src)}
}

func TestEngine_EvaluateSinglePolicy_Pass(t *testing.T) {
	modules := loadTestPolicy(t)
	engine, err := policykit.NewEngine(modules)
	require.NoError(t, err)

	results, err := engine.Evaluate(context.Background(), map[string]any{
		"test_value": true,
	})
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.Equal(t, "TEST-1", results[0].RuleID)
	assert.Equal(t, "PASS", results[0].Status)
	assert.Equal(t, "Test policy", results[0].Name)
	assert.Equal(t, "Test", results[0].CRAReference)
	assert.Equal(t, "low", results[0].Severity)
	assert.Equal(t, map[string]any{"test_value": true}, results[0].Evidence)
}

func TestEngine_EvaluateSinglePolicy_Fail(t *testing.T) {
	modules := loadTestPolicy(t)
	engine, err := policykit.NewEngine(modules)
	require.NoError(t, err)

	results, err := engine.Evaluate(context.Background(), map[string]any{
		"test_value": false,
	})
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.Equal(t, "TEST-1", results[0].RuleID)
	assert.Equal(t, "FAIL", results[0].Status)
}

func TestEngine_MultiplePolicies(t *testing.T) {
	modules := map[string]string{
		"p1.rego": `package cra.policy_alpha

import rego.v1

default result := {
	"rule_id": "P1",
	"name": "Policy Alpha",
	"cra_reference": "Annex I.1",
	"status": "PASS",
	"severity": "high",
}
`,
		"p2.rego": `package cra.policy_beta

import rego.v1

default result := {
	"rule_id": "P2",
	"name": "Policy Beta",
	"cra_reference": "Annex I.2",
	"status": "FAIL",
	"severity": "medium",
}
`,
	}

	engine, err := policykit.NewEngine(modules)
	require.NoError(t, err)

	results, err := engine.Evaluate(context.Background(), map[string]any{})
	require.NoError(t, err)
	require.Len(t, results, 2)

	// Should be sorted alphabetically by package name
	assert.Equal(t, "P1", results[0].RuleID)
	assert.Equal(t, "PASS", results[0].Status)
	assert.Equal(t, "P2", results[1].RuleID)
	assert.Equal(t, "FAIL", results[1].Status)
}

func TestEngine_DuplicateRuleID_Error(t *testing.T) {
	modules := map[string]string{
		"dup1.rego": `package cra.dup_one

import rego.v1

default result := {
	"rule_id": "DUP-1",
	"name": "Duplicate One",
	"cra_reference": "Test",
	"status": "PASS",
	"severity": "low",
}
`,
		"dup2.rego": `package cra.dup_two

import rego.v1

default result := {
	"rule_id": "DUP-1",
	"name": "Duplicate Two",
	"cra_reference": "Test",
	"status": "FAIL",
	"severity": "low",
}
`,
	}

	engine, err := policykit.NewEngine(modules)
	require.NoError(t, err)

	_, err = engine.Evaluate(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DUP-1")
}

func TestEngine_AddCustomPolicies(t *testing.T) {
	modules := loadTestPolicy(t)
	engine, err := policykit.NewEngine(modules)
	require.NoError(t, err)

	custom := map[string]string{
		"custom_check.rego": `package cra.custom_check

import rego.v1

default result := {
	"rule_id": "CUSTOM-1",
	"name": "Custom Check",
	"cra_reference": "Custom",
	"status": "PASS",
	"severity": "low",
}
`,
	}

	err = engine.AddCustomPolicies(custom)
	require.NoError(t, err)

	results, err := engine.Evaluate(context.Background(), map[string]any{
		"test_value": true,
	})
	require.NoError(t, err)
	require.Len(t, results, 2)
}
