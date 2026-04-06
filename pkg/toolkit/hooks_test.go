// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package toolkit_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ravan/cra-toolkit/pkg/toolkit"
)

func TestExecuteWithHooks_NoHooks(t *testing.T) {
	called := false
	err := toolkit.ExecuteWithHooks(context.Background(), "vex", nil, nil, func() error {
		called = true
		return nil
	})
	require.NoError(t, err)
	assert.True(t, called)
}

func TestExecuteWithHooks_PreOnly(t *testing.T) {
	var order []string
	hooks := []toolkit.Hook{
		{Phase: toolkit.Pre, Fn: func(_ context.Context, pkg string, _ any, _ error) error {
			order = append(order, "pre:"+pkg)
			return nil
		}},
	}
	err := toolkit.ExecuteWithHooks(context.Background(), "vex", hooks, nil, func() error {
		order = append(order, "fn")
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"pre:vex", "fn"}, order)
}

func TestExecuteWithHooks_PostOnly(t *testing.T) {
	var order []string
	hooks := []toolkit.Hook{
		{Phase: toolkit.Post, Fn: func(_ context.Context, pkg string, _ any, fnErr error) error {
			order = append(order, "post:"+pkg)
			assert.NoError(t, fnErr)
			return nil
		}},
	}
	err := toolkit.ExecuteWithHooks(context.Background(), "report", hooks, nil, func() error {
		order = append(order, "fn")
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"fn", "post:report"}, order)
}

func TestExecuteWithHooks_PreError_StopsExecution(t *testing.T) {
	fnCalled := false
	hooks := []toolkit.Hook{
		{Phase: toolkit.Pre, Fn: func(_ context.Context, _ string, _ any, _ error) error {
			return errors.New("pre-hook failed")
		}},
	}
	err := toolkit.ExecuteWithHooks(context.Background(), "vex", hooks, nil, func() error {
		fnCalled = true
		return nil
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pre-hook")
	assert.False(t, fnCalled)
}

func TestExecuteWithHooks_PostReceivesFnError(t *testing.T) {
	fnErr := errors.New("fn failed")
	var receivedErr error
	hooks := []toolkit.Hook{
		{Phase: toolkit.Post, Fn: func(_ context.Context, _ string, _ any, err error) error {
			receivedErr = err
			return nil
		}},
	}
	err := toolkit.ExecuteWithHooks(context.Background(), "vex", hooks, nil, func() error {
		return fnErr
	})
	require.Error(t, err)
	assert.Equal(t, fnErr, err)
	assert.Equal(t, fnErr, receivedErr)
}

func TestExecuteWithHooks_MultipleHooks_FireInOrder(t *testing.T) {
	var order []string
	hooks := []toolkit.Hook{
		{Phase: toolkit.Pre, Fn: func(_ context.Context, _ string, _ any, _ error) error {
			order = append(order, "pre1")
			return nil
		}},
		{Phase: toolkit.Pre, Fn: func(_ context.Context, _ string, _ any, _ error) error {
			order = append(order, "pre2")
			return nil
		}},
		{Phase: toolkit.Post, Fn: func(_ context.Context, _ string, _ any, _ error) error {
			order = append(order, "post1")
			return nil
		}},
		{Phase: toolkit.Post, Fn: func(_ context.Context, _ string, _ any, _ error) error {
			order = append(order, "post2")
			return nil
		}},
	}
	err := toolkit.ExecuteWithHooks(context.Background(), "vex", hooks, nil, func() error {
		order = append(order, "fn")
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"pre1", "pre2", "fn", "post1", "post2"}, order)
}

func TestExecuteWithHooks_PostHookError_OverridesFnSuccess(t *testing.T) {
	hooks := []toolkit.Hook{
		{Phase: toolkit.Post, Fn: func(_ context.Context, _ string, _ any, _ error) error {
			return errors.New("post-hook failed")
		}},
	}
	err := toolkit.ExecuteWithHooks(context.Background(), "vex", hooks, nil, func() error {
		return nil
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "post-hook")
}
