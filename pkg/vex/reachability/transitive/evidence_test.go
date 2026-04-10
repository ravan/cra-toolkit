// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/formats"
)

func TestStitchCallPaths_ConcatenatesNodes(t *testing.T) {
	app := formats.CallPath{Nodes: []formats.CallNode{
		{Symbol: "app.handler", File: "app.py", Line: 10},
		{Symbol: "flask.route", File: "flask.py", Line: 100},
	}}
	mid := formats.CallPath{Nodes: []formats.CallNode{
		{Symbol: "flask.route", File: "flask.py", Line: 100},
		{Symbol: "werkzeug.Adapter.send", File: "werkzeug.py", Line: 200},
	}}
	last := formats.CallPath{Nodes: []formats.CallNode{
		{Symbol: "werkzeug.Adapter.send", File: "werkzeug.py", Line: 200},
		{Symbol: "urllib3.PoolManager", File: "urllib3.py", Line: 300},
	}}

	got := StitchCallPaths([]formats.CallPath{app, mid, last})
	if len(got.Nodes) != 4 {
		t.Errorf("expected 4 nodes, got %d", len(got.Nodes))
	}
	if got.Nodes[0].Symbol != "app.handler" {
		t.Errorf("first node: %q", got.Nodes[0].Symbol)
	}
	if got.Nodes[len(got.Nodes)-1].Symbol != "urllib3.PoolManager" {
		t.Errorf("last node: %q", got.Nodes[len(got.Nodes)-1].Symbol)
	}
}

func TestStitchCallPaths_EmptyReturnsEmpty(t *testing.T) {
	got := StitchCallPaths(nil)
	if len(got.Nodes) != 0 {
		t.Errorf("expected empty path")
	}
}

func TestStitchCallPaths_NoOverlapStillConcatenates(t *testing.T) {
	a := formats.CallPath{Nodes: []formats.CallNode{{Symbol: "x"}, {Symbol: "y"}}}
	b := formats.CallPath{Nodes: []formats.CallNode{{Symbol: "a"}, {Symbol: "b"}}}
	got := StitchCallPaths([]formats.CallPath{a, b})
	if len(got.Nodes) != 4 {
		t.Errorf("expected 4 nodes, got %d", len(got.Nodes))
	}
}
