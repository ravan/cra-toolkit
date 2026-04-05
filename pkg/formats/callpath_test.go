package formats_test

import (
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
)

func TestCallPath_String(t *testing.T) {
	tests := []struct {
		name  string
		path  formats.CallPath
		want  string
	}{
		{
			name: "two nodes with file and line",
			path: formats.CallPath{
				Nodes: []formats.CallNode{
					{Symbol: "main.handler", File: "cmd/main.go", Line: 42},
					{Symbol: "vuln.Parse", File: "vendor/vuln/parse.go", Line: 10},
				},
			},
			want: "main.handler (cmd/main.go:42) -> vuln.Parse (vendor/vuln/parse.go:10)",
		},
		{
			name: "node without file info",
			path: formats.CallPath{
				Nodes: []formats.CallNode{
					{Symbol: "main.handler", File: "cmd/main.go", Line: 42},
					{Symbol: "external.Func"},
				},
			},
			want: "main.handler (cmd/main.go:42) -> external.Func",
		},
		{
			name:  "empty path",
			path:  formats.CallPath{},
			want:  "",
		},
		{
			name: "single node",
			path: formats.CallPath{
				Nodes: []formats.CallNode{
					{Symbol: "main.handler", File: "cmd/main.go", Line: 1},
				},
			},
			want: "main.handler (cmd/main.go:1)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.path.String()
			if got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCallPath_Depth(t *testing.T) {
	tests := []struct {
		name string
		path formats.CallPath
		want int
	}{
		{"empty", formats.CallPath{}, 0},
		{"two nodes", formats.CallPath{Nodes: []formats.CallNode{{Symbol: "a"}, {Symbol: "b"}}}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.path.Depth(); got != tt.want {
				t.Errorf("Depth() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestCallPath_EntryPoint(t *testing.T) {
	path := formats.CallPath{
		Nodes: []formats.CallNode{
			{Symbol: "main.handler", File: "cmd/main.go", Line: 42},
			{Symbol: "vuln.Parse", File: "lib/parse.go", Line: 10},
		},
	}
	ep := path.EntryPoint()
	if ep.Symbol != "main.handler" {
		t.Errorf("EntryPoint().Symbol = %q, want main.handler", ep.Symbol)
	}
	if ep.File != "cmd/main.go" {
		t.Errorf("EntryPoint().File = %q, want cmd/main.go", ep.File)
	}
}

func TestCallPath_EntryPoint_EmptyPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected EntryPoint() on empty path to panic")
		}
	}()
	p := formats.CallPath{}
	p.EntryPoint()
}
