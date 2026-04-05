package treesitter_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter"
	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter/grammars/python"
)

func TestParseFile_Python(t *testing.T) {
	dir := t.TempDir()
	pyFile := filepath.Join(dir, "test.py")
	source := []byte("def hello():\n    print('hello')\n\nhello()\n")
	if err := os.WriteFile(pyFile, source, 0o600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	tree, src, err := treesitter.ParseFile(pyFile, python.Language())
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}
	defer tree.Close()

	root := tree.RootNode()
	if root.Kind() != "module" {
		t.Errorf("expected root node kind 'module', got %q", root.Kind())
	}
	if len(src) != len(source) {
		t.Errorf("expected source length %d, got %d", len(source), len(src))
	}
}

func TestParseFiles_Concurrent(t *testing.T) {
	dir := t.TempDir()

	for i := 0; i < 10; i++ {
		name := filepath.Join(dir, fmt.Sprintf("mod%d.py", i))
		src := fmt.Sprintf("def func%d():\n    pass\n", i)
		if err := os.WriteFile(name, []byte(src), 0o600); err != nil {
			t.Fatalf("failed to write %s: %v", name, err)
		}
	}

	files, err := filepath.Glob(filepath.Join(dir, "*.py"))
	if err != nil {
		t.Fatalf("glob failed: %v", err)
	}

	results, errs := treesitter.ParseFiles(files, python.Language())
	if len(errs) > 0 {
		t.Fatalf("unexpected parse errors: %v", errs)
	}
	if len(results) != 10 {
		t.Errorf("expected 10 parse results, got %d", len(results))
	}

	for _, r := range results {
		r.Tree.Close()
	}
}
