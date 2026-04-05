package java_test

import (
	"testing"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter"
	javagrammar "github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter/grammars/java"
	javaextractor "github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter/java"
)

// parseSource parses Java source bytes and returns the tree and the source slice.
func parseSource(t *testing.T, source string) (*tree_sitter.Tree, []byte) { //nolint:gocritic // two return values are self-documenting in context
	t.Helper()
	parser := tree_sitter.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(tree_sitter.NewLanguage(javagrammar.Language())); err != nil {
		t.Fatalf("set language: %v", err)
	}
	src := []byte(source)
	tree := parser.Parse(src, nil)
	if tree == nil {
		t.Fatal("tree-sitter returned nil tree")
	}
	return tree, src
}

// TestExtractSymbols_Java verifies that classes, methods, and imports are extracted
// from a basic Java class with Log4j usage.
//
//nolint:gocognit,gocyclo // test validates multiple symbol kinds with individual assertions
func TestExtractSymbols_Java(t *testing.T) {
	source := `package com.example;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class App {
    private static final Logger logger = LogManager.getLogger(App.class);

    public static void main(String[] args) {
        logger.info("Starting: {}", args[0]);
    }

    public void process(String input) {
        logger.info("Processing: {}", input);
    }
}
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := javaextractor.New()
	symbols, err := ext.ExtractSymbols("App.java", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	// Should extract: App (class), main (method), process (method)
	if len(symbols) < 3 {
		t.Errorf("expected at least 3 symbols, got %d", len(symbols))
		for _, s := range symbols {
			t.Logf("  %s (%s) at line %d", s.QualifiedName, s.Kind, s.StartLine)
		}
	}

	var foundClass, foundMain, foundProcess bool
	for _, s := range symbols {
		switch {
		case s.Name == "App" && s.Kind == treesitter.SymbolClass:
			foundClass = true
			if s.Package != "com.example" {
				t.Errorf("expected package 'com.example', got %q", s.Package)
			}
		case s.Name == "main" && s.Kind == treesitter.SymbolMethod:
			foundMain = true
			if s.QualifiedName != "com.example.App.main" {
				t.Errorf("expected qualified name 'com.example.App.main', got %q", s.QualifiedName)
			}
		case s.Name == "process" && s.Kind == treesitter.SymbolMethod:
			foundProcess = true
		}
	}

	if !foundClass {
		t.Error("expected to find class 'App'")
	}
	if !foundMain {
		t.Error("expected to find method 'main'")
	}
	if !foundProcess {
		t.Error("expected to find method 'process'")
	}
}

// TestExtractSymbols_Constructor verifies that constructors are extracted as methods.
//
//nolint:dupl // similar structure to TestExtractSymbols_InterfaceAndImplementor is intentional — different Java constructs
func TestExtractSymbols_Constructor(t *testing.T) {
	source := `package com.example;

public class Service {
    private final String name;

    public Service(String name) {
        this.name = name;
    }

    public String getName() {
        return this.name;
    }
}
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := javaextractor.New()
	symbols, err := ext.ExtractSymbols("Service.java", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	var foundConstructor, foundGetName bool
	for _, s := range symbols {
		switch {
		case s.Name == "Service" && s.Kind == treesitter.SymbolMethod:
			foundConstructor = true
		case s.Name == "getName" && s.Kind == treesitter.SymbolMethod:
			foundGetName = true
		}
	}

	if !foundConstructor {
		t.Error("expected to find constructor 'Service'")
	}
	if !foundGetName {
		t.Error("expected to find method 'getName'")
	}
}

// TestResolveImports_Java verifies that fully-qualified import declarations are extracted.
//
//nolint:gocognit,gocyclo // test validates multiple import forms
func TestResolveImports_Java(t *testing.T) {
	source := `package com.example;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.util.List;
import java.util.ArrayList;

public class App {
    public void run() {}
}
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := javaextractor.New()
	imports, err := ext.ResolveImports("App.java", src, tree, "/project")
	if err != nil {
		t.Fatalf("ResolveImports failed: %v", err)
	}

	if len(imports) < 4 {
		t.Errorf("expected at least 4 imports, got %d", len(imports))
		for _, imp := range imports {
			t.Logf("  %s (alias: %q)", imp.Module, imp.Alias)
		}
	}

	var foundLogManager, foundLogger, foundList bool
	for _, imp := range imports {
		switch imp.Module {
		case "org.apache.logging.log4j.LogManager":
			foundLogManager = true
		case "org.apache.logging.log4j.Logger":
			foundLogger = true
		case "java.util.List":
			foundList = true
		}
	}

	if !foundLogManager {
		t.Error("expected to find import 'org.apache.logging.log4j.LogManager'")
	}
	if !foundLogger {
		t.Error("expected to find import 'org.apache.logging.log4j.Logger'")
	}
	if !foundList {
		t.Error("expected to find import 'java.util.List'")
	}
}

// TestExtractCalls_Java verifies that method invocations are extracted as call edges.
//
//nolint:gocognit,gocyclo // test validates multiple call forms
func TestExtractCalls_Java(t *testing.T) {
	source := `package com.example;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class App {
    private static final Logger logger = LogManager.getLogger(App.class);

    public static void main(String[] args) {
        logger.info("Starting: {}", args[0]);
    }

    public void process(String input) {
        logger.info("Processing: {}", input);
    }
}
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := javaextractor.New()
	// First extract symbols to populate CHA state
	_, err := ext.ExtractSymbols("App.java", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	scope := treesitter.NewScope(nil)
	edges, err := ext.ExtractCalls("App.java", src, tree, scope)
	if err != nil {
		t.Fatalf("ExtractCalls failed: %v", err)
	}

	// Should find calls: LogManager.getLogger, logger.info (twice)
	if len(edges) < 2 {
		t.Errorf("expected at least 2 call edges, got %d", len(edges))
		for _, e := range edges {
			t.Logf("  %s -> %s (%s, conf=%.1f)", e.From, e.To, e.Kind, e.Confidence)
		}
	}

	var foundLogManagerCall bool
	for _, e := range edges {
		if string(e.To) == "LogManager.getLogger" || string(e.To) == "org.apache.logging.log4j.LogManager.getLogger" {
			foundLogManagerCall = true
		}
	}
	if !foundLogManagerCall {
		t.Error("expected LogManager.getLogger call edge — field initializer calls should be extracted")
	}

	// At minimum, check that edges have proper From fields set
	for _, e := range edges {
		if e.From == "" {
			t.Errorf("edge has empty From field: %+v", e)
		}
		if e.Confidence <= 0 {
			t.Errorf("edge has non-positive confidence: %+v", e)
		}
	}
}

// TestCHA_InterfaceDispatch verifies that CHA produces EdgeDispatch edges
// from interface method calls to concrete implementor methods.
//
//nolint:gocognit,gocyclo // test validates CHA dispatch with interface hierarchy
func TestCHA_InterfaceDispatch(t *testing.T) {
	source := `package com.example;

public interface Handler {
    void handle(String input);
}

public class LogHandler implements Handler {
    public void handle(String input) {
        System.out.println(input);
    }
}

public class App {
    public void run(Handler handler) {
        handler.handle("test");
    }
}
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := javaextractor.New()
	// ExtractSymbols populates the CHA interface→implementors map
	symbols, err := ext.ExtractSymbols("App.java", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	if len(symbols) == 0 {
		t.Fatal("expected symbols to be extracted")
	}

	scope := treesitter.NewScope(nil)
	edges, err := ext.ExtractCalls("App.java", src, tree, scope)
	if err != nil {
		t.Fatalf("ExtractCalls failed: %v", err)
	}

	// CHA should create EdgeDispatch from App.run → LogHandler.handle
	// with confidence 0.5 (interface dispatch)
	var foundDispatch bool
	for _, e := range edges {
		if e.Kind == treesitter.EdgeDispatch && e.Confidence == 0.5 {
			foundDispatch = true
			t.Logf("Found dispatch edge: %s -> %s (conf=%.1f)", e.From, e.To, e.Confidence)
		}
	}

	if !foundDispatch {
		t.Error("expected CHA to produce at least one EdgeDispatch with confidence 0.5")
		for _, e := range edges {
			t.Logf("  edge: %s -> %s (%s, conf=%.1f)", e.From, e.To, e.Kind, e.Confidence)
		}
	}
}

// TestExtractSymbols_InterfaceAndImplementor verifies that interface declarations and
// implements relationships are tracked for CHA.
//
//nolint:dupl // similar structure to TestExtractSymbols_Constructor is intentional — different Java constructs
func TestExtractSymbols_InterfaceAndImplementor(t *testing.T) {
	source := `package com.example;

public interface Processor {
    void process(String data);
}

public class DataProcessor implements Processor {
    public void process(String data) {
        System.out.println(data);
    }
}
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := javaextractor.New()
	symbols, err := ext.ExtractSymbols("Processor.java", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	var foundInterface, foundImpl bool
	for _, s := range symbols {
		switch {
		case s.Name == "Processor" && s.Kind == treesitter.SymbolClass:
			foundInterface = true
		case s.Name == "DataProcessor" && s.Kind == treesitter.SymbolClass:
			foundImpl = true
		}
	}

	if !foundInterface {
		t.Error("expected to find interface 'Processor' as class symbol")
	}
	if !foundImpl {
		t.Error("expected to find class 'DataProcessor'")
	}
}

// TestCHA_CrossFile verifies that SnapshotCHA / RestoreCHA allow ExtractCalls to
// produce EdgeDispatch edges when an interface is defined in one file and its
// implementor is defined in another file.
//
// Scenario:
//   - "file_a.java" declares interface Handler
//   - "file_b.java" declares LogHandler implements Handler
//   - "file_b.java" also has App.run(Handler handler) which calls handler.handle(...)
//
// After ExtractSymbols on both files and SnapshotCHA, RestoreCHA must make the
// cross-file interface→implementor mapping visible during ExtractCalls on file_b.
//
//nolint:gocognit,gocyclo // test validates cross-file CHA state across two parse trees
func TestCHA_CrossFile(t *testing.T) {
	sourceA := `package com.example;

public interface Handler {
    void handle(String input);
}
`
	sourceB := `package com.example;

public class LogHandler implements Handler {
    public void handle(String input) {
        System.out.println(input);
    }
}

public class App {
    public void run(Handler handler) {
        handler.handle("test");
    }
}
`
	treeA, srcA := parseSource(t, sourceA)
	defer treeA.Close()

	treeB, srcB := parseSource(t, sourceB)
	defer treeB.Close()

	ext := javaextractor.New()

	// Phase 1: extract symbols from both files (mirrors the analyzer pipeline)
	if _, err := ext.ExtractSymbols("file_a.java", srcA, treeA); err != nil {
		t.Fatalf("ExtractSymbols file_a.java: %v", err)
	}
	if _, err := ext.ExtractSymbols("file_b.java", srcB, treeB); err != nil {
		t.Fatalf("ExtractSymbols file_b.java: %v", err)
	}

	// Snapshot the accumulated cross-file CHA state
	snap := ext.SnapshotCHA()

	// Phase 3 simulation: re-extract file_b symbols (resets extractor state),
	// then restore the cross-file CHA snapshot before extracting calls.
	if _, err := ext.ExtractSymbols("file_b.java", srcB, treeB); err != nil {
		t.Fatalf("re-ExtractSymbols file_b.java: %v", err)
	}
	ext.RestoreCHA(snap)

	scope := treesitter.NewScope(nil)
	edges, err := ext.ExtractCalls("file_b.java", srcB, treeB, scope)
	if err != nil {
		t.Fatalf("ExtractCalls file_b.java: %v", err)
	}

	// CHA should emit EdgeDispatch from App.run → LogHandler.handle
	// because Handler (file_a) → LogHandler (file_b) is in the merged snapshot.
	var foundDispatch bool
	for _, e := range edges {
		if e.Kind == treesitter.EdgeDispatch && e.Confidence == 0.5 {
			foundDispatch = true
			t.Logf("cross-file dispatch edge: %s -> %s (conf=%.1f)", e.From, e.To, e.Confidence)
		}
	}

	if !foundDispatch {
		t.Error("expected cross-file CHA to produce at least one EdgeDispatch with confidence 0.5")
		for _, e := range edges {
			t.Logf("  edge: %s -> %s (%s, conf=%.1f)", e.From, e.To, e.Kind, e.Confidence)
		}
	}
}

// TestExtractSymbols_InnerClass verifies that inner (nested) classes and their methods
// are extracted with qualified names.
//
//nolint:gocyclo // test validates multiple symbol kinds for outer + inner class hierarchy
func TestExtractSymbols_InnerClass(t *testing.T) {
	source := `package com.example;

public class Outer {
    public void outerMethod() {}

    public static class Inner {
        public void innerMethod() {}
    }
}
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := javaextractor.New()
	symbols, err := ext.ExtractSymbols("Outer.java", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	var foundOuter, foundInner, foundOuterMethod bool
	for _, s := range symbols {
		switch {
		case s.Name == "Outer" && s.Kind == treesitter.SymbolClass:
			foundOuter = true
		case s.Name == "Inner" && s.Kind == treesitter.SymbolClass:
			foundInner = true
		case s.Name == "outerMethod" && s.Kind == treesitter.SymbolMethod:
			foundOuterMethod = true
		}
	}

	if !foundOuter {
		t.Error("expected to find class 'Outer'")
	}
	if !foundInner {
		t.Error("expected to find inner class 'Inner'")
	}
	if !foundOuterMethod {
		t.Error("expected to find method 'outerMethod'")
	}
}
