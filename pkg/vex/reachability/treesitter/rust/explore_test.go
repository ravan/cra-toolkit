package rust_test

import (
	"fmt"
	"strings"
	"testing"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	rustgrammar "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/rust"
)

func parseRust(t *testing.T, source string) (*tree_sitter.Tree, []byte) { //nolint:gocritic // two return values are self-documenting in context
	t.Helper()
	parser := tree_sitter.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(tree_sitter.NewLanguage(rustgrammar.Language())); err != nil {
		t.Fatalf("set language: %v", err)
	}
	src := []byte(source)
	tree := parser.Parse(src, nil)
	if tree == nil {
		t.Fatal("tree-sitter returned nil tree")
	}
	return tree, src
}

func printTree(node *tree_sitter.Node, source []byte, indent int) {
	text := node.Utf8Text(source)
	if len(text) > 80 {
		text = text[:80] + "..."
	}
	fmt.Printf("%s%s [%d-%d]: %q\n", strings.Repeat("  ", indent), node.Kind(), node.StartPosition().Row, node.EndPosition().Row, text)
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child != nil {
			printTree(child, source, indent+1)
		}
	}
}

func TestExploreAST(t *testing.T) {
	source := `
use std::collections::HashMap;
use crate::handler::{process, Handle};
use hyper::{Body, Request, Response};
use serde::Serialize as Ser;
use std::io::*;
extern crate serde;

mod utils {
    pub fn helper() {}
}

struct Server {
    port: u16,
}

enum Status {
    Ok,
    Error(String),
}

trait Handler {
    fn handle(&self, input: &str) -> String;
}

impl Handler for Server {
    fn handle(&self, input: &str) -> String {
        input.to_string()
    }
}

impl Server {
    fn new(port: u16) -> Self {
        Server { port }
    }

    pub fn start(&self) {
        println!("Starting on port {}", self.port);
    }
}

fn main() {
    let s = Server::new(8080);
    s.start();
    helper(42);
}

fn process(handler: &dyn Handler) {
    handler.handle("test");
}

fn test_something() {
    assert!(true);
}
`
	tree, src := parseRust(t, source)
	defer tree.Close()
	printTree(tree.RootNode(), src, 0)
}
