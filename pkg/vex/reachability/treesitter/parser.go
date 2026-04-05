// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package treesitter

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"unsafe"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
)

// ParseResult holds the result of parsing a single file.
type ParseResult struct {
	File   string
	Source []byte
	Tree   *tree_sitter.Tree
}

// ParseFile parses a single source file using the given tree-sitter language.
// The caller is responsible for calling Tree.Close() on the returned result.
func ParseFile(filePath string, langPtr unsafe.Pointer) (*tree_sitter.Tree, []byte, error) {
	source, err := os.ReadFile(filePath) //nolint:gosec // path from controlled input
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", filePath, err)
	}

	parser := tree_sitter.NewParser()
	defer parser.Close()

	lang := tree_sitter.NewLanguage(langPtr)
	if err := parser.SetLanguage(lang); err != nil {
		return nil, nil, fmt.Errorf("set language: %w", err)
	}

	tree := parser.Parse(source, nil)
	if tree == nil {
		return nil, nil, fmt.Errorf("parse %s: tree-sitter returned nil", filePath)
	}

	return tree, source, nil
}

type parseResult struct {
	pr  ParseResult
	err error
}

// workerCount returns the number of workers to use for a job list of the given size.
func workerCount(n int) int {
	w := runtime.NumCPU()
	if w > n {
		return n
	}
	return w
}

// collectResults drains the results channel and partitions into successes and errors.
func collectResults(ch <-chan parseResult) ([]ParseResult, []error) {
	var prs []ParseResult
	var errs []error
	for r := range ch {
		if r.err != nil {
			errs = append(errs, r.err)
		} else {
			prs = append(prs, r.pr)
		}
	}
	return prs, errs
}

// ParseFiles parses multiple files concurrently using a worker pool.
// Returns all successful parse results and any errors encountered.
// The caller is responsible for calling Tree.Close() on each result.
func ParseFiles(files []string, langPtr unsafe.Pointer) ([]ParseResult, []error) {
	n := len(files)
	nw := workerCount(n)
	if nw == 0 {
		return nil, nil
	}

	jobs := make(chan string, n)
	results := make(chan parseResult, n)

	var wg sync.WaitGroup
	for range nw {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for file := range jobs {
				tree, source, err := ParseFile(file, langPtr)
				if err != nil {
					results <- parseResult{err: err}
					continue
				}
				results <- parseResult{pr: ParseResult{File: file, Source: source, Tree: tree}}
			}
		}()
	}

	for _, f := range files {
		jobs <- f
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	return collectResults(results)
}
