//go:build integration

package main

import (
	"testing"

	"golang.org/x/text/language"
)

func TestParse(t *testing.T) {
	tag, err := language.Parse("en")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(tag)
}
