package main

import (
	"testing"

	"golang.org/x/text/language"
)

func TestLanguage(t *testing.T) {
	tag, err := language.Parse("en-US")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("parsed: %s", tag)
}
