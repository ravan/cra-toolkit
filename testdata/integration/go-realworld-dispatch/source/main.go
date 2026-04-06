package main

import (
	"fmt"

	"golang.org/x/text/language"
)

// LangParser is an interface for parsing language tags.
type LangParser interface {
	ParseLangs(s string) []language.Tag
}

// AcceptParser implements LangParser using golang.org/x/text/language.
type AcceptParser struct{}

// ParseLangs delegates to language.ParseAcceptLanguage from golang.org/x/text.
func (p AcceptParser) ParseLangs(s string) []language.Tag {
	tags, _, err := language.ParseAcceptLanguage(s)
	if err != nil {
		return nil
	}
	return tags
}

func run(p LangParser) {
	result := p.ParseLangs("en-US,fr;q=0.9")
	fmt.Println(result)
}

func main() {
	run(AcceptParser{})
}
