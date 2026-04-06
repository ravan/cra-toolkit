package main

import (
	"fmt"
	"os"

	"golang.org/x/text/language"
)

func main() {
	tags, _, err := language.ParseAcceptLanguage(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid accept-language: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(tags)
}
