package main

import (
	"fmt"
	"golang.org/x/text/language"
)

func main() {
	tags, q, err := language.ParseAcceptLanguage("en-US,en;q=0.9,fr;q=0.8")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	for i, tag := range tags {
		fmt.Printf("lang: %s, quality: %f\n", tag, q[i])
	}
}
