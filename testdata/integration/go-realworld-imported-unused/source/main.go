package main

import (
	"fmt"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

func main() {
	c := cases.Title(language.English)
	fmt.Println(c.String("hello world"))
}
