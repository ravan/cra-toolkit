package policies

import "embed"

//go:embed *.rego
var Embedded embed.FS
