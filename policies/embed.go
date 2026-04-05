// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package policies

import "embed"

//go:embed *.rego
var Embedded embed.FS
