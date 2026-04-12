// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package php

import "testing"

func TestNormalizeSep(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "plain namespace",
			input: `Foo\Bar\Baz`,
			want:  "Foo.Bar.Baz",
		},
		{
			name:  "static dispatch",
			input: "Foo::bar",
			want:  "Foo.bar",
		},
		{
			name:  "mixed namespace and static dispatch",
			input: `Foo\Bar::baz`,
			want:  "Foo.Bar.baz",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "global namespace qualified (leading backslash)",
			input: `\Foo\Bar`,
			want:  "Foo.Bar",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeSep(tc.input)
			if got != tc.want {
				t.Errorf("normalizeSep(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
