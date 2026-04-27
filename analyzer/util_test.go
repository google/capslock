// Copyright 2026 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package analyzer

import (
	"strings"
	"testing"
)

func TestEscapeControlChars(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{
			name: "plain filename unchanged",
			in:   "foo.go",
			want: "foo.go",
		},
		{
			name: "filename with spaces unchanged",
			in:   "my file.go",
			want: "my file.go",
		},
		{
			name: "ansi csi escaped",
			in:   "\x1b[2J\x1b[H\x1b[32mOK\x1b[0m",
			want: `\x1b[2J\x1b[H\x1b[32mOK\x1b[0m`,
		},
		{
			name: "tab escaped",
			in:   "evil\tbenign",
			want: `evil\tbenign`,
		},
		{
			name: "bel escaped",
			in:   "x\x07y",
			want: `x\ay`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := escapeControlChars(tc.in)
			if got != tc.want {
				t.Errorf("escapeControlChars(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if strings.ContainsAny(got, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x7f") {
				t.Errorf("escapeControlChars(%q) returned %q, which still contains a control byte", tc.in, got)
			}
		})
	}
}
