// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// Package callutf8 is used for testing.
package callutf8

import (
	"unicode/utf8"
)

// Foo is a test function with no interesting capabilities.
func Foo() int {
	return 1 + utf8.RuneLen('1')
}
