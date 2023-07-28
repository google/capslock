// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// Package callruntime is used for testing.
package callruntime

import (
	"runtime"
)

// Interesting is used for testing.
func Interesting() int {
	return len(runtime.CPUProfile())
}

// Uninteresting is used for testing.
func Uninteresting() int {
	var f runtime.Func
	return len(f.Name())
}
