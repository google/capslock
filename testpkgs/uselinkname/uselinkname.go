// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// Package uselinkname is for testing go:linkname.
package uselinkname

import (
	"syscall"

	_ "unsafe" // To allow go:linkname.
)

// Foo calls the Go runtime's internal random-number generator, using go:linkname.
func Foo() uint64 {
	return runtime_fastrand64()
}

//go:linkname runtime_fastrand64 runtime.fastrand64
func runtime_fastrand64() uint64

// CallExplicitlyCategorizedFunction calls a function which uses linkname.
// Functions using linkname which are not explicitly categorized should have
// the arbitrary-execution capability, but Getpagesize has been categorized as
// having the system-calls capability.
func CallExplicitlyCategorizedFunction() int {
	return syscall.Getpagesize() + 1
}
