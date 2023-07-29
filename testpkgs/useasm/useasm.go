// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// Package useasm is for testing analysis of packages that include .s files.
package useasm

func bar(x int) int

// Foo calls an assembly function.
func Foo() int {
	return bar(1)
}
