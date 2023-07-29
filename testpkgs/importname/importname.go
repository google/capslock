// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// Package importname is used for testing whether we analyze the names of imports correctly.
package importname

import (
	"github.com/google/capslock/testpkgs/importname/sort"
)

type foo struct{}

func (m *foo) Len() int           { return 1 }
func (m *foo) Less(i, j int) bool { return false }
func (m *foo) Swap(i, j int)      {}

// CallTheWrongSort calls a function that is written sort.Sort, but
// refers to a function in a library that isn't the standard library "sort".
func CallTheWrongSort() {
	sort.Sort(new(foo))
}
