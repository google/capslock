// Copyright 2024 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// Package rewrites is for testing that the syntax-rewriting code in the
// analysis library handles various types of statements correctly.
package rewrites

import "sort"

func Foo() {
	var err error
	err.Error()
	s := sort.IntSlice(nil)
	goto foo
foo:
	sort.Sort(s)
	if sort.Sort(s); true {
	}
	switch sort.Sort(s); int(0) {
	}
	var x any
	switch sort.Sort(s); x.(type) {
	}
	for sort.Sort(s); false; sort.Sort(s) {
	}
	sort.Sort(nil)
}
