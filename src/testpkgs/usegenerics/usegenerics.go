// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// Package usegenerics is used for testing.
package usegenerics

import (
	"net"
	"os"
	"sync/atomic"
)

type i interface {
	Baz() int
}

type a int

func (a a) Baz() int {
	is, _ := net.Interfaces()
	return 2 * int(a) * len(is)
}

// Foo is a generic function used for testing.
func Foo[T i](a T, b int) int {
	err := os.Rename("/tmp/12345", "/tmp/12345")
	if err != nil {
		b++
	}
	return a.Baz() + b
}

// Bar calls a generic function.
func Bar() int {
	var a a = 1
	return Foo(a, 3)
}

// AtomicPointer calls various methods on an instantiation of the generic
// type atomic.Pointer.
func AtomicPointer() int {
	i := 3
	var x atomic.Pointer[int]
	x.Store(&i)
	x.Swap(&i)
	x.CompareAndSwap(nil, nil)
	return *x.Load()
}

// NestedFunction is a generic function that returns a nested function.
func NestedFunction[T i](a T, b int) func() int {
	return func() int { return a.Baz() + b }
}

// CallNestedFunction calls a function that is nested in a generic function.
func CallNestedFunction() int {
	var a a = 1
	return NestedFunction(a, 3)() + 1
}
