// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// Package useunsafe is used for testing.
package useunsafe

import (
	"unsafe"
)

// Foo converts a pointer using unsafe.Pointer.
func Foo() int {
	x := uint(3)
	u := unsafe.Pointer(&x)
	y := *(*int)(u)
	return y
}

type up = unsafe.Pointer

// Bar converts a pointer using a type equivalent to unsafe.Pointer.
func Bar() int {
	x := uint(3)
	u := up(&x)
	y := *(*int)(u)
	return y
}

// Some exported variables.
var (
	I  int
	U  up = up(&I)
	IP *int
	Y  = *(*int)(U)
	Z  = func() int {
		return *(*int)(U)
	}
)

// Baz converts an unsafe pointer in a global variable.
func Baz() int {
	IP = (*int)(U)
	return *IP
}

// ReturnFunction returns a function that converts an unsafe.Pointer.
func ReturnFunction() func() int {
	return func() int {
		return *(*int)(U)
	}
}

// Indirect calls a function that converts an unsafe.Pointer.
func Indirect() int {
	return ReturnFunction()()
}

// Indirect2 calls a function that converts an unsafe.Pointer.
func Indirect2() int {
	return Z()
}

// NestedFunctions contains a nested function that converts an unsafe.Pointer.
func NestedFunctions() func() func() func() float32 {
	return func() func() func() float32 {
		return func() func() float32 {
			return func() float32 {
				return *(*float32)(U)
			}
		}
	}
}

// CallNestedFunctions calls a nested function that converts an unsafe.Pointer.
func CallNestedFunctions() float32 {
	return NestedFunctions()()()()
}

// Ok converts an unsafe.Pointer to a uintptr.
func Ok() uintptr {
	var p unsafe.Pointer
	return (uintptr)(p)
}

// T is a type with a method that uses an unsafe.Pointer.
type T struct{}

// M uses an unsafe pointer.
func (t T) M() int {
	return *(*int)(U)
}
