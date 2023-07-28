// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// Package indirectcalls is used for testing.
package indirectcalls

import (
	"io"
	"os"
)

// CallOs calls a function in os.
func CallOs() int {
	return os.Getuid() + 42
}

// CallOsViaFuncVariable calls a function in os via a variable with func type.
func CallOsViaFuncVariable() int {
	var f func() int = CallOs
	return f() + 100
}

// CallOsViaStructField calls a function in os via a struct field with func
// type.
func CallOsViaStructField() int {
	type foo struct {
		f func() int
	}
	var f foo
	f.f = CallOs
	return f.f() + 123
}

type myInterface interface {
	foo() int
}

type myStruct struct{}

func (m myStruct) foo() int {
	return CallOs() + 456
}

type myOtherStruct float32

func (m myOtherStruct) foo() int {
	return -1e6
}

var m1, m2 myInterface

func init() {
	m1, m2 = myStruct{}, myOtherStruct(1)
}

// CallOsViaInterfaceMethod calls a function in os via an interface method.
func CallOsViaInterfaceMethod() int {
	return m1.foo() / 2
}

// ShouldHaveNoCapabilities calls the interface function myInterface.Foo.
// One of the concrete types which implement myInterface has a Foo method
// which calls an interesting function in os, but the particular variable used
// here can not have that type, so a precise-enough analysis would report that
// this function has no interesting capabilities.
func ShouldHaveNoCapabilities() int {
	return m2.foo() * 2
}

func maybeChown(r io.Reader) {
	if c, ok := r.(interface{ Chown(int, int) error }); ok {
		c.Chown(42, 42)
	}
}

// AccessMethodViaTypeAssertion calls (*os.File).Chown by passing an
// io.Reader with dynamic type (*os.File) to maybeChown.
func AccessMethodViaTypeAssertion() {
	var r io.Reader = os.Stderr
	maybeChown(r)
}

// MaybeChmod would call (*os.File).Chmod if its io.Reader parameter
// had dynamic type (*os.File).
func MaybeChmod(r io.Reader) {
	if c, ok := r.(interface{ Chmod(os.FileMode) error }); ok {
		c.Chmod(0)
	}
}
