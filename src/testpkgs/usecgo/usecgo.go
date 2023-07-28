// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// Package usecgo is used for testing.  It contains a C function and a Go
// function which calls it via cgo, and some functions which call type
// conversion functions from the "C" pseudo-package.
package usecgo

// int acfunction() { return 42; }
import "C"
import "unsafe"

// Foo calls a C function using cgo.
func Foo() int {
	return int(C.acfunction()) + 1
}

// CallCString is a test function that calls C.CString.
func CallCString() {
	s := "abc"
	var c *C.char = C.CString(s)
	_ = c
}

// CallCBytes is a test function that calls C.CBytes.
func CallCBytes([]byte) {
	b := []byte{1, 2, 3}
	var u unsafe.Pointer = C.CBytes(b)
	_ = u
}

// CallGoString is a test function that calls C.GoString.
func CallGoString(*C.char) {
	var c C.char
	var s string = C.GoString(&c)
	_ = s
}

// CallGoStringN is a test function that calls C.GoStringN.
func CallGoStringN(*C.char, C.int) {
	var c C.char
	var s string = C.GoStringN(&c, C.int(1))
	_ = s
}

// CallGoBytes is a test function that calls C.GoBytes.
func CallGoBytes(unsafe.Pointer, C.int) {
	var u unsafe.Pointer
	var b []byte = C.GoBytes(u, C.int(1))
	_ = b
}
